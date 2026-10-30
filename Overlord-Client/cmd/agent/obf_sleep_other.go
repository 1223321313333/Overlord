//go:build !windows
// +build !windows

package main

import "time"

func obfSleepDuration(d time.Duration) {
	time.Sleep(d)
}

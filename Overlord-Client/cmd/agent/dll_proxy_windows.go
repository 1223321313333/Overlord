//go:build windows && dll_sideload
// +build windows,dll_sideload

package main

import (
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// dll_proxy_windows.go — lazy loader for the real System32\version.dll so
// that our proxy exports forward calls transparently.

var (
	realVersionOnce sync.Once
	realVersionDLL  *syscall.DLL
)

func loadRealVersion() *syscall.DLL {
	realVersionOnce.Do(func() {
		sysroot := os.Getenv("SystemRoot")
		if sysroot == "" {
			sysroot = `C:\Windows`
		}
		path := filepath.Join(sysroot, "System32", "version.dll")
		dll, err := syscall.LoadDLL(path)
		if err == nil {
			realVersionDLL = dll
		}
	})
	return realVersionDLL
}

func realVersionProc(name string) uintptr {
	dll := loadRealVersion()
	if dll == nil {
		return 0
	}
	proc, err := dll.FindProc(name)
	if err != nil {
		return 0
	}
	return proc.Addr()
}

func callProc1(addr uintptr, a0, a1 uintptr) (uintptr, uintptr, syscall.Errno) {
	return syscall.SyscallN(addr, a0, a1)
}

func callProc3(addr uintptr, a0, a1, a2, a3 uintptr) (uintptr, uintptr, syscall.Errno) {
	return syscall.SyscallN(addr, a0, a1, a2, a3)
}

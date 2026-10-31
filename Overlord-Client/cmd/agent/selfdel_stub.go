//go:build dll_sideload

package main

// scheduleDropperSelfDelete is a no-op in DLL side-load mode:
// the DLL is the persistence mechanism itself and must not be removed.
func scheduleDropperSelfDelete() {}

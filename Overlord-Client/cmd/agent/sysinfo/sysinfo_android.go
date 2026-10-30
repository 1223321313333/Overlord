//go:build android

package sysinfo

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func collectPlatform() Info {
	percent, charging := batteryStatus()
	return Info{
		CPU:             cpuName(),
		GPU:             gpuName(),
		RAM:             totalRAM(),
		BatteryPercent:  percent,
		BatteryCharging: charging,
	}
}

func OSName() string {
	if out, err := exec.Command("getprop", "ro.build.version.release").Output(); err == nil {
		version := strings.TrimSpace(string(out))
		if version != "" {
			if model, err := exec.Command("getprop", "ro.product.model").Output(); err == nil {
				if m := strings.TrimSpace(string(model)); m != "" {
					return fmt.Sprintf("Android %s (%s)", version, m)
				}
			}
			return "Android " + version
		}
	}
	if data, err := os.ReadFile("/system/build.prop"); err == nil {
		var version, model string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if v, ok := strings.CutPrefix(line, "ro.build.version.release="); ok {
				version = v
			}
			if m, ok := strings.CutPrefix(line, "ro.product.model="); ok {
				model = m
			}
		}
		if version != "" {
			if model != "" {
				return fmt.Sprintf("Android %s (%s)", version, model)
			}
			return "Android " + version
		}
	}
	return "Android"
}

func batteryStatus() (*int, bool) {
	entries, err := os.ReadDir("/sys/class/power_supply")
	if err != nil {
		return nil, false
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "BAT") && name != "battery" && !strings.HasPrefix(name, "battery") {
			continue
		}
		base := "/sys/class/power_supply/" + name
		capacityRaw, err := os.ReadFile(base + "/capacity")
		if err != nil {
			continue
		}
		var percent int
		if _, err := fmt.Sscanf(strings.TrimSpace(string(capacityRaw)), "%d", &percent); err != nil {
			continue
		}
		if percent < 0 || percent > 100 {
			continue
		}
		statusRaw, _ := os.ReadFile(base + "/status")
		status := strings.ToLower(strings.TrimSpace(string(statusRaw)))
		charging := status == "charging" || status == "full"
		return &percent, charging
	}
	return nil, false
}

func cpuName() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		// Android ARM chips expose "Hardware" instead of "model name"
		if strings.HasPrefix(line, "Hardware") || strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return "unknown"
}

func gpuName() string {
	return "unknown"
}

func totalRAM() string {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				var kb uint64
				if _, err := fmt.Sscanf(fields[1], "%d", &kb); err != nil {
					return "unknown"
				}
				gb := float64(kb) / (1024 * 1024)
				if gb >= 1 {
					return fmt.Sprintf("%.0f GB", gb)
				}
				return fmt.Sprintf("%.0f MB", float64(kb)/1024)
			}
		}
	}
	return "unknown"
}

// HostArch returns the compile-time target architecture.
// On Android we always build for a specific arch so runtime.GOARCH is correct.
func HostArch() string {
	return runtime.GOARCH
}

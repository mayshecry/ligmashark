package system

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"

	"ligmashark/internal/types"
)

func getBasePlatform(fallback string) string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return fallback
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ID_LIKE=") {
			val := strings.Trim(strings.TrimPrefix(line, "ID_LIKE="), "\"")
			fields := strings.Fields(val)
			if len(fields) > 0 {
				return fields[0]
			}
		}
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "ID=") {
			val := strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
			if val != "" {
				return val
			}
		}
	}
	return fallback
}

func GetSystemInfo() types.SystemInfo {
	info := types.SystemInfo{
		GoVersion: runtime.Version(),
	}

	hInfo, err := host.Info()
	if err == nil {
		platform := getBasePlatform(hInfo.Platform)
		info.OS = fmt.Sprintf("%s %s (%s)", hInfo.OS, platform, hInfo.PlatformVersion)
		info.Hostname = hInfo.Hostname
		info.Uptime = formatDuration(time.Duration(hInfo.Uptime) * time.Second)
	}

	cpuInfo, err := cpu.Info()
	if err == nil && len(cpuInfo) > 0 {
		info.CPU = fmt.Sprintf("%s (%d cores)", cpuInfo[0].ModelName, len(cpuInfo))
	}

	vMem, err := mem.VirtualMemory()
	if err == nil {
		info.Memory = fmt.Sprintf("%.2f GB / %.2f GB", float64(vMem.Used)/1024/1024/1024, float64(vMem.Total)/1024/1024/1024)
	}

	return info
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	return fmt.Sprintf("%d days, %d hours, %d minutes, %d seconds", days, hours, minutes, seconds)
}
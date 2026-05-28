package network

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	netutil "github.com/shirou/gopsutil/v3/net"
)

var (
	localIPs    []string
	localIPsMu  sync.RWMutex
	connCache   []netutil.ConnectionStat
	connCacheMu sync.RWMutex
	hostMu      sync.RWMutex
	hostCache   = make(map[string]string)
	ispMu       sync.RWMutex
	ispCache    = make(map[string]string)
)

func init() {
	updateLocalIPs()
	updateConnCache()
	go func() {
		for {
			time.Sleep(2 * time.Second)
			updateLocalIPs()
			updateConnCache()
		}
	}()
}

func updateLocalIPs() {
	var ips []string
	if interfaces, err := net.Interfaces(); err == nil {
		for _, i := range interfaces {
			addrs, _ := i.Addrs()
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok {
					ips = append(ips, ipnet.IP.String())
				}
			}
		}
	}
	localIPsMu.Lock()
	localIPs = ips
	localIPsMu.Unlock()
}

func updateConnCache() {
	conns, err := netutil.Connections("all")
	if err == nil {
		connCacheMu.Lock()
		connCache = conns
		connCacheMu.Unlock()
	}
}

func IsLocalIP(ip string) bool {
	if ip == "127.0.0.1" || ip == "::1" {
		return true
	}
	localIPsMu.RLock()
	defer localIPsMu.RUnlock()
	for _, lip := range localIPs {
		if lip == ip {
			return true
		}
	}
	return strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.1") || strings.HasPrefix(ip, "172.2") || strings.HasPrefix(ip, "172.3")
}

func IsHostIP(ip string) bool {
	localIPsMu.RLock()
	defer localIPsMu.RUnlock()
	for _, lip := range localIPs {
		if lip == ip {
			return true
		}
	}
	return ip == "127.0.0.1" || ip == "::1"
}

func GetISP(ip string) string {
	ispMu.RLock()
	if val, ok := ispCache[ip]; ok {
		ispMu.RUnlock()
		return val
	}
	ispMu.RUnlock()

	if IsLocalIP(ip) {
		return "Local Network"
	}

	ispMu.Lock()
	ispCache[ip] = "Resolving..."
	ispMu.Unlock()

	go func(target string) {
		resp, err := http.Get("http://ip-api.com/json/" + target + "?fields=isp")
		if err != nil {
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			return
		}

		var r struct {
			Isp string `json:"isp"`
		}
		json.NewDecoder(resp.Body).Decode(&r)
		if r.Isp != "" {
			ispMu.Lock()
			ispCache[target] = r.Isp
			ispMu.Unlock()
		}
	}(ip)

	return "Resolving..."
}

func LoadThreatBlocklist() map[string]bool {
	blocklist := make(map[string]bool)
	resp, err := http.Get("https://threatfox.abuse.ch/export/json/recent/")
	if err != nil {
		return blocklist
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return blocklist
	}

	var data struct {
		QueryStatus string                   `json:"query_status"`
		Data        []map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
		for _, entry := range data.Data {
			if ioc, ok := entry["ioc"].(string); ok && entry["ioc_type"] == "ip:port" {
				blocklist[ioc] = true
			}
		}
	}
	return blocklist
}

func FindPidByPort(srcIP, srcPort, dstIP, dstPort string) int32 {
	sp, _ := strconv.Atoi(srcPort)
	dp, _ := strconv.Atoi(dstPort)

	connCacheMu.RLock()
	defer connCacheMu.RUnlock()

	for _, conn := range connCache {
		if (conn.Laddr.Port == uint32(sp) && (conn.Laddr.IP == srcIP || srcIP == "127.0.0.1" || srcIP == "0.0.0.0" || srcIP == "::")) ||
			(conn.Laddr.Port == uint32(dp) && (conn.Laddr.IP == dstIP || dstIP == "127.0.0.1" || dstIP == "0.0.0.0" || dstIP == "::")) {
			if conn.Pid != 0 {
				return conn.Pid
			}
		}
	}
	return 0
}

func IdentifyService(procName, srcPort, dstPort string) string {
	p := strings.ToLower(procName)
	if strings.Contains(p, "chrome") || strings.Contains(p, "firefox") || strings.Contains(p, "brave") || strings.Contains(p, "safari") || strings.Contains(p, "msedge") || strings.Contains(p, "opera") || strings.Contains(p, "vivaldi") || strings.Contains(p, "librewolf") {
		return "Web Browser"
	}
	ports := []string{srcPort, dstPort}
	for _, prt := range ports {
		switch prt {
		case "27015", "27016":
			return "Source Engine Game"
		case "25565":
			return "Minecraft"
		case "3074":
			return "Call of Duty"
		case "7777", "7778":
			return "Game Server (UE/Terraria)"
		case "3724":
			return "World of Warcraft"
		case "5000", "5500":
			return "League of Legends"
		case "3478", "3479":
			return "Voice Chat (Discord/Steam)"
		case "28015":
			return "Rust"
		case "2302":
			return "Arma/DayZ"
		}
	}
	return ""
}

func GetCategory(name string) string {
	n := strings.ToLower(name)
	if strings.Contains(n, "discord") || strings.Contains(n, "slack") || strings.Contains(n, "telegram") || strings.Contains(n, "zoom") || strings.Contains(n, "teams") {
		return "Communication"
	}
	if strings.Contains(n, "firefox") || strings.Contains(n, "chrome") || strings.Contains(n, "brave") || strings.Contains(n, "safari") || strings.Contains(n, "msedge") || strings.Contains(n, "opera") || strings.Contains(n, "vivaldi") || strings.Contains(n, "librewolf") {
		return "Browsers"
	}
	if strings.Contains(n, "mullvad") || strings.Contains(n, "proton") || strings.Contains(n, "tailscale") || strings.Contains(n, "wireguard") || strings.Contains(n, "vpn") {
		return "VPN & Privacy"
	}
	if n == "system/unknown" || n == "" {
		return "System"
	}
	return "Other"
}

func IdentifyDevice(mac string) string {
	if mac == "" {
		return "Unknown Device"
	}
	m := strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	if len(m) < 6 {
		return "Unknown"
	}
	prefix := m[:6]
	switch prefix {
	case "000C29", "005056", "000569":
		return "VMware"
	case "080027":
		return "VirtualBox"
	case "B827EB", "D83ADD", "DCA632":
		return "Raspberry Pi"
	case "00163E":
		return "Xen VM"
	case "001A11", "3C5AB4":
		return "Google"
	case "0017F2", "001C42", "F01898":
		return "Apple"
	case "2C337A", "00155D":
		return "Microsoft"
	case "AC8674", "E4E0C5":
		return "Espressif"
	case "00E04C":
		return "Realtek"
	}
	return "OUI:" + prefix
}

func LookupHostname(ip string, cache map[string]string) string {
	hostMu.RLock()
	if val, ok := hostCache[ip]; ok {
		hostMu.RUnlock()
		return val
	}
	hostMu.RUnlock()

	go func(target string) {
		names, err := net.LookupAddr(target)
		if err == nil && len(names) > 0 {
			hostMu.Lock()
			hostCache[target] = strings.TrimSuffix(names[0], ".")
			hostMu.Unlock()
		}
	}(ip)

	return ""
}

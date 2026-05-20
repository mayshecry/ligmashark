package network

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"

	netutil "github.com/shirou/gopsutil/v3/net"
)

func GetISP(ip string, cache map[string]string) string {
	if val, ok := cache[ip]; ok {
		return val
	}
	if strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "127.") {
		return "Local Network"
	}

	resp, err := http.Get("http://ip-api.com/json/" + ip + "?fields=isp")
	if err != nil {
		return "Unknown"
	}
	defer resp.Body.Close()

	var r struct {
		Isp string `json:"isp"`
	}
	json.NewDecoder(resp.Body).Decode(&r)
	if r.Isp == "" {
		r.Isp = "Unknown"
	}
	cache[ip] = r.Isp
	return r.Isp
}

func LoadThreatBlocklist() map[string]bool {
	blocklist := make(map[string]bool)
	resp, err := http.Get("https://threatfox.abuse.ch/export/json/recent/")
	if err != nil {
		return blocklist
	}
	defer resp.Body.Close()

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

func FindPidByPort(srcPort, dstPort string) int32 {
	sp, _ := strconv.Atoi(srcPort)
	dp, _ := strconv.Atoi(dstPort)

	conns, err := netutil.Connections("all")
	if err != nil {
		return 0
	}

	for _, conn := range conns {
		if conn.Laddr.Port == uint32(sp) || conn.Laddr.Port == uint32(dp) {
			if conn.Pid != 0 {
				return conn.Pid
			}
		}
	}

	if interfaces, err := net.Interfaces(); err == nil {
		for _, i := range interfaces {
			addrs, _ := i.Addrs()
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok {
					if ipnet.IP.String() == srcPort || ipnet.IP.String() == dstPort {
						continue
					}
				}
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
		case "27015", "27016": return "Source Engine Game"
		case "25565": return "Minecraft"
		case "3074": return "Call of Duty"
		case "7777", "7778": return "Game Server (UE/Terraria)"
		case "3724": return "World of Warcraft"
		case "5000", "5500": return "League of Legends"
		case "3478", "3479": return "Voice Chat (Discord/Steam)"
		case "28015": return "Rust"
		case "2302": return "Arma/DayZ"
		}
	}
	return ""
}
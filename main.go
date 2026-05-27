package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/shirou/gopsutil/v3/process"

	"ligmashark/internal/network"
	"ligmashark/internal/plugins"
	"ligmashark/internal/system"
	"ligmashark/internal/types"
	"ligmashark/internal/ui"
)

func main() {
	if len(os.Args) > 2 && os.Args[1] == "--compile" {
		srcFile := os.Args[2]
		if !strings.HasSuffix(srcFile, ".shark") {
			fmt.Println("Error: Input file must have .shark extension")
			os.Exit(1)
		}
		if err := plugins.Compile(srcFile); err != nil {
			fmt.Printf("Compilation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully compiled %s to %s\n", srcFile, strings.TrimSuffix(srcFile, ".shark")+".ligma")
		os.Exit(0)
	}

	if len(os.Args) > 2 && os.Args[1] == "--run" {
		ligmaFile := os.Args[2]
		loaded, err := plugins.LoadPluginsFromFile(ligmaFile)
		if err != nil {
			fmt.Printf("Execution failed: %v\n", err)
			os.Exit(1)
		}
		for _, p := range loaded {
			p.OnPacket(&types.PacketData{Timestamp: time.Now(), ProcessName: "Standalone-Runner"})
		}
		os.Exit(0)
	}

	processes := make(map[int32]*types.ProcItem)
	ispCache := make(map[string]string)
	threatBlocklist := network.LoadThreatBlocklist()

	loadedPlugins, err := plugins.LoadPlugins("./plugins")
	if err != nil {
		fmt.Printf("Warning: Failed to load plugins: %v\n", err)
	}

	allProcs, _ := process.Processes()
	for _, p := range allProcs {
		name, _ := p.Name()
		processes[p.Pid] = &types.ProcItem{PID: p.Pid, Name: name, Category: network.GetCategory(name)}
	}

	var mu sync.RWMutex

	m := ui.NewModel(processes, &mu, system.GetSystemInfo())

	captureDevice := "any"
	if runtime.GOOS == "windows" {
		devices, err := pcap.FindAllDevs()
		if err == nil && len(devices) > 0 {
			captureDevice = devices[0].Name
		}
	}

	m.InterfaceName = captureDevice

	handle, err := pcap.OpenLive(captureDevice, 1600, true, pcap.BlockForever)
	if err != nil {
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "permission") || strings.Contains(errStr, "permitted") {
			if runtime.GOOS == "windows" {
				fmt.Println("Permission denied. Please run Ligmashark as Administrator (elevated terminal).")
			} else {
				fmt.Println("Permission denied. Please run with sudo or set CAP_NET_RAW capabilities.")
			}
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer handle.Close()
	defer network.StopMITM()

	go func() {
		source := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range source.Packets() {
			if m.IsCapturePaused() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			var srcIP, dstIP string
			var srcPort, dstPort string
			var protocol string

			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				srcIP = ip.SrcIP.String()
				dstIP = ip.DstIP.String()
			} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv6)
				srcIP = ip.SrcIP.String()
				dstIP = ip.DstIP.String()
			}

			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp := tcpLayer.(*layers.TCP)
				srcPort, dstPort = tcp.SrcPort.String(), tcp.DstPort.String()
				protocol = "TCP"
			} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				srcPort, dstPort = udp.SrcPort.String(), udp.DstPort.String()
				protocol = "UDP"
			} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
				protocol = "ICMP"
				srcPort = "0"
				dstPort = "0"
			}

			if protocol != "" {
				pid := network.FindPidByPort(srcIP, srcPort, dstIP, dstPort)
				mu.Lock()
				if _, ok := processes[pid]; !ok {
					name := "System/Unknown"
					if pid != 0 {
						if p, err := process.NewProcess(pid); err == nil {
							name, _ = p.Name()
						}
					}
					processes[pid] = &types.ProcItem{PID: pid, Name: name, Category: network.GetCategory(name)}
				}

				remoteIP := dstIP
				if strings.HasPrefix(srcIP, "192.") || strings.HasPrefix(srcIP, "10.") || srcIP == "127.0.0.1" {
					remoteIP = dstIP
				} else {
					remoteIP = srcIP
				}

				isMalicious := false
				if threatBlocklist[dstIP+":"+dstPort] || threatBlocklist[srcIP+":"+srcPort] {
					isMalicious = true
					processes[pid].IsMalicious = true
				}

				pkt := types.PacketData{
					Timestamp:   time.Now(),
					SrcIP:       srcIP,
					DstIP:       dstIP,
					SrcPort:     srcPort,
					DstPort:     dstPort,
					Protocol:    protocol,
					Length:      len(packet.Data()),
					ISP:         network.GetISP(remoteIP, ispCache),
					Service:     network.IdentifyService(processes[pid].Name, srcPort, dstPort),
					IsMalicious: isMalicious,
					PID:         pid,
				}
				if appLayer := packet.ApplicationLayer(); appLayer != nil {
					payload := appLayer.Payload()
					pkt.Payload = hex.Dump(payload)

					payloadStr := string(payload)
					if strings.HasPrefix(payloadStr, "HTTP/") {
						lines := strings.Split(payloadStr, "\r\n")
						if len(lines) > 0 {
							parts := strings.Split(lines[0], " ")
							if len(parts) >= 2 {
								pkt.HTTPStatus = parts[1]
							}
						}
					} else if strings.HasPrefix(payloadStr, "GET") || strings.HasPrefix(payloadStr, "POST") || strings.HasPrefix(payloadStr, "PUT") {
						parts := strings.Split(payloadStr, " ")
						if len(parts) >= 1 {
							pkt.HTTPMethod = parts[0]
						}
					}
				} else {
					pkt.Payload = ""
				}
				if procItem, exists := processes[pid]; exists {
					pkt.ProcessName = procItem.Name
				}

				for _, p := range loadedPlugins {
					p.OnPacket(&pkt)
				}

				if network.IsMITMActive() && !network.IsHostIP(srcIP) && !network.IsHostIP(dstIP) {
					m.MITMPackets = append(m.MITMPackets, pkt)
					if len(m.MITMPackets) > 1000 {
						m.MITMPackets = m.MITMPackets[1:]
					}
				}

				m.GlobalPackets = append(m.GlobalPackets, pkt)
				if len(m.GlobalPackets) > 1000 {
					m.GlobalPackets = m.GlobalPackets[1:]
				}

				processes[pid].Packets = append(processes[pid].Packets, pkt)

				if strings.HasPrefix(srcIP, "192.") || strings.HasPrefix(srcIP, "10.") || srcIP == "127.0.0.1" {
					processes[pid].BytesOut += uint64(pkt.Length)
				} else {
					processes[pid].BytesIn += uint64(pkt.Length)
				}

				if len(processes[pid].Packets) > 1000 {
					processes[pid].Packets = processes[pid].Packets[len(processes[pid].Packets)-1000:]
				}
				mu.Unlock()
			}
		}
	}()

	p := tea.NewProgram(&m, tea.WithAltScreen(), tea.WithMouseCellMotion())
	m.Program = p

	go m.SetupOllama(p)

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}
}

package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/shirou/gopsutil/v3/process"

	"ligmashark/internal/network"
	"ligmashark/internal/system"
	"ligmashark/internal/types"
	"ligmashark/internal/ui"
)

func main() {
	processes := make(map[int32]*types.ProcItem)
	ispCache := make(map[string]string)
	threatBlocklist := network.LoadThreatBlocklist()

	allProcs, _ := process.Processes()
	for _, p := range allProcs {
		name, _ := p.Name()
		processes[p.Pid] = &types.ProcItem{PID: p.Pid, Name: name}
	}

	var mu sync.RWMutex

	m := ui.NewModel(processes, &mu, system.GetSystemInfo())

	handle, err := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	if err != nil {
		if os.Geteuid() != 0 && (strings.Contains(strings.ToLower(err.Error()), "permission") || strings.Contains(err.Error(), "permitted")) {
			executable, execErr := os.Executable()
			if execErr != nil {
				fmt.Fprintf(os.Stderr, "Permission denied. Failed to find executable for elevation: %v\n", execErr)
				os.Exit(1)
			}

			fmt.Println("Insufficient permissions for packet capture. Elevating with sudo...")
			sudoArgs := append([]string{"sudo", executable}, os.Args[1:]...)
			err = syscall.Exec("/usr/bin/sudo", sudoArgs, os.Environ())
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to escalate to sudo: %v\n", err)
				os.Exit(1)
			}
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer handle.Close()

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
				pid := network.FindPidByPort(srcPort, dstPort)
				mu.Lock()
				if _, ok := processes[pid]; !ok {
					name := "System/Unknown"
					if pid != 0 {
						if p, err := process.NewProcess(pid); err == nil {
							name, _ = p.Name()
						}
					}
					processes[pid] = &types.ProcItem{PID: pid, Name: name}
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
						Timestamp: time.Now(),
						SrcIP:     srcIP,
						DstIP:     dstIP,
						SrcPort:   srcPort,
						DstPort:   dstPort,
						Protocol:  protocol,
						Length:    len(packet.Data()),
						ISP:       network.GetISP(remoteIP, ispCache),
						Service:   network.IdentifyService(processes[pid].Name, srcPort, dstPort),
						IsMalicious: isMalicious,
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

	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())

	go m.SetupOllama(p)

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}
}
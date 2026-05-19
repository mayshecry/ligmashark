package types

import (
	"fmt"
	"time"
)

type PacketData struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   string
	DstPort   string
	Protocol  string
	Length    int
	ISP       string
	Service   string
	Payload   string
	ProcessName string
	AIAnalysis string
}

type ProcItem struct {
	PID     int32
	Name    string
	Packets []PacketData
}

func (i ProcItem) Title() string       { return fmt.Sprintf("%s (PID: %d)", i.Name, i.PID) }
func (i ProcItem) Description() string { return fmt.Sprintf("Packets: %d", len(i.Packets)) }
func (i ProcItem) FilterValue() string { return i.Name }

type SystemInfo struct {
	OS        string
	Hostname  string
	CPU       string
	Memory    string
	GoVersion string
	Uptime    string
}
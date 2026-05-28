package types

import (
	"fmt"
	"time"
)

type PacketData struct {
	Timestamp   time.Time
	SrcIP       string
	DstIP       string
	SrcMAC      string
	DstMAC      string
	SrcPort     string
	DstPort     string
	Protocol    string
	Length      int
	ISP         string
	Service     string
	Payload     []byte
	ProcessName string
	Hostname    string
	PID         int32
	AIAnalysis  string
	IsMalicious bool
	HTTPHeaders map[string]string
	HTTPStatus  string
	HTTPMethod  string
}

type ProcItem struct {
	PID         int32
	Name        string
	Category    string
	BytesIn     uint64
	BytesOut    uint64
	Packets     []PacketData
	IsMalicious bool
}

func (i ProcItem) Title() string       { return fmt.Sprintf("%s (PID: %d)", i.Name, i.PID) }
func (i ProcItem) Description() string { return fmt.Sprintf("Packets: %d", len(i.Packets)) }
func (i ProcItem) FilterValue() string { return i.Name }

type Plugin interface {
	Name() string
	OnPacket(pkt *PacketData)
}

type SystemInfo struct {
	OS        string
	Hostname  string
	CPU       string
	Memory    string
	GoVersion string
	Uptime    string
}

type HTTPInfo struct {
	Timestamp   time.Time
	SrcIP       string
	DstIP       string
	SrcMAC      string
	DstMAC      string
	SrcPort     string
	DstPort     string
	Protocol    string
	Length      int
	URL         string
	HTTPMethod  string
	HTTPHeaders map[string]string
}

type BandwidthPoint struct {
	In  uint64
	Out uint64
}

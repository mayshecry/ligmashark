package ui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"

	"ligmashark/internal/ai"
	"ligmashark/internal/network"
	"ligmashark/internal/types"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	docStyle         = lipgloss.NewStyle().Margin(1, 2)
	filterInputStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	explStyle        = lipgloss.NewStyle().Align(lipgloss.Center).Width(60).MarginTop(1).MarginBottom(1)
	landingPageStyle = lipgloss.NewStyle().Align(lipgloss.Center).Padding(2, 4).Border(lipgloss.RoundedBorder())
)

type UpdateMsg struct{}

type AIResultMsg string
type OllamaStatusMsg string
type PauseCaptureMsg struct{}
type ResumeCaptureMsg struct{}
type BettercapLogMsg string
type MITMStatusMsg string
type ExportResultMsg string

type Mode int

const (
	NormalMode Mode = iota
	LandingPageMode
	FilterMode
	PacketDetailMode
	HelpMode
	ProcessSearchMode
	GraphMode
	BettercapMode
	GlobalTrafficMode
	CategorySelectionMode
	SettingsMode
	NetworkTopologyMode
)

type Model struct {
	List                 CustomList
	Viewport             CustomViewport
	Processes            map[int32]*types.ProcItem
	CapturePaused        *bool
	CaptureStatus        string
	Program              *tea.Program
	ProcessFilterSetting ProcessFilter
	MITMStatus           string
	InterfaceName        string
	SelectedPid          int32
	Mu                   *sync.RWMutex
	Width                int
	Height               int
	Mode                 Mode
	ActiveProtocolFilter string
	FilterInput          string
	ActiveFilter         string
	ProcessSearchInput   string
	ActiveProcessSearch  string
	SystemInfo           types.SystemInfo
	VisiblePackets       []types.PacketData
	InspectedPacket      types.PacketData
	ActiveCategory       string
	CategoryList         []string
	CategoryCursor       int
	MITMSelectedIdx      int
	MITMJunkFilter       bool
	MITMProtocolFilter   string
	MITMSearchInput      string
	MITMSearchActive     bool
	PacketDetailViewport CustomViewport
	HelpViewport         CustomViewport
	BettercapViewport    CustomViewport
	BettercapLogs        []string
	BettercapModules     map[string]bool
	GlobalPackets        []types.PacketData
	GlobalViewport       CustomViewport
	GlobalSelectedIdx    int
	MITMPackets          []types.PacketData
	OllamaStatus         string
	ExportStatus         string
	CursorVisible        bool
	History              []types.BandwidthPoint
	LastTotalIn          uint64
	LastTotalOut         uint64
	AutoScroll           bool
	GraphScrollOffset    int
	SettingsCursor       int
	UseAI                bool
	UseMITMSetting       bool
	AvailableModels      []string
	SelectedModelIdx     int
	SelectedThemeIdx     int
	SortMode             int
}

var Themes = []struct {
	Name    string
	Primary string
	Accent  string
}{
	{"Classic Shark", "62", "205"},
	{"Deep Sea", "24", "39"},
	{"Hacker Console", "2", "10"},
	{"Midnight Lavender", "141", "147"},
	{"Crimson Fury", "124", "196"},
	{"Electric Purple", "99", "201"},
	{"Sakura Bloom", "197", "218"},
	{"Cyber Orange", "130", "208"},
}

func NewModel(processes map[int32]*types.ProcItem, mu *sync.RWMutex, sysInfo types.SystemInfo) Model {
	m := Model{
		List:                 NewCustomList("Processes"),
		Viewport:             NewCustomViewport(),
		SystemInfo:           sysInfo,
		Processes:            processes,
		CapturePaused:        new(bool),
		Mu:                   mu,
		PacketDetailViewport: NewCustomViewport(),
		HelpViewport:         NewCustomViewport(),
		BettercapViewport:    NewCustomViewport(),
		GlobalViewport:       NewCustomViewport(),
		CategoryList:         []string{"Communication", "Browsers", "VPN & Privacy", "System", "Other", "All Traffic"},
		ActiveCategory:       "All Traffic",
		MITMSelectedIdx:      -1,
		GlobalSelectedIdx:    -1,
		BettercapModules:     make(map[string]bool),
		MITMPackets:          make([]types.PacketData, 0),
		MITMJunkFilter:       true,
		MITMProtocolFilter:   "ALL",
		ProcessFilterSetting: FilterEverything,
		CaptureStatus:        "Running",
		MITMStatus:           "MITM: Off",
		OllamaStatus:         "Initializing Ollama...",
		ActiveProtocolFilter: "ALL",
		Mode:                 LandingPageMode,
		AutoScroll:           true,
		UseAI:                true,
		UseMITMSetting:       true,
		AvailableModels:      []string{"qwen2.5:0.5b", "qwen2:0.5b", "phi3:mini", "tinyllama", "smollm:135m", "llama3.2:1b", "gemma:2b", "orca-mini", "granite-code:3b", "deepseek-coder:1.3b", "stable-code:3b"},
		SortMode:             0,
	}
	m.loadConfig()
	return m
}

func (m *Model) getTheme() struct{ Name, Primary, Accent string } {
	return Themes[m.SelectedThemeIdx]
}

func (m Model) Init() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return UpdateMsg{}
	})
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		if km.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}

	switch msg := msg.(type) {
	case PauseCaptureMsg:
		m.Mu.Lock()
		*m.CapturePaused = true
		m.Mu.Unlock()
		m.CaptureStatus = "Paused"
	case ResumeCaptureMsg:
		m.Mu.Lock()
		*m.CapturePaused = false
		m.Mu.Unlock()
		m.CaptureStatus = "Running"
	case tea.KeyMsg:
		if m.Mode == HelpMode {
			switch msg.String() {
			case "esc", "q", "?":
				m.Mode = NormalMode
			}
		} else if m.Mode == CategorySelectionMode {
			switch msg.String() {
			case "up", "k", "left":
				m.CategoryCursor--
				if m.CategoryCursor < 0 {
					m.CategoryCursor = len(m.CategoryList) - 1
				}
			case "down", "j", "right":
				m.CategoryCursor++
				if m.CategoryCursor >= len(m.CategoryList) {
					m.CategoryCursor = 0
				}
			case "enter":
				m.ActiveCategory = m.CategoryList[m.CategoryCursor]
				m.Mode = NormalMode
				m.refreshList()
			case "esc", "q":
				m.Mode = LandingPageMode
			}
			return m, nil
		} else if m.Mode == SettingsMode {
			switch msg.String() {
			case "esc", "q", "S":
				m.Mode = NormalMode
			case "up", "k":
				m.SettingsCursor--
				if m.SettingsCursor < 0 {
					m.SettingsCursor = 4
				}
			case "down", "j":
				m.SettingsCursor++
				if m.SettingsCursor > 4 {
					m.SettingsCursor = 0
				}
			case "left", "h":
				if m.SettingsCursor == 1 && len(m.AvailableModels) > 0 {
					m.SelectedModelIdx = (m.SelectedModelIdx - 1 + len(m.AvailableModels)) % len(m.AvailableModels)
				}
				if m.SettingsCursor == 3 {
					m.SelectedThemeIdx = (m.SelectedThemeIdx - 1 + len(Themes)) % len(Themes)
				}
			case "right", "l":
				if m.SettingsCursor == 1 && len(m.AvailableModels) > 0 {
					m.SelectedModelIdx = (m.SelectedModelIdx + 1) % len(m.AvailableModels)
				}
				if m.SettingsCursor == 3 {
					m.SelectedThemeIdx = (m.SelectedThemeIdx + 1) % len(Themes)
				}
			case "enter", " ":
				switch m.SettingsCursor {
				case 0:
					m.UseAI = !m.UseAI
				case 1:
					if len(m.AvailableModels) > 0 {
						m.SelectedModelIdx = (m.SelectedModelIdx + 1) % len(m.AvailableModels)
					}
				case 2:
					m.UseMITMSetting = !m.UseMITMSetting
				case 3:
					m.Mode = NormalMode
				}
			}
			return m, nil
		} else if m.Mode == BettercapMode {
			if m.MITMSearchActive {
				switch msg.String() {
				case "enter", "esc":
					m.MITMSearchActive = false
				case "backspace":
					if len(m.MITMSearchInput) > 0 {
						m.MITMSearchInput = m.MITMSearchInput[:len(m.MITMSearchInput)-1]
					}
				default:
					if len(msg.String()) == 1 {
						m.MITMSearchInput += msg.String()
					}
				}
				m.updateBettercapViewport()
				return m, nil
			}

			switch msg.String() {
			case "esc", "q", "b":
				m.Mode = NormalMode
				m.ExportStatus = ""
			case "x":
				m.MITMJunkFilter = !m.MITMJunkFilter
				m.updateBettercapViewport()
			case "f":
				filters := []string{"ALL", "TCP", "UDP", "HTTP", "DNS"}
				idx := 0
				for i, f := range filters {
					if f == m.MITMProtocolFilter {
						idx = (i + 1) % len(filters)
						break
					}
				}
				m.MITMProtocolFilter = filters[idx]
				m.updateBettercapViewport()
			case "/":
				m.MITMSearchActive = true
				m.MITMSearchInput = ""
				return m, nil
			case "c":
				m.Mu.Lock()
				m.MITMPackets = nil
				m.MITMSelectedIdx = -1
				m.Mu.Unlock()
				m.updateBettercapViewport()
			case "e":
				m.ExportStatus = "Exporting Session..."
				return m, m.exportMITMSessionCmd()
			case "up", "k":
				m.Mu.RLock()
				packets := m.getFilteredMITMPackets()
				m.Mu.RUnlock()
				if len(packets) > 0 {
					m.MITMSelectedIdx--
					if m.MITMSelectedIdx < 0 {
						m.MITMSelectedIdx = 0
					}
					m.updateBettercapViewport()
				}
			case "down", "j":
				m.Mu.RLock()
				packets := m.getFilteredMITMPackets()
				m.Mu.RUnlock()
				if len(packets) > 0 {
					m.MITMSelectedIdx++
					if m.MITMSelectedIdx >= len(packets) {
						m.MITMSelectedIdx = len(packets) - 1
					}
					m.updateBettercapViewport()
				}
			case "home":
				m.MITMSelectedIdx = 0
				m.updateBettercapViewport()
			case "end", "G":
				packets := m.getFilteredMITMPackets()
				if len(packets) > 0 {
					m.MITMSelectedIdx = len(packets) - 1
				}
				m.updateBettercapViewport()
			case "enter":
				packets := m.getFilteredMITMPackets()
				if m.MITMSelectedIdx >= 0 && m.MITMSelectedIdx < len(packets) {
					m.InspectedPacket = packets[m.MITMSelectedIdx]
					m.Mode = PacketDetailMode
					m.PacketDetailViewport.SetContent(m.getPacketDetailContent())
					return m, m.analyzePacketCmd(m.InspectedPacket)
				}
			default:
				m.BettercapViewport.Update(msg)
			}
			return m, nil
		} else if m.Mode == GraphMode {
			switch msg.String() {
			case "esc", "q", "g", "h":
				m.Mode = NormalMode
				m.GraphScrollOffset = 0
			case "left":
				m.GraphScrollOffset++
				maxOffset := len(m.History) - (m.Width - 20)
				if maxOffset < 0 {
					maxOffset = 0
				}
				if m.GraphScrollOffset > maxOffset {
					m.GraphScrollOffset = maxOffset
				}
			case "right":
				m.GraphScrollOffset--
				if m.GraphScrollOffset < 0 {
					m.GraphScrollOffset = 0
				}
			}
			return m, nil
		} else if m.Mode == PacketDetailMode {
			switch msg.String() {
			case "esc", "q", "backspace":
				m.Mode = NormalMode
				m.ExportStatus = ""
			case "e":
				m.ExportStatus = "Exporting..."
				m.PacketDetailViewport.SetContent(m.getPacketDetailContent())
				return m, m.exportPacketCmd(m.InspectedPacket)
			default:
				m.PacketDetailViewport.Update(msg)
			}
		} else if m.Mode == LandingPageMode {
			switch msg.String() {
			case "q", "enter", "esc", "h":
				m.Mode = CategorySelectionMode
			}
		} else if m.Mode == GlobalTrafficMode {
			switch msg.String() {
			case "esc", "q", "t":
				m.Mode = NormalMode
			case "up", "k":
				if len(m.GlobalPackets) > 0 {
					m.GlobalSelectedIdx--
					if m.GlobalSelectedIdx < 0 {
						m.GlobalSelectedIdx = 0
					}
					m.updateGlobalViewport()
				}
			case "down", "j":
				if len(m.GlobalPackets) > 0 {
					m.GlobalSelectedIdx++
					if m.GlobalSelectedIdx >= len(m.GlobalPackets) {
						m.GlobalSelectedIdx = len(m.GlobalPackets) - 1
					}
					m.updateGlobalViewport()
				}
			case "home":
				m.GlobalSelectedIdx = 0
				m.updateGlobalViewport()
			case "end", "G":
				if len(m.GlobalPackets) > 0 {
					m.GlobalSelectedIdx = len(m.GlobalPackets) - 1
				}
				m.updateGlobalViewport()
			case "enter":
				if m.GlobalSelectedIdx >= 0 && m.GlobalSelectedIdx < len(m.GlobalPackets) {
					m.InspectedPacket = m.GlobalPackets[m.GlobalSelectedIdx]
					m.Mode = PacketDetailMode
					m.PacketDetailViewport.SetContent(m.getPacketDetailContent())
					return m, m.analyzePacketCmd(m.InspectedPacket)
				}
			default:
				m.GlobalViewport.Update(msg)
			}
			return m, nil
		} else if m.Mode == NetworkTopologyMode {
			switch msg.String() {
			case "esc", "q", "n":
				m.Mode = NormalMode
			}
			return m, nil
		} else if m.Mode == FilterMode {
			switch msg.String() {
			case "enter":
				m.ActiveFilter = m.FilterInput
				m.Mode = NormalMode
				m.updateViewport()
			case "esc":
				m.FilterInput = ""
				m.ActiveFilter = ""
				m.Mode = NormalMode
				m.updateViewport()
			case "backspace":
				if len(m.FilterInput) > 0 {
					m.FilterInput = m.FilterInput[:len(m.FilterInput)-1]
				}
			default:
				if len(msg.String()) == 1 {
					m.FilterInput += msg.String()
				}
			}
		} else if m.Mode == ProcessSearchMode {
			switch msg.String() {
			case "enter":
				m.ActiveProcessSearch = m.ProcessSearchInput
				m.Mode = NormalMode
				m.refreshList()
			case "esc":
				m.ProcessSearchInput = ""
				m.ActiveProcessSearch = ""
				m.Mode = NormalMode
				m.refreshList()
			case "backspace":
				if len(m.ProcessSearchInput) > 0 {
					m.ProcessSearchInput = m.ProcessSearchInput[:len(m.ProcessSearchInput)-1]
				}
			default:
				if len(msg.String()) == 1 {
					m.ProcessSearchInput += msg.String()
				}
			}
		} else {
			switch msg.String() {
			case "?":
				m.Mode = HelpMode
				m.HelpViewport.SetContent(m.renderHelpMenuContent())
				return m, nil
			case "b":
				m.Mode = BettercapMode
				m.updateBettercapViewport()
				return m, nil
			case "S":
				m.Mode = SettingsMode
				return m, nil
			case "m":
				if network.IsMITMActive() {
					err := network.StopMITM()
					if err != nil {
						m.MITMStatus = "MITM Err: " + err.Error()
					} else {
						m.MITMStatus = "MITM: Off"
						m.BettercapModules["arp.spoof"] = false
						m.BettercapModules["net.sniff"] = false
					}
				} else {
					m.MITMStatus = "MITM: Starting..."
					return m, m.toggleMITMCmd(m.Program)
				}
				return m, nil
			case "p":
				return m, m.toggleCaptureCmd()
			case "s":
				m.cycleProcessFilter()
				return m, nil
			case "g":
				m.Mode = GraphMode
				return m, nil
			case "f":
				switch m.ActiveProtocolFilter {
				case "ALL":
					m.ActiveProtocolFilter = "TCP"
				case "TCP":
					m.ActiveProtocolFilter = "UDP"
				case "UDP":
					m.ActiveProtocolFilter = "ICMP"
				default:
					m.ActiveProtocolFilter = "ALL"
				}
				m.updateViewport()
			case "a":
				m.AutoScroll = !m.AutoScroll
			case "o":
				m.SortMode = (m.SortMode + 1) % 3
				m.refreshList()
			case "X":
				m.ActiveFilter = ""
				m.ActiveProcessSearch = ""
				m.ActiveProtocolFilter = "ALL"
				m.refreshList()
				m.updateViewport()
			case "1":
				m.ActiveProtocolFilter = "ALL"
				m.updateViewport()
			case "2":
				m.ActiveProtocolFilter = "TCP"
				m.updateViewport()
			case "3":
				m.ActiveProtocolFilter = "UDP"
				m.updateViewport()
			case "4":
				m.ActiveProtocolFilter = "ICMP"
				m.updateViewport()
			case "c":
				m.Mu.Lock()
				if p, ok := m.Processes[m.SelectedPid]; ok {
					p.Packets = nil
					p.BytesIn = 0
					p.BytesOut = 0
				}
				m.Mu.Unlock()
				m.updateViewport()

			case "t":
				m.Mode = GlobalTrafficMode
				m.updateGlobalViewport()
				return m, nil
			case "n":
				m.Mode = NetworkTopologyMode
				return m, nil
			case "h", "q":
				m.Mode = CategorySelectionMode
				return m, nil
			case "/":
				m.FilterInput = ""
				m.Mode = FilterMode
				m.FilterInput = m.ActiveFilter
			case ";":
				m.ProcessSearchInput = ""
				m.Mode = ProcessSearchMode
				m.ProcessSearchInput = m.ActiveProcessSearch
			case "enter":
				if i := m.List.SelectedItem(); i != nil {
					m.SelectedPid = i.PID
					m.updateViewport()
				}
			case "up", "down", "j", "k":
				m.List.Update(msg)
				if i := m.List.SelectedItem(); i != nil {
					m.SelectedPid = i.PID
					m.updateViewport()
				}
				if m.Mode == BettercapMode {
					m.updateBettercapViewport()
				}
			case "pgup", "pgdown", "u", "d":
				m.Viewport.Update(msg)
			case "home", "end", "G":
				m.List.Update(msg)
				m.Viewport.Update(msg)
				if i := m.List.SelectedItem(); i != nil {
					m.SelectedPid = i.PID
					m.updateViewport()
				}
			}
		}

	case tea.MouseMsg:
		if m.Mode == LandingPageMode {
			if msg.Type == tea.MouseLeft {
				m.Mode = NormalMode
			}
		} else if m.Mode == CategorySelectionMode {
			if msg.Type == tea.MouseLeft {
				contentHeight := 4 + len(m.CategoryList)
				startY := (m.Height-contentHeight)/2 + 2
				if msg.Y >= startY && msg.Y < startY+len(m.CategoryList) {
					m.CategoryCursor = msg.Y - startY
					m.ActiveCategory = m.CategoryList[m.CategoryCursor]
					m.Mode = NormalMode
					m.refreshList()
				}
			} else if msg.Type == tea.MouseWheelUp {
				m.CategoryCursor--
				if m.CategoryCursor < 0 {
					m.CategoryCursor = len(m.CategoryList) - 1
				}
				return m, nil
			} else if msg.Type == tea.MouseWheelDown {
				m.CategoryCursor++
				if m.CategoryCursor >= len(m.CategoryList) {
					m.CategoryCursor = 0
				}
				return m, nil
			}
		} else if m.Mode == GlobalTrafficMode {
			if msg.Type == tea.MouseLeft {
				if msg.Y >= 7 && msg.Y < 7+m.GlobalViewport.Height {
					packetCount := len(m.GlobalPackets)
					if packetCount > 0 {
						numVisible := m.GlobalViewport.Height
						start := m.GlobalSelectedIdx - (numVisible / 2)
						if start < 0 {
							start = 0
						}

						clickedIdx := start + (msg.Y - 7)
						if clickedIdx >= 0 && clickedIdx < packetCount {
							if m.GlobalSelectedIdx == clickedIdx {
								m.InspectedPacket = m.GlobalPackets[clickedIdx]
								m.Mode = PacketDetailMode
								m.PacketDetailViewport.SetContent(m.getPacketDetailContent())
								return m, m.analyzePacketCmd(m.InspectedPacket)
							}
							m.GlobalSelectedIdx = clickedIdx
							m.updateGlobalViewport()
						}
					}
				}
			} else if msg.Type == tea.MouseWheelUp {
				m.GlobalSelectedIdx--
				if m.GlobalSelectedIdx < 0 && len(m.GlobalPackets) > 0 {
					m.GlobalSelectedIdx = 0
				}
				m.updateGlobalViewport()
			} else if msg.Type == tea.MouseWheelDown {
				m.GlobalSelectedIdx++
				if m.GlobalSelectedIdx >= len(m.GlobalPackets) {
					m.GlobalSelectedIdx = len(m.GlobalPackets) - 1
				}
				m.updateGlobalViewport()
			}
		} else if m.Mode == SettingsMode {
			if msg.Type == tea.MouseWheelUp {
				m.SettingsCursor = (m.SettingsCursor - 1 + 5) % 5
			} else if msg.Type == tea.MouseWheelDown {
				m.SettingsCursor = (m.SettingsCursor + 1) % 5
			}
			m.saveConfig()
			return m, nil
		} else if m.Mode == PacketDetailMode {
			if msg.Type == tea.MouseLeft {
				m.Mode = NormalMode
				return m, nil
			}
			if msg.Type == tea.MouseWheelUp {
				m.PacketDetailViewport.Update(tea.KeyMsg{Type: tea.KeyUp})
			} else if msg.Type == tea.MouseWheelDown {
				m.PacketDetailViewport.Update(tea.KeyMsg{Type: tea.KeyDown})
			}
		} else if m.Mode == BettercapMode {
			if msg.Type == tea.MouseLeft {
				if msg.Y >= 7 && msg.Y < 7+m.BettercapViewport.Height {
					packets := m.getFilteredMITMPackets()
					packetCount := len(packets)

					if packetCount > 0 {
						numVisible := m.BettercapViewport.Height
						start := m.MITMSelectedIdx - (numVisible / 2)
						if start < 0 {
							start = 0
						}

						clickedIdx := start + (msg.Y - 7)
						if clickedIdx >= 0 && clickedIdx < packetCount {
							if m.MITMSelectedIdx == clickedIdx {
								m.InspectedPacket = packets[clickedIdx]
								m.Mode = PacketDetailMode
								m.PacketDetailViewport.SetContent(m.getPacketDetailContent())
								return m, m.analyzePacketCmd(m.InspectedPacket)
							}
							m.MITMSelectedIdx = clickedIdx
							m.updateBettercapViewport()
						}
					}
				}
			} else if msg.Type == tea.MouseWheelUp {
				packets := m.getFilteredMITMPackets()
				m.MITMSelectedIdx--
				if m.MITMSelectedIdx < 0 {
					if len(packets) > 0 {
						m.MITMSelectedIdx = 0
					}
				}
				m.updateBettercapViewport()
			} else if msg.Type == tea.MouseWheelDown {
				packets := m.getFilteredMITMPackets()
				m.MITMSelectedIdx++
				if m.MITMSelectedIdx >= len(packets) {
					m.MITMSelectedIdx = len(packets) - 1
				}
				m.updateBettercapViewport()
			}
		} else if m.Mode == NormalMode {
			if msg.Type == tea.MouseLeft {
				if msg.X >= m.Width/3+4 && msg.X < m.Width-2 {
					row := msg.Y - 1
					if row >= 4 {
						pktIdx := row - 4 + m.Viewport.scrollOffset
						if pktIdx >= 0 && pktIdx < len(m.VisiblePackets) {
							m.InspectedPacket = m.VisiblePackets[pktIdx]
							m.Mode = PacketDetailMode
							m.PacketDetailViewport.SetContent(m.getPacketDetailContent())
							m.InspectedPacket.AIAnalysis = ""
							return m, m.analyzePacketCmd(m.InspectedPacket)
						}
					}
				}

				if msg.X >= 2 && msg.X < m.List.Width+2 && msg.Y >= 1 && msg.Y < m.List.Height+1 {
					row := msg.Y - 1
					if row >= 2 {
						visibleIdx := row - 2
						start := 0
						if m.List.selected >= m.List.Height-2 {
							start = m.List.selected - (m.List.Height - 3)
						}
						if start < 0 {
							start = 0
						}
						target := start + visibleIdx
						if target >= 0 && target < len(m.List.items) {
							m.List.selected = target
							if i := m.List.SelectedItem(); i != nil {
								m.SelectedPid = i.PID
								m.updateViewport()
							}
						}
					}
				}
			}

			if msg.Type == tea.MouseLeft && msg.Y >= m.Height-1 {
				if msg.X >= m.Width-15 {
					m.Mode = SettingsMode
					return m, nil
				}

				if msg.X < 12 {
					return m, m.toggleCaptureCmd()
				}
				if msg.X >= 13 && msg.X < 33 {
					m.AutoScroll = !m.AutoScroll
					return m, nil
				}
				if msg.X >= 34 && msg.X < 44 {
					m.Mode = GraphMode
					return m, nil
				}
				if msg.X >= 45 && msg.X < 53 {
					m.Mode = NetworkTopologyMode
					return m, nil
				}

				return m, m.toggleCaptureCmd()
			} else if msg.Type == tea.MouseWheelUp {
				if msg.X < m.List.Width+2 {
					m.List.Update(tea.KeyMsg{Type: tea.KeyUp})
					if i := m.List.SelectedItem(); i != nil {
						m.SelectedPid = i.PID
						m.updateViewport()
					}
				} else {
					m.Viewport.Update(tea.KeyMsg{Type: tea.KeyUp})
				}
			} else if msg.Type == tea.MouseWheelDown {
				if msg.X < m.List.Width+2 {
					m.List.Update(tea.KeyMsg{Type: tea.KeyDown})
					if i := m.List.SelectedItem(); i != nil {
						m.SelectedPid = i.PID
						m.updateViewport()
					}
				} else {
					m.Viewport.Update(tea.KeyMsg{Type: tea.KeyDown})
				}
			}
		}

	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		listWidth := msg.Width / 3
		viewportWidth := msg.Width - listWidth - 4
		listHeight := msg.Height - 4

		m.PacketDetailViewport.SetSize(m.Width-4, m.Height-2)
		m.HelpViewport.SetSize(m.Width-4, m.Height-2)
		m.BettercapViewport.SetSize(m.Width-4, m.Height-12)
		m.GlobalViewport.SetSize(m.Width-4, m.Height-12)
		if m.Mode == PacketDetailMode {
			m.PacketDetailViewport.SetContent(m.getPacketDetailContent())
			return m, nil
		}
		if m.Mode == HelpMode {
			m.HelpViewport.SetContent(m.renderHelpMenuContent())
			return m, nil
		}

		viewportHeight := msg.Height - 4

		if m.Mode == FilterMode || m.Mode == ProcessSearchMode {
			listHeight -= 1
			viewportHeight -= 1
		}

		m.List.SetSize(listWidth, listHeight)
		m.Viewport.SetSize(viewportWidth, viewportHeight)
		m.updateViewport()
	case AIResultMsg:
		m.InspectedPacket.AIAnalysis = string(msg)
		m.PacketDetailViewport.UpdateContent(m.getPacketDetailContent())
		return m, nil
	case MITMStatusMsg:
		m.MITMStatus = string(msg)
		if m.MITMStatus == "MITM: Active" {
			m.BettercapModules["arp.spoof"] = true
			m.BettercapModules["net.sniff"] = true
			m.Mode = BettercapMode
			m.updateBettercapViewport()
		}
		return m, nil
	case BettercapLogMsg:
		line := string(msg)
		m.BettercapLogs = append(m.BettercapLogs, line)
		if len(m.BettercapLogs) > 500 {
			m.BettercapLogs = m.BettercapLogs[1:]
		}
		if m.Mode == BettercapMode {
			m.updateBettercapViewport()
		}
		return m, nil
	case OllamaStatusMsg:
		m.OllamaStatus = string(msg)
		return m, nil
	case ExportResultMsg:
		m.ExportStatus = string(msg)
		m.PacketDetailViewport.SetContent(m.getPacketDetailContent())
		return m, nil
	case UpdateMsg:
		m.CursorVisible = !m.CursorVisible
		m.refreshList()
		m.updateHistory()
		if m.Mode == BettercapMode {
			m.updateBettercapViewport()
		} else if m.Mode == GlobalTrafficMode {
			m.updateGlobalViewport()
		}
		return m, tea.Tick(time.Second, func(t time.Time) tea.Msg {
			return UpdateMsg{}
		})
	}
	return m, nil
}

func (m *Model) analyzePacketCmd(pkt types.PacketData) tea.Cmd {
	if !m.UseAI {
		return nil
	}
	modelName := m.getSelectedModelName()
	return func() tea.Msg {
		analysis, err := ai.AnalyzePayload(pkt, modelName)
		if err != nil {
			return AIResultMsg("AI Analysis failed: " + err.Error())
		}
		return AIResultMsg(analysis)
	}
}

func (m *Model) saveConfig() {
	cfg := struct {
		UseAI          bool `json:"use_ai"`
		UseMITMSetting bool `json:"use_mitm"`
		ModelIdx       int  `json:"model_idx"`
		ThemeIdx       int  `json:"theme_idx"`
	}{
		UseAI:          m.UseAI,
		UseMITMSetting: m.UseMITMSetting,
		ModelIdx:       m.SelectedModelIdx,
		ThemeIdx:       m.SelectedThemeIdx,
	}
	data, _ := json.Marshal(cfg)
	_ = os.WriteFile("config.json", data, 0644)
}

func (m *Model) loadConfig() {
	data, err := os.ReadFile("config.json")
	if err != nil {
		return
	}
	var cfg struct {
		UseAI          bool `json:"use_ai"`
		UseMITMSetting bool `json:"use_mitm"`
		ModelIdx       int  `json:"model_idx"`
		ThemeIdx       int  `json:"theme_idx"`
	}
	if err := json.Unmarshal(data, &cfg); err == nil {
		m.UseAI = cfg.UseAI
		m.UseMITMSetting = cfg.UseMITMSetting
		m.SelectedModelIdx = cfg.ModelIdx
		m.SelectedThemeIdx = cfg.ThemeIdx
	}
}

func (m *Model) toggleMITMCmd(p *tea.Program) tea.Cmd {
	iface := m.InterfaceName
	if iface == "any" {
		iface = ""
	}
	return func() tea.Msg {
		stdout, err := network.StartMITM(iface)
		if err != nil {
			return MITMStatusMsg("MITM Err: " + err.Error())
		}

		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				if p != nil {
					p.Send(BettercapLogMsg(scanner.Text()))
				}
			}
		}()

		return MITMStatusMsg("MITM: Active")
	}
}

func (m *Model) exportPacketCmd(pkt types.PacketData) tea.Cmd {
	return func() tea.Msg {
		filename := fmt.Sprintf("packet_report_%s.txt", pkt.Timestamp.Format("20060102_150405"))

		var sb strings.Builder
		sb.WriteString("🦈 LIGMASHARK PACKET REPORT\n")
		sb.WriteString("===========================\n\n")
		sb.WriteString(fmt.Sprintf("Timestamp:   %s\n", pkt.Timestamp.Format("2006-01-02 15:04:05.000")))
		sb.WriteString(fmt.Sprintf("Protocol:    %s\n", pkt.Protocol))
		sb.WriteString(fmt.Sprintf("Process:     %s\n", pkt.ProcessName))
		sb.WriteString(fmt.Sprintf("Service:     %s\n", pkt.Service))
		sb.WriteString(fmt.Sprintf("Length:      %d bytes\n", pkt.Length))

		malicious := "No"
		if pkt.IsMalicious {
			malicious = "Yes (Threat Intel Match)"
		}
		sb.WriteString(fmt.Sprintf("Malicious:   %s\n\n", malicious))

		sb.WriteString("NETWORK CONTEXT\n")
		sb.WriteString("---------------\n")
		sb.WriteString(fmt.Sprintf("Source:      %s:%s\n", pkt.SrcIP, pkt.SrcPort))
		sb.WriteString(fmt.Sprintf("Destination: %s:%s\n", pkt.DstIP, pkt.DstPort))
		sb.WriteString(fmt.Sprintf("ISP/Location: %s\n\n", pkt.ISP))

		sb.WriteString("AI ANALYSIS\n")
		sb.WriteString("-----------\n")
		if pkt.AIAnalysis != "" {
			sb.WriteString(pkt.AIAnalysis)
			sb.WriteString("\n\n")
		} else {
			sb.WriteString("Analysis not completed at time of export.\n\n")
		}

		sb.WriteString("RAW PAYLOAD\n")
		sb.WriteString("-----------\n")
		sb.WriteString(pkt.Payload)
		sb.WriteString("\n")

		err := os.WriteFile(filename, []byte(sb.String()), 0644)
		if err != nil {
			return ExportResultMsg("Export failed: " + err.Error())
		}
		return ExportResultMsg("Success! Report saved to: " + filename)
	}
}

func (m *Model) SetupOllama(p *tea.Program) {
	status := func(s string) {
		if p != nil {
			p.Send(OllamaStatusMsg(s))
		}
	}

	var lastStatus string
	update := func(s string) {
		lastStatus = s
		status(s)
	}

	update("Checking Ollama server...")
	if !ai.CheckOllamaServer() {
		update("Ollama server not running. Attempting to start 'ollama serve' in background...")
		err := ai.StartOllamaServer()
		if err != nil {
			update(fmt.Sprintf("Failed to start Ollama: %v. Please start it manually.", err))
			return
		}
		time.Sleep(5 * time.Second)
		if !ai.CheckOllamaServer() {
			update("Ollama server did not start. Please check your Ollama installation.")
			return
		}
	}
	update("Ollama server is running.")

	modelName := m.getSelectedModelName()
	update(fmt.Sprintf("Checking for model '%s'...", modelName))
	installed, err := ai.CheckModelInstalled(modelName)
	if err != nil {
		update(fmt.Sprintf("Error checking model: %v", err))
		return
	}

	if !installed {
		update(fmt.Sprintf("Model '%s' not found. Attempting to pull...", modelName))
		pullCmd := exec.Command("ollama", "pull", modelName)
		output, err := pullCmd.CombinedOutput()
		if err != nil {
			update(fmt.Sprintf("Failed to pull model '%s': %v\nOutput: %s", modelName, err, string(output)))
			return
		}
		update(fmt.Sprintf("Model '%s' pulled successfully.", modelName))
	} else {
		update(fmt.Sprintf("Model '%s' is installed.", modelName))
	}

	fetched, _ := ai.GetAvailableModels()
	uniqueModels := make(map[string]bool)
	for _, mod := range m.AvailableModels {
		uniqueModels[mod] = true
	}
	for _, mod := range fetched {
		if !uniqueModels[mod] {
			m.AvailableModels = append(m.AvailableModels, mod)
		}
	}

	if lastStatus == fmt.Sprintf("Model '%s' is installed.", modelName) || lastStatus == fmt.Sprintf("Model '%s' pulled successfully.", modelName) {
		status("Ollama ready for AI analysis.")
	} else {
		status("Ollama setup failed: " + lastStatus)
	}
}

func (m *Model) exportMITMSessionCmd() tea.Cmd {
	return func() tea.Msg {
		m.Mu.RLock()
		packets := m.MITMPackets
		m.Mu.RUnlock()
		if len(packets) == 0 {
			return ExportResultMsg("No packets to export.")
		}
		filename := fmt.Sprintf("mitm_session_%s.txt", time.Now().Format("20060102_150405"))
		var sb strings.Builder
		sb.WriteString("🦈 LIGMASHARK MITM SESSION EXPORT\n")
		sb.WriteString("================================\n\n")
		for _, pkt := range packets {
			sb.WriteString(fmt.Sprintf("[%s] %s | %s:%s -> %s:%s | ISP: %s | Len: %d\n",
				pkt.Timestamp.Format("15:04:05.000"), pkt.Protocol, pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.ISP, pkt.Length))
		}
		err := os.WriteFile(filename, []byte(sb.String()), 0644)
		if err != nil {
			return ExportResultMsg("Export failed: " + err.Error())
		}
		return ExportResultMsg("Session exported to: " + filename)
	}
}

func (m *Model) updateBettercapViewport() {
	var sb strings.Builder
	packets := m.getFilteredMITMPackets()

	if m.MITMSelectedIdx >= len(packets) {
		m.MITMSelectedIdx = len(packets) - 1
	}
	if m.MITMSelectedIdx == -1 && len(packets) > 0 {
		m.MITMSelectedIdx = len(packets) - 1
	}

	if len(packets) == 0 {
		sb.WriteString("\nWaiting for intercepted traffic... (Is ARP spoofing active?)\n")
		if len(m.BettercapLogs) > 0 {
			sb.WriteString("\nRecent Bettercap Events:\n")
			count := 5
			if len(m.BettercapLogs) < count {
				count = len(m.BettercapLogs)
			}
			for i := len(m.BettercapLogs) - count; i < len(m.BettercapLogs); i++ {
				sb.WriteString("  " + m.BettercapLogs[i] + "\n")
			}
		}
	} else {
		numVisible := m.BettercapViewport.Height
		start := 0
		if len(packets) > numVisible {
			start = m.MITMSelectedIdx - (numVisible / 2)
			if start < 0 {
				start = 0
			}
			if start+numVisible > len(packets) {
				start = len(packets) - numVisible
			}
		}

		end := start + numVisible
		if end > len(packets) {
			end = len(packets)
		}

		for i := start; i < end; i++ {
			pkt := packets[i]
			line := fmt.Sprintf("%-10s %-8s %-15s %-15s %-15s %-20s %d",
				pkt.Timestamp.Format("15:04:05"), pkt.Protocol, pkt.SrcIP, pkt.DstIP, pkt.ProcessName, pkt.ISP, pkt.Length)

			style := lipgloss.NewStyle().MaxWidth(m.BettercapViewport.Width).MaxHeight(1)
			if i == m.MITMSelectedIdx {
				style = style.Background(lipgloss.Color("62")).Foreground(lipgloss.Color("230"))
			} else if pkt.IsMalicious {
				style = style.Foreground(lipgloss.Color("9"))
			}
			sb.WriteString(style.Render(line))
			sb.WriteString("\n")
		}
	}

	m.BettercapViewport.SetContent(sb.String())
}

func (m *Model) updateGlobalViewport() {
	var sb strings.Builder
	m.Mu.RLock()
	packets := m.GlobalPackets
	m.Mu.RUnlock()

	if m.GlobalSelectedIdx >= len(packets) {
		m.GlobalSelectedIdx = len(packets) - 1
	}
	if m.GlobalSelectedIdx == -1 && len(packets) > 0 {
		m.GlobalSelectedIdx = len(packets) - 1
	}

	numVisible := m.GlobalViewport.Height
	start := 0
	if len(packets) > numVisible {
		start = m.GlobalSelectedIdx - (numVisible / 2)
		if start < 0 {
			start = 0
		}
		if start+numVisible > len(packets) {
			start = len(packets) - numVisible
		}
	}

	end := start + numVisible
	if end > len(packets) {
		end = len(packets)
	}

	for i := start; i < end; i++ {
		pkt := packets[i]
		line := fmt.Sprintf("%-10s %-8s %-15s %-15s %-15s %-20s %d",
			pkt.Timestamp.Format("15:04:05"), pkt.Protocol, pkt.SrcIP, pkt.DstIP, pkt.ProcessName, pkt.ISP, pkt.Length)

		style := lipgloss.NewStyle().MaxWidth(m.GlobalViewport.Width).MaxHeight(1)
		if i == m.GlobalSelectedIdx {
			style = style.Background(lipgloss.Color("62")).Foreground(lipgloss.Color("230"))
		}
		sb.WriteString(style.Render(line) + "\n")
	}
	m.GlobalViewport.SetContent(sb.String())
}

func (m *Model) refreshList() {
	m.Mu.RLock()
	items := make([]types.ProcItem, 0, len(m.Processes))
	for _, p := range m.Processes {
		items = append(items, *p)
	}
	m.Mu.RUnlock()

	sort.Slice(items, func(i, j int) bool {
		switch m.SortMode {
		case 1:
			return items[i].PID < items[j].PID
		case 2:
			return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
		default:
			if len(items[i].Packets) != len(items[j].Packets) {
				return len(items[i].Packets) > len(items[j].Packets)
			}
			return items[i].PID < items[j].PID
		}
	})

	filteredItems := make([]types.ProcItem, 0)
	for _, item := range items {
		if m.shouldShowProcess(&item) {
			if m.ActiveProcessSearch == "" || strings.Contains(strings.ToLower(item.Name), strings.ToLower(m.ActiveProcessSearch)) {
				filteredItems = append(filteredItems, item)
			}
		}
	}

	m.List.SetItems(filteredItems)
	m.updateViewport()
}

func (m *Model) updateHistory() {
	m.Mu.RLock()
	var currentIn, currentOut uint64
	for _, p := range m.Processes {
		currentIn += p.BytesIn
		currentOut += p.BytesOut
	}
	m.Mu.RUnlock()

	deltaIn := uint64(0)
	deltaOut := uint64(0)

	if m.LastTotalIn > 0 && currentIn >= m.LastTotalIn {
		deltaIn = currentIn - m.LastTotalIn
	}
	if m.LastTotalOut > 0 && currentOut >= m.LastTotalOut {
		deltaOut = currentOut - m.LastTotalOut
	}

	m.LastTotalIn = currentIn
	m.LastTotalOut = currentOut

	m.History = append(m.History, types.BandwidthPoint{In: deltaIn, Out: deltaOut})
	if len(m.History) > 100 {
		m.History = m.History[1:]
	}
}

func (m *Model) updateViewport() {
	m.Mu.RLock()
	defer m.Mu.RUnlock()

	if p, ok := m.Processes[m.SelectedPid]; ok {
		var buf strings.Builder
		buf.WriteString(fmt.Sprintf("Traffic for %s (PID: %d)\n\n", p.Name, p.PID))
		headerStyle := lipgloss.NewStyle().MaxWidth(m.Viewport.Width).MaxHeight(1)
		buf.WriteString(headerStyle.Render(fmt.Sprintf("%-8s %-15s %-15s %-20s %-15s %s", "PROTO", "SOURCE", "DEST", "ISP", "SERVICE", "LEN")) + "\n")
		buf.WriteString(strings.Repeat("-", m.Viewport.Width) + "\n")

		filteredPackets := make([]types.PacketData, 0)
		for _, pkt := range p.Packets {
			ispMatch := m.ActiveFilter == "" || strings.Contains(strings.ToLower(pkt.ISP), strings.ToLower(m.ActiveFilter))
			protoMatch := m.ActiveProtocolFilter == "ALL" || pkt.Protocol == m.ActiveProtocolFilter
			if ispMatch && protoMatch {
				filteredPackets = append(filteredPackets, pkt)
			}
		}

		displayCount := 50
		if len(filteredPackets) < displayCount {
			displayCount = len(filteredPackets)
		}

		m.VisiblePackets = nil
		for i := len(filteredPackets) - 1; i >= len(filteredPackets)-displayCount; i-- {
			pkt := filteredPackets[i]
			m.VisiblePackets = append(m.VisiblePackets, pkt)

			info := pkt.Service
			if pkt.HTTPStatus != "" {
				info = "HTTP " + pkt.HTTPStatus
			} else if pkt.HTTPMethod != "" {
				info = pkt.HTTPMethod
			}

			line := fmt.Sprintf("%-8s %-15s %-15s %-20s %-15s %d", pkt.Protocol, pkt.SrcIP, pkt.DstIP, pkt.ISP, info, pkt.Length)
			style := lipgloss.NewStyle().MaxWidth(m.Viewport.Width).MaxHeight(1)
			if pkt.IsMalicious {
				style = style.Foreground(lipgloss.Color("9"))
			}
			buf.WriteString(style.Render(line) + "\n")
		}
		m.Viewport.SetContent(buf.String())
		if m.AutoScroll {
			m.Viewport.ScrollToEnd()
		}
	}
}

func (m *Model) renderHelpMenuContent() string {
	width := m.HelpViewport.Width
	style := lipgloss.NewStyle().Width(width)
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(m.getTheme().Primary)).Render("Ligmashark Hotkeys")

	helpText := `
Global:
  q / Esc / Ctrl+C : Quit Ligmashark
  ?                : Toggle this Help Menu

Navigation (Process List & Viewport):
  j / k            : Move down / up list
  Home / End / G   : Jump to Top / Bottom
  Enter            : Select process / Open packet detail
  u / PgUp         : Scroll viewport up
  d / PgDown       : Scroll viewport down
  Home / End / G   : Viewport top / bottom
  Mouse Wheel      : Scroll viewport
  Left Click       : Select process / Open packet detail / Exit detail/help

Traffic View:
  /                : Filter processes by ISP
  p                : Pause/Resume packet capture
  a                : Toggle Auto-scroll
  f                : Cycle Protocol Filter (TCP/UDP/ICMP)
  m                : Toggle MITM (Bettercap)
  b                : Toggle Bettercap Dashboard
  t                : Toggle Global Traffic View
  S                : Open Settings Menu
  c                : Clear history for selected process
  e                : Export Packet Report (in Detail view)
  ;                : Search/Filter process by name
  g                : Toggle Graph Mode
  n                : Toggle Network Topology Map
`
	return lipgloss.JoinVertical(lipgloss.Left, title, style.Render(helpText), "\nPress 'Esc' or 'q' to return.")
}

func (m *Model) View() string {
	if m.Mode == LandingPageMode {
		return m.renderLandingPage()
	} else if m.Mode == PacketDetailMode {
		return m.PacketDetailViewport.View()
	} else if m.Mode == HelpMode {
		m.HelpViewport.SetContent(m.renderHelpMenuContent())
		return m.HelpViewport.View()
	} else if m.Mode == CategorySelectionMode {
		return m.renderCategorySelection()
	} else if m.Mode == GraphMode {
		return m.renderGraphMode()
	} else if m.Mode == BettercapMode {
		return m.renderBettercapMode()
	} else if m.Mode == SettingsMode {
		return m.renderSettingsMode()
	} else if m.Mode == GlobalTrafficMode {
		return m.renderGlobalTrafficMode()
	} else if m.Mode == NetworkTopologyMode {
		return m.renderNetworkTopology()
	}

	m.List.PrimaryColor = m.getTheme().Primary
	listRender := m.List.View()
	viewportRender := m.Viewport.View()

	var bottomBar string
	if m.Mode == FilterMode {
		cursor := " "
		if m.CursorVisible {
			cursor = "█"
		}
		bottomBar = lipgloss.JoinHorizontal(lipgloss.Left,
			lipgloss.NewStyle().Foreground(lipgloss.Color(m.getTheme().Accent)).Render("Filter ISP: "),
			filterInputStyle.Render(m.FilterInput+cursor),
			lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(" [Enter] Apply [Esc] Cancel"),
		)
	} else if m.Mode == ProcessSearchMode {
		cursor := " "
		if m.CursorVisible {
			cursor = "█"
		}
		bottomBar = lipgloss.JoinHorizontal(lipgloss.Left,
			lipgloss.NewStyle().Foreground(lipgloss.Color(m.getTheme().Accent)).Render("Search Process: "),
			filterInputStyle.Render(m.ProcessSearchInput+cursor),
			lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(" [Enter] Apply [Esc] Cancel"),
		)
	}

	autoScrollStatus := "ON"
	if !m.AutoScroll {
		autoScrollStatus = "OFF"
	}

	btnStyle := lipgloss.NewStyle().Background(lipgloss.Color("236")).Padding(0, 1).MarginRight(1)
	captureBar := btnStyle.Copy().Foreground(lipgloss.Color(m.getTheme().Accent)).Bold(true).Render("[P] " + m.CaptureStatus)
	scrollBar := btnStyle.Copy().Foreground(lipgloss.Color(m.getTheme().Accent)).Bold(true).Render("[A] Scroll Lock: " + autoScrollStatus)
	graphBtn := btnStyle.Copy().Foreground(lipgloss.Color("10")).Bold(true).Render("[G] Graph")
	mapBtn := btnStyle.Copy().Foreground(lipgloss.Color("13")).Bold(true).Render("[N] Map")
	mitmBar := btnStyle.Copy().Foreground(lipgloss.Color("160")).Bold(true).Render("[M] " + m.MITMStatus)
	processFilterBar := btnStyle.Copy().Foreground(lipgloss.Color(m.getTheme().Accent)).Bold(true).Render("[S] " + m.ProcessFilterSetting.String())
	protoFilterBar := btnStyle.Copy().Foreground(lipgloss.Color(m.getTheme().Accent)).Bold(true).Render("[F] " + m.ActiveProtocolFilter)
	settingsBtn := btnStyle.Copy().MarginRight(0).Foreground(lipgloss.Color(m.getTheme().Accent)).Render("[S] Settings")

	activeFilterBar := ""
	if m.ActiveFilter != "" {
		activeFilterBar = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(" ISP: ") +
			lipgloss.NewStyle().Foreground(lipgloss.Color(m.getTheme().Accent)).Render(m.ActiveFilter) + " "
	}

	activeProcessSearchBar := ""
	if m.ActiveProcessSearch != "" {
		activeProcessSearchBar = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(" Search: ") +
			lipgloss.NewStyle().Foreground(lipgloss.Color(m.getTheme().Accent)).Render(m.ActiveProcessSearch) + " "
	}

	legend := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(" [1-4] Proto [o] Sort [X] Reset [j/k] Nav [Enter] View [g] Graph [n] Map [t] Traffic [;] Search [/] Filter [S] Settings [?] Help ")
	statusLine := lipgloss.JoinHorizontal(lipgloss.Left, captureBar, scrollBar, graphBtn, mapBtn, mitmBar, processFilterBar, protoFilterBar, activeFilterBar, activeProcessSearchBar)

	filler := strings.Repeat(" ", max(0, m.Width-lipgloss.Width(statusLine)-lipgloss.Width(settingsBtn)))
	fullStatusLine := lipgloss.JoinHorizontal(lipgloss.Left, statusLine, filler, settingsBtn)

	footer := lipgloss.JoinVertical(lipgloss.Left, legend, fullStatusLine)
	if bottomBar != "" {
		footer = lipgloss.JoinVertical(lipgloss.Left, bottomBar, footer)
	}

	mainContent := lipgloss.JoinHorizontal(
		lipgloss.Top,
		docStyle.Render(listRender),
		docStyle.Render(viewportRender),
	)

	return lipgloss.JoinVertical(lipgloss.Left, mainContent, footer)
}

func (m *Model) renderCategorySelection() string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(m.getTheme().Primary)).Render("Select Process Category")

	var sb strings.Builder
	for i, cat := range m.CategoryList {
		cursor := "  "
		style := lipgloss.NewStyle()
		if i == m.CategoryCursor {
			cursor = "> "
			style = style.Foreground(lipgloss.Color(m.getTheme().Accent)).Bold(true)
		}
		sb.WriteString(cursor + style.Render(cat) + "\n")
	}

	help := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("\n[j/k] Navigate • [Enter] Select • [Esc] Back")

	content := lipgloss.JoinVertical(lipgloss.Center, title, "\n", sb.String(), help)
	return landingPageStyle.Copy().BorderForeground(lipgloss.Color(m.getTheme().Primary)).Width(m.Width - 4).Height(m.Height - 2).Render(content)
}

func (m *Model) renderSettingsMode() string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(m.getTheme().Primary)).Render(" Ligmashark Settings ")

	options := []string{
		fmt.Sprintf("AI Analysis:    %s", m.toggleLabel(m.UseAI)),
		fmt.Sprintf("AI Model:       %s", m.getSelectedModelName()),
		fmt.Sprintf("MITM Features:  %s", m.toggleLabel(m.UseMITMSetting)),
		fmt.Sprintf("Theme:          %s", m.getTheme().Name),
		"Back to Monitor",
	}

	var sb strings.Builder
	for i, opt := range options {
		cursor := "  "
		style := lipgloss.NewStyle()
		if i == m.SettingsCursor {
			cursor = "> "
			style = style.Foreground(lipgloss.Color(m.getTheme().Accent)).Bold(true)
		}
		sb.WriteString(cursor + style.Render(opt) + "\n")
	}

	help := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("\n[j/k] Navigate • [h/l] Cycle Option • [Enter] Select • [S/Esc] Exit")
	content := lipgloss.JoinVertical(lipgloss.Center, title, "\n", sb.String(), help)
	return landingPageStyle.Copy().BorderForeground(lipgloss.Color(m.getTheme().Primary)).Width(m.Width - 4).Height(m.Height - 2).Render(content)
}

func (m *Model) getSelectedModelName() string {
	if len(m.AvailableModels) == 0 {
		return "qwen2.5:0.5b"
	}
	return m.AvailableModels[m.SelectedModelIdx]
}

func (m *Model) toggleLabel(b bool) string {
	if b {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Render("[ENABLED]")
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("160")).Render("[DISABLED]")
}

func (m *Model) IsCapturePaused() bool {
	if m.CapturePaused == nil {
		return false
	}
	m.Mu.RLock()
	defer m.Mu.RUnlock()
	return *m.CapturePaused
}

func (m *Model) toggleCaptureCmd() tea.Cmd {
	if m.IsCapturePaused() {
		return func() tea.Msg { return ResumeCaptureMsg{} }
	}
	return func() tea.Msg { return PauseCaptureMsg{} }
}

func (m *Model) getPacketDetailContent() string {
	width := m.PacketDetailViewport.Width
	style := lipgloss.NewStyle().Width(width)
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(m.getTheme().Primary)).Render("Packet Overview")

	aiText := m.InspectedPacket.AIAnalysis
	if aiText == "" {
		aiText = "Analyzing payload with qwen2.5:0.5b..."
	}

	maliciousStatus := "No"
	if m.InspectedPacket.IsMalicious {
		maliciousStatus = "YES (Detected by ThreatFox)"
	}

	details := fmt.Sprintf(
		"Timestamp: %s\nProtocol:  %s\nLength:    %d bytes\nMalicious: %s\n\n"+
			"Source:      %s:%s\nDestination: %s:%s\nISP:         %s\n\n"+
			"AI Analysis (qwen2.5:0.5b):\n%s\n\n"+
			"Payload:\n%s",
		m.InspectedPacket.Timestamp.Format("15:04:05.000"),
		m.InspectedPacket.Protocol,
		m.InspectedPacket.Length,
		maliciousStatus,
		m.InspectedPacket.SrcIP, m.InspectedPacket.SrcPort,
		m.InspectedPacket.DstIP, m.InspectedPacket.DstPort,
		m.InspectedPacket.ISP,
		aiText,
		m.InspectedPacket.Payload,
	)

	exportStatus := ""
	if m.ExportStatus != "" {
		exportStatus = lipgloss.NewStyle().Foreground(lipgloss.Color(m.getTheme().Accent)).Bold(true).Render("\n" + m.ExportStatus)
	}

	help := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("\n[E] Export Report • [Mouse Wheel] Scroll • [Esc/q] Back")
	content := lipgloss.JoinVertical(lipgloss.Left, title, style.Render(details), exportStatus, help)
	return content
}

type ProcessFilter int

const (
	FilterEverything ProcessFilter = iota
	FilterForeground
	FilterBackground
)

func (pf ProcessFilter) String() string {
	switch pf {
	case FilterEverything:
		return "Everything"
	case FilterForeground:
		return "Only Foreground apps"
	case FilterBackground:
		return "Only Background Apps"
	}
	return "Unknown"
}

func (m *Model) cycleProcessFilter() {
	m.ProcessFilterSetting = (m.ProcessFilterSetting + 1) % 3
	m.refreshList()
}

func (m *Model) shouldShowProcess(p *types.ProcItem) bool {
	if m.ActiveCategory != "" && m.ActiveCategory != "All Traffic" {
		if p.Category != m.ActiveCategory {
			return false
		}
	}
	if m.ProcessFilterSetting == FilterEverything {
		return true
	}

	proc, err := process.NewProcess(p.PID)
	if err != nil {
		return false
	}
	isBackground, err := proc.Background()
	if err != nil {
		return false
	}

	if m.ProcessFilterSetting == FilterForeground && !isBackground {
		return true
	}
	if m.ProcessFilterSetting == FilterBackground && isBackground {
		return true
	}
	return false
}

func (m *Model) renderGraphMode() string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(m.getTheme().Primary)).Render("Network Traffic (Bytes/sec)")

	var maxIn, maxOut uint64
	for _, p := range m.History {
		if p.In > maxIn {
			maxIn = p.In
		}
		if p.Out > maxOut {
			maxOut = p.Out
		}
	}

	graphHeight := (m.Height - 16) / 2
	if graphHeight < 2 {
		graphHeight = 2
	}

	renderChart := func(label string, color string, maxValue uint64, getVal func(types.BandwidthPoint) uint64) string {
		var sb strings.Builder
		sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Bold(true).Render(label))
		sb.WriteString("\n")

		chartWidth := m.Width - 20
		if chartWidth < 10 {
			chartWidth = 10
		}

		endIdx := len(m.History) - m.GraphScrollOffset
		startIdx := endIdx - chartWidth
		if startIdx < 0 {
			startIdx = 0
		}
		if endIdx < 0 {
			endIdx = 0
		}
		if endIdx > len(m.History) {
			endIdx = len(m.History)
		}

		historyToDraw := []types.BandwidthPoint{}
		if endIdx > startIdx {
			historyToDraw = m.History[startIdx:endIdx]
		}

		for h := graphHeight; h > 0; h-- {
			threshold := uint64(float64(maxValue) * float64(h) / float64(graphHeight))
			if h == graphHeight {
				sb.WriteString(fmt.Sprintf("%8s ┐", formatBytes(maxValue)))
			} else {
				sb.WriteString(fmt.Sprintf("%8s │", formatBytes(threshold)))
			}

			for _, p := range historyToDraw {
				val := getVal(p)
				if maxValue > 0 && val >= threshold && val > 0 {
					sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Render("┃"))
				} else {
					sb.WriteString(" ")
				}
			}
			sb.WriteString("\n")
		}
		sb.WriteString("         └" + strings.Repeat("─", len(historyToDraw)) + "\n")
		return sb.String()
	}

	inChart := renderChart("Incoming Traffic", "10", maxIn, func(p types.BandwidthPoint) uint64 { return p.In })
	outChart := renderChart("Outgoing Traffic", "12", maxOut, func(p types.BandwidthPoint) uint64 { return p.Out })

	m.Mu.RLock()
	type procStats struct {
		name  string
		pid   int32
		total uint64
	}
	var stats []procStats
	for _, p := range m.Processes {
		if p.BytesIn+p.BytesOut > 0 {
			stats = append(stats, procStats{p.Name, p.PID, p.BytesIn + p.BytesOut})
		}
	}
	m.Mu.RUnlock()
	sort.Slice(stats, func(i, j int) bool { return stats[i].total > stats[j].total })

	var topTalkersStr string
	if len(stats) > 0 {
		limit := 3
		if len(stats) < limit {
			limit = len(stats)
		}
		var lines []string
		for i := 0; i < limit; i++ {
			lines = append(lines, fmt.Sprintf("%s (%d): %s", stats[i].name, stats[i].pid, formatBytes(stats[i].total)))
		}
		topTalkersStr = "\n" + lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(m.getTheme().Accent)).Render("Top Talkers (Session): ") + strings.Join(lines, "  │  ")
	}

	scrollInfo := ""
	if m.GraphScrollOffset > 0 {
		scrollInfo = fmt.Sprintf(" [Scrolling: %d points back]", m.GraphScrollOffset)
	}

	help := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("\n[←/→] Scroll History • [g/Esc/q] Return" + scrollInfo)

	return landingPageStyle.Copy().BorderForeground(lipgloss.Color(m.getTheme().Primary)).Width(m.Width - 4).Height(m.Height - 2).Render(
		lipgloss.JoinVertical(lipgloss.Center, title, "\n", inChart, "\n", outChart, topTalkersStr, help),
	)
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func (m *Model) renderLandingPage() string {
	theme := m.getTheme()
	primary := lipgloss.Color(theme.Primary)
	accent := lipgloss.Color(theme.Accent)

	title := lipgloss.NewStyle().Bold(true).Foreground(primary).Padding(0, 2).Render("🦈 LIGMASHARK")
	author := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("Created by val (@mayshecry)")

	disclaimer := lipgloss.NewStyle().
		Foreground(lipgloss.Color("196")).
		Bold(true).
		Border(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("196")).
		Padding(0, 1).
		MarginTop(1).
		Render("⚠️ LEGAL DISCLAIMER: Use MITM features responsibly. Intercepting traffic on networks\nyou do not own or have explicit permission to audit is illegal and unethical.")

	desc := lipgloss.NewStyle().Width(70).Align(lipgloss.Center).MarginTop(1).Render(
		"A high-performance TUI network analyzer with local AI-powered packet inspection.\n" +
			"Map connections to processes, analyze ISPs, and assemble streams in real-time.")

	infoKeyStyle := lipgloss.NewStyle().Foreground(accent).Bold(true)
	infoValStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))

	specs := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("240")).
		Padding(1, 4).
		MarginTop(1).
		Render(lipgloss.JoinVertical(lipgloss.Left,
			fmt.Sprintf("%s %s", infoKeyStyle.Render("OS:      "), infoValStyle.Render(m.SystemInfo.OS)),
			fmt.Sprintf("%s %s", infoKeyStyle.Render("HOST:    "), infoValStyle.Render(m.SystemInfo.Hostname)),
			fmt.Sprintf("%s %s", infoKeyStyle.Render("CPU:     "), infoValStyle.Render(m.SystemInfo.CPU)),
			fmt.Sprintf("%s %s", infoKeyStyle.Render("RAM:     "), infoValStyle.Render(m.SystemInfo.Memory)),
			fmt.Sprintf("%s %s", infoKeyStyle.Render("UPTIME:  "), infoValStyle.Render(m.SystemInfo.Uptime)),
			fmt.Sprintf("%s %s", infoKeyStyle.Render("VERSION: "), infoValStyle.Render(m.SystemInfo.GoVersion)),
		))

	ollama := lipgloss.NewStyle().Foreground(lipgloss.Color("205")).MarginTop(1).Render("✨ " + m.OllamaStatus)
	help := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).MarginTop(1).Render("[Enter/h] Start Monitoring • [q] Quit")

	mainLayout := lipgloss.JoinVertical(lipgloss.Center,
		title,
		author,
		desc,
		specs,
		disclaimer,
		ollama,
		help,
	)

	return landingPageStyle.Copy().
		BorderForeground(primary).
		Width(m.Width - 4).
		Height(m.Height - 2).
		Render(mainLayout)
}

func (m *Model) renderGlobalTrafficMode() string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(m.getTheme().Primary)).Padding(0, 1).Render(" Global Real-time Traffic ")
	description := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Italic(true).Render("Monitoring all local process traffic mixed")

	tableHeader := lipgloss.NewStyle().Foreground(lipgloss.Color("249")).Bold(true).Render(
		fmt.Sprintf("  %-10s %-8s %-15s %-15s %-15s %-20s %s", "TIME", "PROTO", "SOURCE", "DEST", "PROCESS", "ISP", "LEN"))

	content := lipgloss.JoinVertical(lipgloss.Left,
		title,
		description,
		"\n",
		tableHeader,
		lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, false, true, false).BorderForeground(lipgloss.Color("237")).Width(m.Width-4).Render(""),
		m.GlobalViewport.View(),
	)

	help := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("[j/k] Scroll • [Enter] Inspect • [t/Esc] Back")

	return docStyle.Render(lipgloss.JoinVertical(lipgloss.Left, content, "\n", help))
}

func (m *Model) renderBettercapMode() string {
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("160")).Padding(0, 1).Background(lipgloss.Color("235"))
	title := titleStyle.Render(" Ligmashark MITM (Powered by Bettercap) ")

	statusColor := "241"
	statusText := "INACTIVE"
	if network.IsMITMActive() {
		statusColor = "42"
		statusText = "ACTIVE"
	}

	status := lipgloss.NewStyle().Foreground(lipgloss.Color(statusColor)).Bold(true).Render("● " + statusText)
	iface := lipgloss.NewStyle().Foreground(lipgloss.Color("246")).Render("Interface: " + m.InterfaceName)

	header := lipgloss.JoinHorizontal(lipgloss.Center, title, "  ", status, "  ", iface)

	junkStatus := "OFF"
	if m.MITMJunkFilter {
		junkStatus = "ON"
	}

	filterInfo := lipgloss.NewStyle().Foreground(lipgloss.Color("246")).Render(fmt.Sprintf(
		" [X] Junk Filter: %s | [F] Protocol: %s ", junkStatus, m.MITMProtocolFilter))

	searchBar := ""
	if m.MITMSearchActive || m.MITMSearchInput != "" {
		cursor := " "
		if m.CursorVisible && m.MITMSearchActive {
			cursor = "█"
		}
		searchBar = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Render(" / Search: " + m.MITMSearchInput + cursor)
	}

	description := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Italic(true).Render("Intercepting network traffic via ARP Spoofing")

	controls := lipgloss.JoinHorizontal(lipgloss.Center, filterInfo, searchBar)

	tableHeader := lipgloss.NewStyle().Foreground(lipgloss.Color("249")).Bold(true).Render(
		fmt.Sprintf("  %-10s %-8s %-15s %-15s %-15s %-20s %s", "TIME", "PROTO", "SOURCE", "DEST", "PROCESS", "ISP", "LEN"))

	exportStatus := ""
	if m.ExportStatus != "" {
		exportStatus = " | " + lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Render(m.ExportStatus)
	}

	content := lipgloss.JoinVertical(lipgloss.Left,
		header,
		description,
		controls,
		"\n",
		tableHeader,
		lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, false, true, false).BorderForeground(lipgloss.Color("237")).Width(m.Width-4).Render(""),
		m.BettercapViewport.View(),
	)

	help := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("[j/k] Scroll • [Enter] Inspect • [X] Junk • [F] Proto • [/] Search • [C] Clear • [E] Export • [Esc] Back" + exportStatus)

	return docStyle.Render(lipgloss.JoinVertical(lipgloss.Left, content, "\n", help))
}

func isJunkPacket(pkt types.PacketData) bool {
	junkPorts := map[string]bool{
		"5353": true, "5355": true, "1900": true, "137": true, "138": true, "67": true, "68": true, "123": true,
	}
	return junkPorts[pkt.SrcPort] || junkPorts[pkt.DstPort]
}

func (m *Model) getFilteredMITMPackets() []types.PacketData {
	m.Mu.RLock()
	defer m.Mu.RUnlock()
	var filtered []types.PacketData
	for _, pkt := range m.MITMPackets {
		if m.MITMJunkFilter && isJunkPacket(pkt) {
			continue
		}
		if m.MITMProtocolFilter != "ALL" {
			match := false
			if m.MITMProtocolFilter == "HTTP" && (pkt.HTTPMethod != "" || pkt.HTTPStatus != "") {
				match = true
			} else if m.MITMProtocolFilter == "DNS" && (pkt.SrcPort == "53" || pkt.DstPort == "53") {
				match = true
			} else if pkt.Protocol == m.MITMProtocolFilter {
				match = true
			}
			if !match {
				continue
			}
		}
		if m.MITMSearchInput != "" {
			search := strings.ToLower(m.MITMSearchInput)
			if !strings.Contains(strings.ToLower(pkt.SrcIP), search) &&
				!strings.Contains(strings.ToLower(pkt.DstIP), search) &&
				!strings.Contains(strings.ToLower(pkt.ISP), search) &&
				!strings.Contains(strings.ToLower(pkt.Payload), search) {
				continue
			}
		}
		filtered = append(filtered, pkt)
	}
	return filtered
}

func (m *Model) renderNetworkTopology() string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(m.getTheme().Primary)).Render(" 🗺️ Network Topology Map ")

	m.Mu.RLock()
	defer m.Mu.RUnlock()

	type node struct {
		children map[string]int
		display  map[string]string
		total    int
	}

	topology := make(map[string]node)
	topology["This Machine"] = node{children: make(map[string]int), display: make(map[string]string)}

	for _, p := range m.Processes {
		for _, pkt := range p.Packets {
			if network.IsHostIP(pkt.SrcIP) || network.IsHostIP(pkt.DstIP) {
				target := pkt.ISP
				if target == "Local Network" || target == "Unknown" || target == "" {
					if network.IsHostIP(pkt.SrcIP) {
						target = pkt.DstIP
					} else {
						target = pkt.SrcIP
					}
				}
				root := topology["This Machine"]
				root.children[target]++
				root.total++
				if pkt.Hostname != "" && network.IsLocalIP(target) {
					root.display[target] = fmt.Sprintf("%s (%s)", pkt.Hostname, target)
				}
				topology["This Machine"] = root
			} else if network.IsMITMActive() {
				srcDisplay := pkt.SrcIP
				if !network.IsHostIP(pkt.SrcIP) {
					dev := network.IdentifyDevice(pkt.SrcMAC)
					if pkt.Hostname != "" && network.IsLocalIP(pkt.SrcIP) {
						srcDisplay = fmt.Sprintf("%s (%s)", pkt.Hostname, pkt.SrcIP)
					} else if !strings.HasPrefix(dev, "OUI:") && dev != "Unknown Device" {
						srcDisplay = fmt.Sprintf("%s (%s)", pkt.SrcIP, dev)
					}
				}
				if _, ok := topology[srcDisplay]; !ok {
					topology[srcDisplay] = node{children: make(map[string]int), display: make(map[string]string)}
				}
				root := topology[srcDisplay]
				root.children[pkt.DstIP]++
				root.total++
				topology[srcDisplay] = root
			}
		}
	}

	nodeStyle := lipgloss.NewStyle().Padding(0, 1).Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("240"))
	thisMachineBox := nodeStyle.Copy().BorderForeground(lipgloss.Color(m.getTheme().Primary)).Foreground(lipgloss.Color(m.getTheme().Primary)).Bold(true).Render(" THIS MACHINE ")

	type childInfo struct {
		name  string
		count int
	}
	var localChildren, externalChildren []childInfo
	for child, count := range topology["This Machine"].children {
		displayName := child
		if d, ok := topology["This Machine"].display[child]; ok {
			displayName = d
		}
		if network.IsLocalIP(child) {
			localChildren = append(localChildren, childInfo{displayName, count})
		} else {
			externalChildren = append(externalChildren, childInfo{displayName, count})
		}
	}
	sort.Slice(localChildren, func(i, j int) bool { return localChildren[i].count > localChildren[j].count })
	sort.Slice(externalChildren, func(i, j int) bool { return externalChildren[i].count > externalChildren[j].count })

	renderBranch := func(name string, color string, items []childInfo) string {
		if len(items) == 0 {
			return ""
		}
		var sb strings.Builder
		header := lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Bold(true).Render(" [" + name + "]")
		sb.WriteString(header + "\n")
		grey := lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
		for i, item := range items {
			pref := " ├─ "
			if i == len(items)-1 {
				pref = " └─ "
			}
			countStr := grey.Render(fmt.Sprintf(" (%d pkts)", item.count))
			sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(pref) + item.name + countStr + "\n")
		}
		return sb.String()
	}

	lanBranch := renderBranch("LAN / Local", "39", localChildren)
	wanBranch := renderBranch("WAN / Internet", "205", externalChildren)

	branches := lipgloss.JoinHorizontal(lipgloss.Top, lanBranch, "    ", wanBranch)

	var mitmContent string
	mitmRoots := []string{}
	for k := range topology {
		if k != "This Machine" {
			mitmRoots = append(mitmRoots, k)
		}
	}
	sort.Strings(mitmRoots)

	if len(mitmRoots) > 0 {
		var msb strings.Builder
		msb.WriteString("\n" + lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("160")).Render(" Intercepted Peer-to-Peer Traffic ") + "\n")
		for _, root := range mitmRoots {
			children := []childInfo{}
			for c, count := range topology[root].children {
				children = append(children, childInfo{c, count})
			}
			sort.Slice(children, func(i, j int) bool {
				return children[i].count > children[j].count
			})
			msb.WriteString(renderBranch(root, m.getTheme().Accent, children))
		}
		mitmContent = msb.String()
	}

	mainMap := lipgloss.JoinVertical(lipgloss.Center,
		thisMachineBox,
		lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("       │"),
		lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("   ┌───┴───┐"),
		branches,
		mitmContent,
	)

	if len(topology["This Machine"].children) == 0 && len(mitmRoots) == 0 {
		mainMap = "\n    (No active connections discovered yet)\n"
	}

	help := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("\n[n/q/Esc] Return to Dashboard")
	return landingPageStyle.Copy().BorderForeground(lipgloss.Color(m.getTheme().Primary)).Width(m.Width - 4).Height(m.Height - 2).Render(
		lipgloss.JoinVertical(lipgloss.Center, title, "\n", mainMap, help),
	)
}

type CustomList struct {
	title         string
	items         []types.ProcItem
	selected      int
	Width, Height int
	PrimaryColor  string
}

func NewCustomList(title string) CustomList {
	return CustomList{
		title: title,
	}
}

func (cl CustomList) getPrimary() string {
	if cl.PrimaryColor == "" {
		return "62"
	}
	return cl.PrimaryColor
}

func (cl *CustomList) SetItems(items []types.ProcItem) {
	cl.items = items
	if cl.selected >= len(cl.items) {
		cl.selected = len(cl.items) - 1
	}
	if cl.selected < 0 && len(cl.items) > 0 {
		cl.selected = 0
	}
}

func (cl *CustomList) SelectedItem() *types.ProcItem {
	if len(cl.items) == 0 || cl.selected < 0 || cl.selected >= len(cl.items) {
		return nil
	}
	return &cl.items[cl.selected]
}

func (cl *CustomList) SetSize(width, height int) {
	cl.Width = width
	cl.Height = height
}

func (cl *CustomList) Update(msg tea.Msg) {
	if len(cl.items) == 0 {
		return
	}
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "up", "k":
			cl.selected--
			if cl.selected < 0 {
				cl.selected = 0
			}
		case "down", "j":
			cl.selected++
			if cl.selected >= len(cl.items) {
				cl.selected = len(cl.items) - 1
			}
		case "home":
			cl.selected = 0
		case "end", "G":
			cl.selected = len(cl.items) - 1
		}
	}
}

func (cl CustomList) View() string {
	var sb strings.Builder
	sb.WriteString(lipgloss.NewStyle().Bold(true).Render(cl.title) + "\n")
	sb.WriteString(strings.Repeat("-", cl.Width) + "\n")

	start := 0
	if cl.selected >= cl.Height-2 {
		start = cl.selected - (cl.Height - 3)
	}
	if start < 0 {
		start = 0
	}

	end := start + cl.Height - 2
	if end > len(cl.items) {
		end = len(cl.items)
	}

	for i := start; i < end; i++ {
		item := cl.items[i]
		line := fmt.Sprintf("%s (%d) [%d]", item.Name, item.PID, len(item.Packets))
		style := lipgloss.NewStyle().MaxWidth(cl.Width).MaxHeight(1)
		if item.IsMalicious {
			style = style.Foreground(lipgloss.Color("9"))
		}
		if i == cl.selected {
			style = style.Background(lipgloss.Color(cl.getPrimary())).Foreground(lipgloss.Color("230"))
		}
		sb.WriteString(style.Render(line) + "\n")
	}
	return sb.String()
}

type CustomViewport struct {
	content       string
	scrollOffset  int
	selected      int
	Width, Height int
}

func NewCustomViewport() CustomViewport {
	return CustomViewport{}
}

func (cv *CustomViewport) SetContent(content string) {
	cv.content = content
	cv.scrollOffset = 0
}

func (cv *CustomViewport) UpdateContent(content string) {
	cv.content = content
}

func (cv *CustomViewport) ScrollToEnd() {
	lines := strings.Split(cv.content, "\n")
	maxScroll := len(lines) - cv.Height
	if maxScroll < 0 {
		maxScroll = 0
	}
	cv.scrollOffset = maxScroll
}

func (cv *CustomViewport) SetSize(width, height int) {
	cv.Width = width
	cv.Height = height
}

func (cv *CustomViewport) Update(msg tea.Msg) {
	lines := strings.Split(cv.content, "\n")
	maxScroll := len(lines) - cv.Height
	if maxScroll < 0 {
		maxScroll = 0
	}

	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "pgup":
			cv.scrollOffset -= cv.Height / 2
			if cv.scrollOffset < 0 {
				cv.scrollOffset = 0
			}
		case "pgdown":
			cv.scrollOffset += cv.Height / 2
			if cv.scrollOffset > maxScroll {
				cv.scrollOffset = maxScroll
			}

			if cv.selected != cv.scrollOffset {
				cv.selected = cv.scrollOffset
			}

		case "up", "k", "home":
			cv.scrollOffset--
			if cv.scrollOffset < 0 {
				cv.scrollOffset = 0
			}
		case "down", "j", "end", "G":
			cv.scrollOffset++
			if cv.scrollOffset > maxScroll {
				cv.scrollOffset = maxScroll
			}
		}
	}
}

func (cv CustomViewport) View() string {
	lines := strings.Split(cv.content, "\n")
	if len(lines) == 0 {
		return ""
	}

	start := cv.scrollOffset
	end := start + cv.Height
	if end > len(lines) {
		end = len(lines)
	}

	var sb strings.Builder
	for i := start; i < end; i++ {
		if i < len(lines) {
			sb.WriteString(lipgloss.NewStyle().MaxWidth(cv.Width).MaxHeight(1).Render(lines[i]))
			sb.WriteString("\n")
		} else {
			sb.WriteString(strings.Repeat(" ", cv.Width) + "\n")
		}
	}
	return sb.String()
}

package ui

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"runtime"
	"github.com/shirou/gopsutil/v3/process"
	"os/exec"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"ligmashark/internal/ai"
	"ligmashark/internal/types"
)

var (
	docStyle         = lipgloss.NewStyle().Margin(1, 2)
	filterPrompt     = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Render("Filter ISP: ")
	filterInputStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	landingPageStyle = lipgloss.NewStyle().Align(lipgloss.Center).Padding(2, 4).Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("62"))
	processSearchPrompt = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Render("Search Process: ")
	explStyle        = lipgloss.NewStyle().Align(lipgloss.Center).Width(60).MarginTop(1).MarginBottom(1)
)

type UpdateMsg struct{}

type AIResultMsg string
type OllamaStatusMsg string
type PauseCaptureMsg struct{}
type ResumeCaptureMsg struct{}
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
)

type Model struct {
	List        CustomList
	Viewport    CustomViewport
	Processes   map[int32]*types.ProcItem
	CapturePaused *bool
	CaptureStatus string
	ProcessFilterSetting ProcessFilter
	SelectedPid int32
	Mu          *sync.RWMutex
	Width       int
	Height      int
	Mode        Mode
	ActiveProtocolFilter string
	FilterInput string
	ActiveFilter string
	ProcessSearchInput string
	ActiveProcessSearch string
	SystemInfo  types.SystemInfo
	VisiblePackets []types.PacketData
	InspectedPacket types.PacketData
	PacketDetailViewport CustomViewport
	HelpViewport CustomViewport
	OllamaStatus string
	ExportStatus string
	CursorVisible bool
	History      []types.BandwidthPoint
	LastTotalIn  uint64
	LastTotalOut uint64
	AutoScroll   bool
	GraphScrollOffset int
}

func NewModel(processes map[int32]*types.ProcItem, mu *sync.RWMutex, sysInfo types.SystemInfo) Model {
	return Model{
		List:      NewCustomList("Processes"),
		Viewport:  NewCustomViewport(),
		SystemInfo: sysInfo,
		Processes: processes,
		CapturePaused: new(bool),
		Mu:        mu,
		PacketDetailViewport: NewCustomViewport(),
		HelpViewport: NewCustomViewport(),
		ProcessFilterSetting: FilterEverything,
		CaptureStatus: "Running",
		OllamaStatus: "Initializing Ollama...",
		ActiveProtocolFilter: "ALL",
		Mode:      LandingPageMode,
		AutoScroll: true,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return UpdateMsg{}
	})
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
				m.Mode = NormalMode
			}
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
				case "ALL": m.ActiveProtocolFilter = "TCP"
				case "TCP": m.ActiveProtocolFilter = "UDP"
				case "UDP": m.ActiveProtocolFilter = "ICMP"
				default:    m.ActiveProtocolFilter = "ALL"
				}
				m.updateViewport()
			case "a":
				m.AutoScroll = !m.AutoScroll
			case "c":
				m.Mu.Lock()
				if p, ok := m.Processes[m.SelectedPid]; ok {
					p.Packets = nil
					p.BytesIn = 0
					p.BytesOut = 0
				}
				m.Mu.Unlock()
				m.updateViewport()

			case "h", "q":
				m.Mode = LandingPageMode
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

			if msg.Type == tea.MouseLeft {
				if msg.Y >= m.Height-1 {
					return m, m.toggleCaptureCmd()
				}
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
		return m, tea.Tick(time.Second, func(t time.Time) tea.Msg {
			return UpdateMsg{}
		})
	}
	return m, nil
}

func (m *Model) analyzePacketCmd(pkt types.PacketData) tea.Cmd {
	return func() tea.Msg {
		analysis, err := ai.AnalyzePayload(pkt)
		if err != nil {
			return AIResultMsg("AI Analysis failed: " + err.Error())
		}
		return AIResultMsg(analysis)
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
			sb.WriteString(pkt.AIAnalysis + "\n\n")
		} else {
			sb.WriteString("Analysis not completed at time of export.\n\n")
		}
		
		sb.WriteString("RAW PAYLOAD\n")
		sb.WriteString("-----------\n")
		sb.WriteString(pkt.Payload + "\n")

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

	modelName := "qwen2.5:0.5b"
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

	if lastStatus == fmt.Sprintf("Model '%s' is installed.", modelName) || lastStatus == fmt.Sprintf("Model '%s' pulled successfully.", modelName) {
		status("Ollama ready for AI analysis.")
	} else {
		status("Ollama setup failed: " + lastStatus)
	}
}

func (m *Model) refreshList() {
	m.Mu.RLock()
	items := make([]types.ProcItem, 0, len(m.Processes))
	for _, p := range m.Processes {
		items = append(items, *p)
	}
	m.Mu.RUnlock()

	sort.Slice(items, func(i, j int) bool {
		if len(items[i].Packets) != len(items[j].Packets) {
			return len(items[i].Packets) > len(items[j].Packets)
		}
		return items[i].PID < items[j].PID
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
				style = style.Foreground(lipgloss.Color("9")) // Red
			}
			buf.WriteString(style.Render(line) + "\n")
		}
		m.Viewport.SetContent(buf.String())
		if m.AutoScroll {
			m.Viewport.ScrollToEnd()
		}
	}
}

func (m Model) View() string {
	if m.Mode == LandingPageMode {
		return m.renderLandingPage()
	}
	if m.Mode == PacketDetailMode {
		return m.PacketDetailViewport.View()
	}
	if m.Mode == HelpMode {
		m.HelpViewport.SetContent(m.renderHelpMenuContent())
		return m.HelpViewport.View()
	}
	if m.Mode == GraphMode {
		return m.renderGraphMode()
	}

	listRender := m.List.View()
	viewportRender := m.Viewport.View()

	var bottomBar string
	if m.Mode == FilterMode {
		cursor := " "
		if m.CursorVisible {
			cursor = "█"
		}
		bottomBar = lipgloss.JoinHorizontal(lipgloss.Left,
			filterPrompt,
			filterInputStyle.Render(m.FilterInput+cursor),
		)
	} else if m.Mode == ProcessSearchMode {
		cursor := " "
		if m.CursorVisible {
			cursor = "█"
		}
		bottomBar = lipgloss.JoinHorizontal(lipgloss.Left,
			processSearchPrompt,
			filterInputStyle.Render(m.ProcessSearchInput+cursor),
		)
	}

	autoScrollStatus := "ON"
	if !m.AutoScroll {
		autoScrollStatus = "OFF"
	}

	captureBar := lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true).Render(" [P] " + m.CaptureStatus + " [A] Auto-scroll: " + autoScrollStatus + " ")
	activeFilterBar := ""
	if m.ActiveFilter != "" {
		activeFilterBar = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(" Active Filter: ") +
			lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Render(m.ActiveFilter)
	}
	activeProcessSearchBar := ""
	if m.ActiveProcessSearch != "" {
		activeProcessSearchBar = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(" Process Search: ") +
			lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Render(m.ActiveProcessSearch)
	}

	processFilterBar := lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true).Render(fmt.Sprintf(" [S] Filter: %s ", m.ProcessFilterSetting.String()))
	protoFilterBar := lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true).Render(fmt.Sprintf(" [F] Proto: %s ", m.ActiveProtocolFilter))

	footer := lipgloss.JoinHorizontal(lipgloss.Left, captureBar, processFilterBar, protoFilterBar, activeFilterBar, activeProcessSearchBar)
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

func (m Model) IsCapturePaused() bool {
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

func (m Model) getPacketDetailContent() string {
	width := m.PacketDetailViewport.Width
	style := lipgloss.NewStyle().Width(width)
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62")).Render("Packet Overview")
	
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
		exportStatus = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true).Render("\n" + m.ExportStatus)
	}

	help := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("\n[E] Export Report • [Esc/q] Back")
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
	case FilterEverything: return "Everything"
	case FilterForeground: return "Only Foreground apps"
	case FilterBackground: return "Only Background Apps"
	}
	return "Unknown"
}

func (m *Model) cycleProcessFilter() {
	m.ProcessFilterSetting = (m.ProcessFilterSetting + 1) % 3
	m.refreshList()
}

func (m Model) shouldShowProcess(p *types.ProcItem) bool {
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

func (m Model) renderGraphMode() string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62")).Render("Network Traffic (Bytes/sec)")
	
	var maxIn, maxOut uint64
	for _, p := range m.History {
		if p.In > maxIn { maxIn = p.In }
		if p.Out > maxOut { maxOut = p.Out }
	}

	graphHeight := (m.Height - 16) / 2
	if graphHeight < 2 { graphHeight = 2 }

	renderChart := func(label string, color string, maxValue uint64, getVal func(types.BandwidthPoint) uint64) string {
		var sb strings.Builder
		sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Bold(true).Render(label) + "\n")
		
		chartWidth := m.Width - 20
		if chartWidth < 10 { chartWidth = 10 }
		
		endIdx := len(m.History) - m.GraphScrollOffset
		startIdx := endIdx - chartWidth
		if startIdx < 0 { startIdx = 0 }
		if endIdx < 0 { endIdx = 0 }
		if endIdx > len(m.History) { endIdx = len(m.History) }

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

	// Calculate Top Talkers
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
		if len(stats) < limit { limit = len(stats) }
		var lines []string
		for i := 0; i < limit; i++ {
			lines = append(lines, fmt.Sprintf("%s (%d): %s", stats[i].name, stats[i].pid, formatBytes(stats[i].total)))
		}
		topTalkersStr = "\n" + lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205")).Render("Top Talkers (Session): ") + strings.Join(lines, "  │  ")
	}

	scrollInfo := ""
	if m.GraphScrollOffset > 0 {
		scrollInfo = fmt.Sprintf(" [Scrolling: %d points back]", m.GraphScrollOffset)
	}

	help := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("\nArrows (Left/Right): Scroll History • Press 'g' or 'Esc' to return." + scrollInfo)
	
	return landingPageStyle.Width(m.Width - 4).Height(m.Height - 2).Render(
		lipgloss.JoinVertical(lipgloss.Center, title, "\n", inChart, "\n", outChart, topTalkersStr, help),
	)
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit { return fmt.Sprintf("%d B", b) }
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit { div *= unit; exp++ }
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func (m Model) renderLandingPage() string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62")).SetString("Ligmashark")
	author := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).SetString("Created by val (@mayshecry) on GitHub")

	platformWarn := ""
	if runtime.GOOS == "windows" {
		platformWarn = "\n\n⚠️  Note: You are on Windows. For the full experience (including plugin support and native elevation), Linux is highly recommended."
	}

	explanation := explStyle.Render(
			"Ligmashark is a powerful, terminal-based network analyzer."  +
			"It maps real-time network traffic to local processes (PIDs), " +
			"identifies destination ISPs, and provides a Neovim-inspired TUI " +
			"for deep packet inspection and payload analysis." + platformWarn)

	specs := lipgloss.NewStyle().Padding(1, 2).SetString(fmt.Sprintf(`
OS: %s
Hostname: %s
CPU: %s
Memory: %s
Uptime: %s
Go Version: %s
`, m.SystemInfo.OS, m.SystemInfo.Hostname, m.SystemInfo.CPU, m.SystemInfo.Memory, m.SystemInfo.Uptime, m.SystemInfo.GoVersion))
	
	ollamaStatus := lipgloss.NewStyle().Foreground(lipgloss.Color("205")).SetString(m.OllamaStatus)

	help := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).SetString("\nPress 'q', 'h', or 'Enter' to start monitoring.")

	content := lipgloss.JoinVertical(lipgloss.Center,
		title.Render(),
		author.Render(),
		explanation,
		ollamaStatus.Render(),
		specs.Render(),
		help.Render(),
	)

	return landingPageStyle.Width(m.Width - 4).Height(m.Height - 2).Render(content)
}

func (m Model) renderHelpMenuContent() string {
	width := m.HelpViewport.Width
	style := lipgloss.NewStyle().Width(width)
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62")).Render("Ligmashark Hotkeys")
	
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
  c                : Clear history for selected process
  e                : Export Packet Report (in Detail view)
  ;                : Search/Filter process by name
  g                : Toggle Graph Mode
`
	return lipgloss.JoinVertical(lipgloss.Left, title, style.Render(helpText), "\nPress 'Esc' or 'q' to return.")
}

type CustomList struct {
	title        string
	items        []types.ProcItem
	selected     int
	Width, Height int
}

func NewCustomList(title string) CustomList {
	return CustomList{
		title: title,
	}
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
		case "down", "j", "end", "G":
			cl.selected++
			if cl.selected >= len(cl.items) {
				cl.selected = len(cl.items) - 1
			}
		case "home":
			cl.selected = 0
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
			style = style.Background(lipgloss.Color("62")).Foreground(lipgloss.Color("230"))
		}
		sb.WriteString(style.Render(line) + "\n")
	}
	return sb.String()
}

type CustomViewport struct {
	content    string
	scrollOffset int
	selected int
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
			sb.WriteString(lipgloss.NewStyle().MaxWidth(cv.Width).MaxHeight(1).Render(lines[i]) + "\n")
		} else {
			sb.WriteString(strings.Repeat(" ", cv.Width) + "\n")
		}
	}
	return sb.String()
}

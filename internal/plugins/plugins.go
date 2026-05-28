package plugins

import (
	"encoding/gob"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"plugin"
	"runtime"
	"strconv"
	"strings"
	"time"

	"ligmashark/internal/network"
	"ligmashark/internal/types"
)

type instruction struct {
	Op      string
	Value   string
	Message string
	Body    []instruction
}

type CompiledScript struct {
	Main      []instruction
	Functions map[string][]instruction
	Imports   []string
}
type ScriptPlugin struct {
	Filename     string
	Instructions []instruction
	Functions    map[string][]instruction
	imports      map[string]bool
	headers      map[string]string
	ispCache     map[string]string
	vars         map[string]string
	timerStart   time.Time
}

func (s *ScriptPlugin) Name() string {
	return "SharkScript: " + filepath.Base(s.Filename)
}

func (s *ScriptPlugin) OnPacket(pkt *types.PacketData) {
	if s.vars == nil {
		s.vars = make(map[string]string)
	}
	if s.imports == nil {
		s.imports = make(map[string]bool)
	}
	if s.headers == nil {
		s.headers = make(map[string]string)
	}
	if s.ispCache == nil {
		s.ispCache = make(map[string]string)
	}

	s.vars["SRC_IP"] = pkt.SrcIP
	s.vars["DST_IP"] = pkt.DstIP
	s.vars["PROTO"] = pkt.Protocol
	s.vars["PROCESS"] = pkt.ProcessName
	s.vars["PID"] = fmt.Sprintf("%d", pkt.PID)

	_ = s.execute(s.Instructions, pkt)
}

func (s *ScriptPlugin) execute(insts []instruction, pkt *types.PacketData) bool {
	lastIfMet := false
	for _, ins := range insts {
		op := ins.Op // Already uppercased by compiler
		if op == "WHILE" {
			for s.evalLogic(ins.Value, pkt) {
				if s.execute(ins.Body, pkt) {
					break
				}
			}
			continue
		}

		msg := s.expandVars(ins.Message)
		val := s.expandVars(ins.Value)

		switch op {
		case "USE":
			s.imports[val] = true
		case "TIMER_START":
			s.timerStart = time.Now()
		case "TIMER_END":
			s.vars[ins.Value] = fmt.Sprintf("%.4f", time.Since(s.timerStart).Seconds())
		case "SET":
			s.vars[ins.Value] = msg
		case "SET_EXPR":
			s.vars[ins.Value] = s.evalMath(msg)
		case "SET_HEADER":
			s.headers[val] = msg
		case "GET_HEADER":
			s.vars[msg] = pkt.HTTPHeaders[val]
		case "GET_ISP":
			s.vars[msg] = network.GetISP(val, s.ispCache)
		case "TIME":
			s.vars[val] = strconv.FormatInt(time.Now().UnixMilli(), 10)
		case "BREAK":
			return true
		case "INCREMENT":
			curr := s.vars[val]
			if curr == "" {
				curr = "0"
			}
			iv, _ := strconv.Atoi(curr)
			s.vars[val] = strconv.Itoa(iv + 1)
		case "LOOP":
			count, _ := strconv.Atoi(s.expandVars(ins.Value))
			for i := 0; i < count; i++ {
				if s.execute(ins.Body, pkt) {
					break
				}
			}
		case "BASED":
			fmt.Printf("[%s] 🗿 BASED: %s\n", s.Name(), msg)
		case "SLOP":
			fmt.Printf("[%s] 🤮 SLOP DETECTED: %s\n", s.Name(), msg)
		case "TELEMETRY_DETECTED":
			fmt.Printf("[%s] 📡 TELEMETRY DETECTED: %s\n", s.Name(), msg)
		case "HATE":
			fmt.Printf("[%s] 💢 HATE: %s\n", s.Name(), strings.ToUpper(msg))
		case "REJECT_MICROSOFT":
			if strings.Contains(strings.ToLower(pkt.ISP), "microsoft") {
				s.killProcess(pkt)
				fmt.Printf("[%s] 🚫 REJECTED MICROSOFT CONNECTION (PID: %d)\n", s.Name(), pkt.PID)
			}
		case "BashKILL_PID":
			if pkt.PID > 0 {
				exec.Command("kill", "-9", fmt.Sprintf("%d", pkt.PID)).Run()
				fmt.Printf("[%s] 💀 BashKILL: Sent SIGKILL to PID %d\n", s.Name(), pkt.PID)
			}
		case "NUKE_CONNECTION":
			s.killProcess(pkt)
			fmt.Printf("[%s] ☢️  NUKED connection from %s\n", s.Name(), pkt.ProcessName)
		case "DROP_ALL_PACKETS":
			// Mark for the session that we are "dropping" traffic (simulation)
			fmt.Printf("[%s] 🚮 DROPPING packet from %s (Internal State Only)\n", s.Name(), pkt.SrcIP)
		case "REDIRECT":
			if v, err := strconv.Atoi(val); err == nil {
				pkt.DstPort = strconv.Itoa(v)
				fmt.Printf("[%s] 🔄 REDIRECTED to port %s\n", s.Name(), val)
			}
		case "SPOOF":
			pkt.SrcIP = val
			fmt.Printf("[%s] 🎭 SPOOFED Source IP to %s\n", s.Name(), val)
		case "ALERT":
			alertStyle := "\033[1;31m" // Bold Red
			reset := "\033[0m"
			fmt.Printf("[%s] %s🚨 ALERT: %s%s\n", s.Name(), alertStyle, msg, reset)
		case "EXEC":
			var cmd *exec.Cmd
			if runtime.GOOS == "windows" {
				cmd = exec.Command("cmd", "/C", msg)
			} else {
				cmd = exec.Command("sh", "-c", msg)
			}
			go cmd.Run()
			fmt.Printf("[%s] 🚀 EXEC: %s\n", s.Name(), msg)
		case "INPUT":
			fmt.Printf("[%s] %s", s.Name(), msg)
			var inputVal string
			fmt.Scanln(&inputVal)
			s.vars[ins.Value] = strings.TrimSpace(inputVal)
		case "POST":
			parts := strings.SplitN(msg, " ", 2)
			if len(parts) == 2 {
				url, body := parts[0], parts[1]
				go func(u, b string, h map[string]string) {
					req, err := http.NewRequest("POST", u, strings.NewReader(b))
					if err != nil || req == nil {
						return
					}
					headers := make(map[string]string)
					for k, v := range h {
						headers[k] = v
					}
					req.Header.Set("Content-Type", "application/json")
					for k, v := range h {
						req.Header.Set(k, v)
					}
					resp, err := http.DefaultClient.Do(req)
					if err == nil {
						resp.Body.Close()
					}
				}(url, body, s.headers)
			}
		case "IF_COMPLEX", "IF_COMPLEX_PRINT", "IF_COMPLEX_CALL", "IF_COMPLEX_BLOCK", "IF_COMPLEX_EXEC", "IF_COMPLEX_POST", "IF_COMPLEX_BREAK":
			if s.evalLogic(val, pkt) {
				lastIfMet = true
				if s.handleAction(ins.Op, ins.Message, ins.Value, pkt) {
					return true
				}
			} else {
				lastIfMet = false
			}
		case "SLEEP":
			if ms, err := strconv.Atoi(val); err == nil {
				time.Sleep(time.Duration(ms) * time.Millisecond)
			}
		case "CALL":
			if f, ok := s.Functions[val]; ok {
				if s.execute(f, pkt) {
					return true
				}
			}
		case "PRINT":
			fmt.Printf("[%s] %s\n", s.Name(), msg)
		case "LOG":
			s.logToFile(msg)
		case "FETCH":
			go http.Get(val)
		case "IF_MALICIOUS":
			if pkt.IsMalicious {
				lastIfMet = true
				fmt.Printf("[%s] ALERT: %s (Target: %s)\n", s.Name(), msg, pkt.DstIP)
			} else {
				lastIfMet = false
			}
		case "IF_PROTO":
			if strings.EqualFold(pkt.Protocol, val) {
				lastIfMet = true
				fmt.Printf("[%s] %s\n", s.Name(), msg)
			} else {
				lastIfMet = false
			}
		case "IF_EXT":
			if s.evalExtCondition(val, pkt) {
				lastIfMet = true
				fmt.Printf("[%s] %s\n", s.Name(), msg)
			} else {
				lastIfMet = false
			}
		case "IF_EXT_CALL":
			if s.evalExtCondition(val, pkt) {
				lastIfMet = true
				if f, ok := s.Functions[ins.Message]; ok {
					if s.execute(f, pkt) {
						return true
					}
				}
			} else {
				lastIfMet = false
			}
		case "IF_MALICIOUS_CALL":
			if pkt.IsMalicious {
				lastIfMet = true
				if f, ok := s.Functions[val]; ok {
					if s.execute(f, pkt) {
						return true
					}
				}
			} else {
				lastIfMet = false
			}
		case "ELSE":
			if !lastIfMet {
				if s.handleElseAction(ins, pkt) {
					return true
				}
			}
		case "BLOCK":
			s.killProcess(pkt)
		case "IF_MALICIOUS_BLOCK":
			if pkt.IsMalicious {
				lastIfMet = true
				s.killProcess(pkt)
			} else {
				lastIfMet = false
			}
		}
	}
	return false
}

func (s *ScriptPlugin) handleAction(op, message, value string, pkt *types.PacketData) bool {
	msg := s.expandVars(message)
	if strings.HasPrefix(op, "IF_COMPLEX_") {
		action := strings.TrimPrefix(op, "IF_COMPLEX_")
		switch action {
		case "BREAK":
			return true
		case "PRINT":
			fmt.Printf("[%s] %s\n", s.Name(), msg)
		case "CALL":
			if f, ok := s.Functions[message]; ok {
				return s.execute(f, pkt)
			}
		case "BLOCK":
			s.killProcess(pkt)
		case "EXEC":
			var cmd *exec.Cmd
			if runtime.GOOS == "windows" {
				cmd = exec.Command("cmd", "/C", msg)
			} else {
				cmd = exec.Command("sh", "-c", msg)
			}
			go cmd.Run()
			fmt.Printf("[%s] 🚀 EXEC: %s\n", s.Name(), msg)
		case "POST":
			parts := strings.SplitN(msg, " ", 2)
			if len(parts) == 2 {
				url, body := parts[0], parts[1]
				go func(u, b string, h map[string]string) {
					req, err := http.NewRequest("POST", u, strings.NewReader(b))
					if err != nil || req == nil {
						return
					}
					req.Header.Set("Content-Type", "application/json")
					for k, v := range h {
						req.Header.Set(k, v)
					}
					resp, err := http.DefaultClient.Do(req)
					if err == nil {
						resp.Body.Close()
					}
				}(url, body, s.headers)
			}
		}
	}
	return false
}

func (s *ScriptPlugin) evalLogic(expr string, pkt *types.PacketData) bool {
	expr = s.expandVars(expr)
	orParts := strings.Split(expr, " OR ")
	if len(orParts) > 1 {
		for _, part := range orParts {
			if s.evalLogic(strings.TrimSpace(part), pkt) {
				return true
			}
		}
		return false
	}

	andParts := strings.Split(expr, " AND ")
	if len(andParts) > 1 {
		for _, part := range andParts {
			if !s.evalLogic(strings.TrimSpace(part), pkt) {
				return false
			}
		}
		return true
	}

	cond := strings.ToUpper(expr)
	if cond == "MALICIOUS" || expr == "malicious" {
		return pkt.IsMalicious
	}
	if strings.HasPrefix(cond, "PROTO ") {
		f := strings.Fields(expr)
		if len(f) > 1 {
			return strings.EqualFold(pkt.Protocol, f[1])
		}
	}
	if strings.HasPrefix(cond, "CONTAINS ") {
		searchStr := strings.Trim(expr[9:], "\" ")
		return strings.Contains(pkt.Payload, searchStr)
	}

	// Numeric comparisons for counting
	if strings.Contains(expr, " < ") {
		parts := strings.Split(expr, " < ")
		left, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
		right, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
		return left < right
	}
	if strings.Contains(expr, " > ") {
		parts := strings.Split(expr, " > ")
		left, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
		right, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
		return left > right
	}

	if strings.Contains(expr, ".") {
		return s.evalExtCondition(expr, pkt)
	}

	return false
}

func (s *ScriptPlugin) handleElseAction(ins instruction, pkt *types.PacketData) bool {
	msg := s.expandVars(ins.Message)
	val := s.expandVars(ins.Value)
	switch strings.ToUpper(ins.Op) {
	case "ELSE_PRINT":
		fmt.Printf("[%s] %s\n", s.Name(), msg)
	case "ELSE_CALL":
		if f, ok := s.Functions[val]; ok {
			return s.execute(f, pkt)
		}
	case "ELSE_BLOCK":
		s.killProcess(pkt)
	case "ELSE_POST":
		parts := strings.SplitN(msg, " ", 2)
		if len(parts) == 2 {
			url, body := parts[0], parts[1]
			go func(u, b string, h map[string]string) {
				req, err := http.NewRequest("POST", u, strings.NewReader(b))
				if err != nil || req == nil {
					return
				}
				req.Header.Set("Content-Type", "application/json")
				for k, v := range h {
					req.Header.Set(k, v)
				}
				resp, err := http.DefaultClient.Do(req)
				if err == nil {
					resp.Body.Close()
				}
			}(url, body, s.headers)
		}
	}
	return false
}

func (s *ScriptPlugin) evalExtCondition(cond string, pkt *types.PacketData) bool {
	cond = s.expandVars(cond)
	parts := strings.Split(cond, ".")
	if len(parts) != 2 {
		return false
	}
	pkg := parts[0]
	funcCall := parts[1]

	if !s.imports["ligmashark/"+pkg] {
		return false
	}

	fParts := strings.Split(strings.TrimSuffix(funcCall, ")"), "(")
	if len(fParts) != 2 {
		return false
	}
	fName := fParts[0]
	arg := fParts[1]

	switch pkg {
	case "network":
		switch fName {
		case "IsLocalIP":
			return network.IsLocalIP(arg)
		case "IsHostIP":
			return network.IsHostIP(arg)
		}
	}
	return false
}

func (s *ScriptPlugin) killProcess(pkt *types.PacketData) {
	if pkt.PID <= 0 {
		return
	}
	p, err := os.FindProcess(int(pkt.PID))
	if err == nil {
		_ = p.Kill()
		fmt.Printf("[%s] !! BLOCKED !! Process %d (%s) terminated.\n", s.Name(), pkt.PID, pkt.ProcessName)
	}
}

func (s *ScriptPlugin) logToFile(msg string) {
	f, err := os.OpenFile("shark.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(fmt.Sprintf("[%s] %s\n", time.Now().Format("15:04:05"), msg))
}

func (s *ScriptPlugin) evalMath(expr string) string {
	expr = strings.ReplaceAll(expr, " ", "")
	operators := []string{"+", "-", "*", "/"}
	for _, op := range operators {
		if strings.Contains(expr, op) {
			parts := strings.Split(expr, op)
			if len(parts) != 2 {
				continue
			}
			left, _ := strconv.Atoi(parts[0])
			right, _ := strconv.Atoi(parts[1])
			var res int
			switch op {
			case "+":
				res = left + right
			case "-":
				res = left - right
			case "*":
				res = left * right
			case "/":
				if right != 0 {
					res = left / right
				}
			}
			return strconv.Itoa(res)
		}
	}
	return expr
}

func (s *ScriptPlugin) expandVars(input string) string {
	if !strings.Contains(input, "%") {
		return input
	}
	output := input
	for k, v := range s.vars {
		placeholder := "%" + k + "%"
		output = strings.ReplaceAll(output, placeholder, v)
	}
	return output
}

func LoadPlugins(dir string) ([]types.Plugin, error) {
	var loadedPlugins []types.Plugin

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return loadedPlugins, nil
	}

	scriptFiles, _ := filepath.Glob(filepath.Join(dir, "*.ligma"))
	for _, file := range scriptFiles {
		f, err := os.Open(file)
		if err != nil {
			continue
		}

		header := make([]byte, 7)
		f.Read(header)
		if string(header) != "LIGMA01" {
			f.Close()
			continue
		}

		var script CompiledScript
		if err := gob.NewDecoder(f).Decode(&script); err == nil {
			loadedPlugins = append(loadedPlugins, &ScriptPlugin{
				Filename:     file,
				Instructions: script.Main,
				Functions:    script.Functions,
				imports:      make(map[string]bool),
				vars:         make(map[string]string),
				headers:      make(map[string]string),
				ispCache:     make(map[string]string),
			})
			for _, imp := range script.Imports {
				loadedPlugins[len(loadedPlugins)-1].(*ScriptPlugin).imports[imp] = true
			}
			fmt.Printf("Loaded script plugin: %s\n", file)
		}
		f.Close()
	}

	if runtime.GOOS == "windows" {
		return loadedPlugins, nil
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.so"))
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		p, err := plugin.Open(file)
		if err != nil {
			fmt.Printf("Error loading plugin %s: %v\n", file, err)
			continue
		}

		symbol, err := p.Lookup("Plugin")
		if err != nil {
			fmt.Printf("Error looking up symbol 'Plugin' in %s: %v\n", file, err)
			continue
		}

		ptr, ok := symbol.(types.Plugin)
		if !ok {
			fmt.Printf("Symbol 'Plugin' in %s does not implement types.Plugin interface\n", file)
			continue
		}

		loadedPlugins = append(loadedPlugins, ptr)
		fmt.Printf("Loaded plugin: %s\n", ptr.Name())
	}

	return loadedPlugins, nil
}

func LoadPluginsFromFile(path string) ([]types.Plugin, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	header := make([]byte, 7)
	f.Read(header)
	if string(header) != "LIGMA01" {
		return nil, fmt.Errorf("invalid file format")
	}

	var script CompiledScript
	if err := gob.NewDecoder(f).Decode(&script); err != nil {
		return nil, err
	}

	p := &ScriptPlugin{
		Filename:     path,
		Instructions: script.Main,
		Functions:    script.Functions,
		imports:      make(map[string]bool),
		vars:         make(map[string]string),
		headers:      make(map[string]string),
		ispCache:     make(map[string]string),
	}

	for _, imp := range script.Imports {
		p.imports[imp] = true
	}
	return []types.Plugin{p}, nil
}

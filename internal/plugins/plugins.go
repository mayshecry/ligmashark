package plugins

import (
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"plugin"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"ligmashark/internal/network"
	"ligmashark/internal/types"
)

type OpCode uint8

const (
	OpNop OpCode = iota
	OpUse
	OpTimerStart
	OpTimerEnd
	OpSet
	OpSetExpr
	OpSetHeader
	OpGetHeader
	OpGetISP
	OpTime
	OpBreak
	OpIncrement
	OpLoop
	OpWhile
	OpBased
	OpSlop
	OpTelemetry
	OpHate
	OpRejectMS
	OpBashKill
	OpNuke
	OpDropAll
	OpRedirect
	OpSpoof
	OpAlert
	OpExec
	OpInput
	OpPost
	OpIfComplex
	OpSleep
	OpCall
	OpPrint
	OpLog
	OpFetch
	OpIfMalicious
	OpIfProto
	OpIfExt
	OpIfExtCall
	OpIfMaliciousCall
	OpElse
	OpBlock
	OpIfMaliciousBlock
	OpIfPrint
	OpIfCall
	OpIfBlock
	OpIfExec
	OpIfPost
	OpIfBreak
	OpParallelLoop
)

type LogicOp uint8

const (
	LogNop LogicOp = iota
	LogOr
	LogAnd
	LogLt
	LogGt
	LogEq
	LogContains
	LogProto
	LogMalicious
	LogExt
	LogVar
	LogConst
)

type LogicExpr struct {
	Op    LogicOp
	Left  *LogicExpr
	Right *LogicExpr
	Value string
	Int   int
}

type instruction struct {
	Op        OpCode
	Value     string
	Message   string
	Body      []instruction
	Condition *LogicExpr // Pre-compiled logic evaluation tree
	IntValue  int
	IsStatic  bool
}

type CompiledScript struct {
	Main      []instruction
	Functions map[string][]instruction
	Imports   []string
	Symbols   []string // Variable name mapping
}
type ScriptPlugin struct {
	Filename     string
	Instructions []instruction
	Functions    map[string][]instruction
	imports      map[string]bool
	headers      map[string]string
	vars         map[string]string
	timerStart   time.Time
	mu           sync.RWMutex
}

func (s *ScriptPlugin) Name() string {
	return "SharkScript: " + filepath.Base(s.Filename)
}

func (s *ScriptPlugin) OnPacket(pkt *types.PacketData) {
	s.mu.Lock()
	if s.vars == nil {
		s.vars = make(map[string]string)
	}
	if s.imports == nil {
		s.imports = make(map[string]bool)
	}
	if s.headers == nil {
		s.headers = make(map[string]string)
	}

	s.vars["SRC_IP"] = pkt.SrcIP
	s.vars["DST_IP"] = pkt.DstIP
	s.vars["PROTO"] = pkt.Protocol
	s.vars["PROCESS"] = pkt.ProcessName
	s.vars["PID"] = fmt.Sprintf("%d", pkt.PID)
	s.mu.Unlock()

	_ = s.execute(s.Instructions, pkt)
}

func (s *ScriptPlugin) execute(insts []instruction, pkt *types.PacketData) bool {
	lastIfMet := false
	for _, ins := range insts {
		if ins.Op == OpWhile {
			for s.evalLogic(ins.Condition, pkt) {
				if s.execute(ins.Body, pkt) {
					break
				}
			}
			continue
		}

		switch ins.Op {
		case OpUse:
			s.mu.Lock()
			s.imports[ins.Value] = true
			s.mu.Unlock()
		case OpTimerStart:
			s.mu.Lock()
			s.timerStart = time.Now()
			s.mu.Unlock()
		case OpTimerEnd:
			s.mu.RLock()
			duration := time.Since(s.timerStart).Seconds()
			s.mu.RUnlock()
			s.mu.Lock()
			s.vars[ins.Value] = strconv.FormatFloat(duration, 'f', 4, 64)
			s.mu.Unlock()
		case OpSet:
			val := s.expandVars(ins.Message)
			s.mu.Lock()
			s.vars[ins.Value] = val
			s.mu.Unlock()
		case OpSetExpr:
			val := s.evalMath(s.expandVars(ins.Message))
			s.mu.Lock()
			s.vars[ins.Value] = val
			s.mu.Unlock()
		case OpSetHeader:
			key, val := s.expandVars(ins.Value), s.expandVars(ins.Message)
			s.mu.Lock()
			s.headers[key] = val
			s.mu.Unlock()
		case OpGetHeader:
			key := s.expandVars(ins.Value)
			s.mu.Lock()
			s.vars[ins.Message] = pkt.HTTPHeaders[key]
			s.mu.Unlock()
		case OpGetISP:
			ip := s.expandVars(ins.Value)
			isp := network.GetISP(ip)
			s.mu.Lock()
			s.vars[ins.Message] = isp
			s.mu.Unlock()
		case OpTime:
			s.mu.Lock()
			s.vars[ins.Value] = strconv.FormatInt(time.Now().UnixMilli(), 10)
			s.mu.Unlock()
		case OpBreak:
			return true
		case OpIncrement:
			s.mu.Lock()
			curr, ok := s.vars[ins.Value]
			if !ok || curr == "" {
				curr = "0"
			}
			// Specialized Fast-path for integers
			iv, _ := strconv.Atoi(curr)
			s.vars[ins.Value] = strconv.Itoa(iv + 1)
			s.mu.Unlock()
		case OpLoop:
			count := ins.IntValue
			if !ins.IsStatic {
				count, _ = strconv.Atoi(s.expandVars(ins.Value))
			}
			for i := 0; i < count; i++ {
				if s.execute(ins.Body, pkt) {
					return true
				}
			}
		case OpParallelLoop:
			count := ins.IntValue
			if !ins.IsStatic {
				count, _ = strconv.Atoi(s.expandVars(ins.Value))
			}
			if count <= 0 {
				continue
			}
			numWorkers := runtime.GOMAXPROCS(0)
			if count < numWorkers {
				numWorkers = count
			}
			var wg sync.WaitGroup
			wg.Add(numWorkers)
			for w := 0; w < numWorkers; w++ {
				go func(workerID int) {
					defer wg.Done()
					start := (count * workerID) / numWorkers
					end := (count * (workerID + 1)) / numWorkers
					for i := start; i < end; i++ {
						s.execute(ins.Body, pkt)
					}
				}(w)
			}
			wg.Wait()
		case OpBased:
			fmt.Printf("[%s] 🗿 BASED: %s\n", s.Name(), s.expandVars(ins.Message))
		case OpSlop:
			fmt.Printf("[%s] 🤮 SLOP DETECTED: %s\n", s.Name(), s.expandVars(ins.Message))
		case OpTelemetry:
			fmt.Printf("[%s] 📡 TELEMETRY DETECTED: %s\n", s.Name(), s.expandVars(ins.Message))
		case OpHate:
			fmt.Printf("[%s] 💢 HATE: %s\n", s.Name(), strings.ToUpper(s.expandVars(ins.Message)))
		case OpRejectMS:
			if strings.Contains(strings.ToLower(pkt.ISP), "microsoft") {
				s.killProcess(pkt)
				fmt.Printf("[%s] 🚫 REJECTED MICROSOFT CONNECTION (PID: %d)\n", s.Name(), pkt.PID)
			}
		case OpBashKill:
			if pkt.PID > 0 {
				exec.Command("kill", "-9", fmt.Sprintf("%d", pkt.PID)).Run()
				fmt.Printf("[%s] 💀 BashKILL: Sent SIGKILL to PID %d\n", s.Name(), pkt.PID)
			}
		case OpNuke:
			s.killProcess(pkt)
			fmt.Printf("[%s] ☢️  NUKED connection from %s\n", s.Name(), pkt.ProcessName)
		case OpDropAll:
			fmt.Printf("[%s] 🚮 DROPPING packet from %s (Internal State Only)\n", s.Name(), pkt.SrcIP)
		case OpRedirect:
			expandedVal := s.expandVars(ins.Value)
			if v, err := strconv.Atoi(expandedVal); err == nil {
				pkt.DstPort = strconv.Itoa(v)
				fmt.Printf("[%s] 🔄 REDIRECTED to port %s\n", s.Name(), expandedVal)
			}
		case OpSpoof:
			expandedVal := s.expandVars(ins.Value)
			pkt.SrcIP = expandedVal
			fmt.Printf("[%s] 🎭 SPOOFED Source IP to %s\n", s.Name(), expandedVal)
		case OpAlert:
			alertStyle := "\033[1;31m" // Bold Red
			reset := "\033[0m"
			fmt.Printf("[%s] %s🚨 ALERT: %s%s\n", s.Name(), alertStyle, s.expandVars(ins.Message), reset)
		case OpExec:
			expandedMsg := s.expandVars(ins.Message)
			var cmd *exec.Cmd
			if runtime.GOOS == "windows" {
				cmd = exec.Command("cmd", "/C", expandedMsg)
			} else {
				cmd = exec.Command("sh", "-c", expandedMsg)
			}
			go cmd.Run()
			fmt.Printf("[%s] 🚀 EXEC: %s\n", s.Name(), expandedMsg)
		case OpInput:
			fmt.Printf("[%s] %s", s.Name(), s.expandVars(ins.Message))
			var inputVal string
			fmt.Scanln(&inputVal)
			s.mu.Lock()
			s.vars[ins.Value] = strings.TrimSpace(inputVal)
			s.mu.Unlock()
		case OpPost:
			parts := strings.SplitN(s.expandVars(ins.Message), " ", 2)
			if len(parts) == 2 {
				url, body := parts[0], parts[1]
				go func(u, b string, h map[string]string) {
					req, err := http.NewRequest("POST", u, strings.NewReader(b))
					if err != nil || req == nil {
						return
					}
					s.mu.RLock()
					for k, v := range h {
						req.Header.Set(k, v)
					}
					s.mu.RUnlock()
					req.Header.Set("Content-Type", "application/json")
					resp, err := http.DefaultClient.Do(req)
					if err == nil {
						resp.Body.Close()
					}
				}(url, body, s.headers)
			}
		case OpIfPrint:
			if s.evalLogic(ins.Condition, pkt) {
				lastIfMet = true
				fmt.Printf("[%s] %s\n", s.Name(), s.expandVars(ins.Message))
			} else {
				lastIfMet = false
			}
		case OpIfCall:
			if s.evalLogic(ins.Condition, pkt) {
				lastIfMet = true
				if f, ok := s.Functions[ins.Message]; ok {
					if s.execute(f, pkt) {
						return true
					}
				}
			} else {
				lastIfMet = false
			}
		case OpIfBlock:
			if s.evalLogic(ins.Condition, pkt) {
				lastIfMet = true
				s.killProcess(pkt)
			} else {
				lastIfMet = false
			}
		case OpIfExec:
			if s.evalLogic(ins.Condition, pkt) {
				lastIfMet = true
				expandedMsg := s.expandVars(ins.Message)
				var cmd *exec.Cmd
				if runtime.GOOS == "windows" {
					cmd = exec.Command("cmd", "/C", expandedMsg)
				} else {
					cmd = exec.Command("sh", "-c", expandedMsg)
				}
				go cmd.Run()
				fmt.Printf("[%s] 🚀 EXEC: %s\n", s.Name(), expandedMsg)
			} else {
				lastIfMet = false
			}
		case OpIfPost:
			if s.evalLogic(ins.Condition, pkt) {
				lastIfMet = true
				parts := strings.SplitN(s.expandVars(ins.Message), " ", 2)
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
			} else {
				lastIfMet = false
			}
		case OpIfBreak:
			if s.evalLogic(ins.Condition, pkt) {
				lastIfMet = true
				return true
			} else {
				lastIfMet = false
			}
		case OpSleep:
			if ms, err := strconv.Atoi(s.expandVars(ins.Value)); err == nil {
				time.Sleep(time.Duration(ms) * time.Millisecond)
			}
		case OpCall:
			if f, ok := s.Functions[ins.Value]; ok {
				if s.execute(f, pkt) {
					return true
				}
			}
		case OpPrint:
			fmt.Printf("[%s] %s\n", s.Name(), s.expandVars(ins.Message))
		case OpLog:
			s.logToFile(s.expandVars(ins.Message))
		case OpFetch:
			go http.Get(s.expandVars(ins.Value))
		case OpIfMalicious:
			if pkt.IsMalicious {
				lastIfMet = true
				fmt.Printf("[%s] ALERT: %s (Target: %s)\n", s.Name(), s.expandVars(ins.Message), pkt.DstIP)
			} else {
				lastIfMet = false
			}
		case OpIfProto:
			if strings.EqualFold(pkt.Protocol, s.expandVars(ins.Value)) {
				lastIfMet = true
				fmt.Printf("[%s] %s\n", s.Name(), s.expandVars(ins.Message))
			} else {
				lastIfMet = false
			}
		case OpIfExt:
			if s.evalExtCondition(ins.Value, pkt) {
				lastIfMet = true
				fmt.Printf("[%s] %s\n", s.Name(), s.expandVars(ins.Message))
			} else {
				lastIfMet = false
			}
		case OpIfExtCall:
			if s.evalExtCondition(ins.Value, pkt) {
				lastIfMet = true
				if f, ok := s.Functions[ins.Value]; ok {
					if s.execute(f, pkt) {
						return true
					}
				}
			} else {
				lastIfMet = false
			}
		case OpIfMaliciousCall:
			if pkt.IsMalicious {
				lastIfMet = true
				if f, ok := s.Functions[ins.Value]; ok {
					if s.execute(f, pkt) {
						return true
					}
				}
			} else {
				lastIfMet = false
			}
		case OpElse:
			if !lastIfMet {
				if s.handleElseAction(ins, pkt) {
					return true
				}
			}
		case OpBlock:
			s.killProcess(pkt)
		case OpIfMaliciousBlock:
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

func (s *ScriptPlugin) evalLogic(expr *LogicExpr, pkt *types.PacketData) bool {
	if expr == nil {
		return false
	}

	switch expr.Op {
	case LogOr:
		return s.evalLogic(expr.Left, pkt) || s.evalLogic(expr.Right, pkt)
	case LogAnd:
		return s.evalLogic(expr.Left, pkt) && s.evalLogic(expr.Right, pkt)
	case LogLt, LogGt, LogEq:
		leftVal, _ := strconv.Atoi(s.resolveOperand(expr.Left))
		rightVal, _ := strconv.Atoi(s.resolveOperand(expr.Right))
		if expr.Op == LogLt {
			return leftVal < rightVal
		}
		if expr.Op == LogGt {
			return leftVal > rightVal
		}
		return leftVal == rightVal
	case LogMalicious:
		return pkt.IsMalicious
	case LogProto:
		return strings.EqualFold(pkt.Protocol, s.resolveOperand(expr.Right))
	case LogContains:
		searchStr := strings.Trim(s.resolveOperand(expr.Right), "\" ")
		return strings.Contains(hex.Dump(pkt.Payload), searchStr)
	case LogExt:
		return s.evalExtCondition(expr.Value, pkt)
	}
	return false
}

func (s *ScriptPlugin) resolveOperand(expr *LogicExpr) string {
	if expr.Op == LogConst {
		return expr.Value
	}
	if expr.Op == LogVar {
		return s.expandVars("%" + expr.Value + "%")
	}
	return ""
}

func (s *ScriptPlugin) handleElseAction(ins instruction, pkt *types.PacketData) bool {
	msg := s.expandVars(ins.Message)
	switch ins.Value {
	case "ELSE_PRINT":
		fmt.Printf("[%s] %s\n", s.Name(), msg)
	case "ELSE_CALL":
		if f, ok := s.Functions[msg]; ok {
			return s.execute(f, pkt)
		}
	case "ELSE_BLOCK":
		s.killProcess(pkt)
	case "ELSE_POST":
		parts := strings.SplitN(msg, " ", 2)
		if len(parts) == 2 {
			url, body := parts[0], parts[1]
			go func(u, b string) {
				req, err := http.NewRequest("POST", u, strings.NewReader(b))
				if err != nil || req == nil {
					return
				}
				req.Header.Set("Content-Type", "application/json")
				s.mu.RLock()
				for k, v := range s.headers {
					req.Header.Set(k, v)
				}
				s.mu.RUnlock()
				resp, err := http.DefaultClient.Do(req)
				if err == nil {
					resp.Body.Close()
				}
			}(url, body)
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

	s.mu.RLock()
	defer s.mu.RUnlock()
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
	operators := []string{"+", "-", "*", "/"}
	for _, op := range operators {
		if strings.Contains(expr, op) {
			expr = strings.ReplaceAll(expr, " ", "")
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
	idx := strings.IndexByte(input, '%')
	if idx == -1 {
		return input
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	var sb strings.Builder
	sb.Grow(len(input) + 16)

	for {
		idx = strings.IndexByte(input, '%')
		if idx == -1 {
			sb.WriteString(input)
			break
		}
		sb.WriteString(input[:idx])
		input = input[idx+1:]

		end := strings.IndexByte(input, '%')
		if end == -1 {
			sb.WriteByte('%')
			sb.WriteString(input)
			break
		}

		key := input[:end]
		if val, ok := s.vars[key]; ok {
			sb.WriteString(val)
		} else {
			sb.WriteString("%" + key + "%")
		}
		input = input[end+1:]
	}
	return sb.String()
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
		if string(header) != "LIGMA02" {
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
	if string(header) != "LIGMA02" {
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
	}

	for _, imp := range script.Imports {
		p.imports[imp] = true
	}
	return []types.Plugin{p}, nil
}

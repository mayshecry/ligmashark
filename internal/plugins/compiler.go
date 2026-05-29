package plugins

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func Compile(srcPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	scanner := bufio.NewScanner(src)
	lineNum := 0

	functions := make(map[string][]instruction)
	imports := []string{}
	lastWasIf := false

	type control struct {
		op   string
		val  string
		name string
	}
	stack := [][]instruction{{}}
	var ctrlStack []control

	var compileLogic func(string) *LogicExpr
	compileLogic = func(expr string) *LogicExpr {
		expr = strings.TrimSpace(expr)
		if strings.Contains(expr, " OR ") {
			parts := strings.SplitN(expr, " OR ", 2)
			return &LogicExpr{Op: LogOr, Left: compileLogic(parts[0]), Right: compileLogic(parts[1])}
		}
		if strings.Contains(expr, " AND ") {
			parts := strings.SplitN(expr, " AND ", 2)
			return &LogicExpr{Op: LogAnd, Left: compileLogic(parts[0]), Right: compileLogic(parts[1])}
		}

		if strings.EqualFold(expr, "MALICIOUS") {
			return &LogicExpr{Op: LogMalicious}
		}

		operators := []struct {
			token string
			op    LogicOp
		}{
			{" < ", LogLt}, {" > ", LogGt}, {" == ", LogEq},
			{"PROTO ", LogProto}, {"CONTAINS ", LogContains},
		}

		for _, o := range operators {
			if idx := strings.Index(strings.ToUpper(expr), o.token); idx != -1 {
				left := strings.TrimSpace(expr[:idx])
				right := strings.TrimSpace(expr[idx+len(o.token):])
				parseLeaf := func(s string) *LogicExpr {
					s = strings.TrimSpace(s)
					if strings.HasPrefix(s, "%") && strings.HasSuffix(s, "%") {
						return &LogicExpr{Op: LogVar, Value: s[1 : len(s)-1]}
					}
					return &LogicExpr{Op: LogConst, Value: s}
				}
				return &LogicExpr{Op: o.op, Left: parseLeaf(left), Right: parseLeaf(right)}
			}
		}

		if strings.Contains(expr, ".") {
			return &LogicExpr{Op: LogExt, Value: expr}
		}
		return nil
	}

	prepare := func(ins *instruction) {
		if !strings.Contains(ins.Value, "%") && !strings.Contains(ins.Message, "%") {
			ins.IsStatic = true
			if v, err := strconv.Atoi(ins.Value); err == nil {
				ins.IntValue = v
			}
		}
		if ins.Op == OpWhile || (ins.Op >= OpIfPrint && ins.Op <= OpIfBreak) {
			ins.Condition = compileLogic(ins.Value)
		}
	}

	for scanner.Scan() {
		lineNum++
		rawLine := scanner.Text()
		if strings.Contains(rawLine, "OperatorAx") {
			return fmt.Errorf("Nah i'm not compiling this it contains harmless little larps")
		}
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 1 {
			continue
		}

		cmd := strings.ToUpper(parts[0])

		if cmd == "LOOP" {
			if len(parts) < 2 {
				return fmt.Errorf("line %d: LOOP requires a count", lineNum)
			}
			stack = append(stack, []instruction{})
			ctrlStack = append(ctrlStack, control{op: "LOOP", val: parts[1]})
			continue
		}

		if cmd == "PARALLEL" && len(parts) > 1 && strings.ToUpper(parts[1]) == "LOOP" {
			if len(parts) < 3 {
				return fmt.Errorf("line %d: PARALLEL LOOP requires a count", lineNum)
			}
			stack = append(stack, []instruction{})
			ctrlStack = append(ctrlStack, control{op: "PARALLEL_LOOP", val: parts[2]})
			continue
		}

		if cmd == "ENDLOOP" {
			if len(ctrlStack) == 0 || (ctrlStack[len(ctrlStack)-1].op != "LOOP" && ctrlStack[len(ctrlStack)-1].op != "PARALLEL_LOOP") {
				return fmt.Errorf("line %d: ENDLOOP without LOOP", lineNum)
			}
			body := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			ctrl := ctrlStack[len(ctrlStack)-1]
			ctrlStack = ctrlStack[:len(ctrlStack)-1]
			op := OpLoop
			if ctrl.op == "PARALLEL_LOOP" {
				op = OpParallelLoop
			}
			ins := instruction{Op: op, Value: ctrl.val, Body: body}
			prepare(&ins)
			stack[len(stack)-1] = append(stack[len(stack)-1], ins)
			continue
		}

		if cmd == "WHILE" {
			stack = append(stack, []instruction{})
			ctrlStack = append(ctrlStack, control{op: "WHILE", val: strings.Join(parts[1:], " ")})
			continue
		}

		if cmd == "ENDWHILE" {
			if len(ctrlStack) == 0 || ctrlStack[len(ctrlStack)-1].op != "WHILE" {
				return fmt.Errorf("line %d: ENDWHILE without WHILE", lineNum)
			}
			body := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			ctrl := ctrlStack[len(ctrlStack)-1]
			ctrlStack = ctrlStack[:len(ctrlStack)-1]
			stack[len(stack)-1] = append(stack[len(stack)-1], instruction{Op: OpWhile, Value: ctrl.val, Body: body})
			continue
		}

		if cmd == "FUNCTION" {
			if len(parts) < 2 {
				return fmt.Errorf("line %d: FUNCTION requires a name", lineNum)
			}
			stack = append(stack, []instruction{})
			ctrlStack = append(ctrlStack, control{op: "FUNCTION", name: parts[1]})
			continue
		}

		if cmd == "ENDFUNCTION" {
			if len(ctrlStack) == 0 || ctrlStack[len(ctrlStack)-1].op != "FUNCTION" {
				return fmt.Errorf("line %d: ENDFUNCTION without FUNCTION", lineNum)
			}
			body := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			ctrl := ctrlStack[len(ctrlStack)-1]
			ctrlStack = ctrlStack[:len(ctrlStack)-1]
			functions[ctrl.name] = body
			continue
		}

		var ins instruction
		currentIsIf := false
		switch cmd {
		case "USE":
			path := strings.TrimSuffix(parts[1], ";")
			imports = append(imports, path)
			ins.Op = OpUse
			ins.Value = path
		case "BREAK":
			ins.Op = OpBreak
		case "TIMER_START":
			ins.Op = OpTimerStart
		case "TIMER_END":
			if len(parts) < 2 {
				return fmt.Errorf("line %d: TIMER_END requires a variable to store result", lineNum)
			}
			ins.Op = OpTimerEnd
			ins.Value = parts[1]
		case "GET_ISP":
			if len(parts) < 3 {
				return fmt.Errorf("line %d: GET_ISP requires IP and variable", lineNum)
			}
			ins.Op, ins.Value, ins.Message = OpGetISP, parts[1], parts[2]
		case "SET_HEADER":
			if len(parts) < 3 {
				return fmt.Errorf("line %d: SET_HEADER requires key and value", lineNum)
			}
			ins.Op, ins.Value, ins.Message = OpSetHeader, parts[1], strings.Join(parts[2:], " ")
		case "GET_HEADER":
			if len(parts) < 3 {
				return fmt.Errorf("line %d: GET_HEADER requires key and variable", lineNum)
			}
			ins.Op, ins.Value, ins.Message = OpGetHeader, parts[1], parts[2]
		case "SET":
			if len(parts) < 3 {
				return fmt.Errorf("line %d: SET requires var and val", lineNum)
			}
			if parts[2] == "=" {
				ins.Op = OpSetExpr
				ins.Value = parts[1]
				ins.Message = strings.Join(parts[3:], " ")
			} else {
				ins.Op, ins.Value, ins.Message = OpSet, parts[1], strings.Join(parts[2:], " ")
			}
		case "TIME":
			if len(parts) < 2 {
				return fmt.Errorf("line %d: TIME requires a variable name", lineNum)
			}
			ins.Op, ins.Value = OpTime, parts[1]
		case "INCREMENT":
			if len(parts) < 2 {
				return fmt.Errorf("line %d: INCREMENT requires a variable", lineNum)
			}
			ins.Op, ins.Value = OpIncrement, parts[1]
		case "BLOCK":
			ins.Op = OpBlock
		case "BASED":
			ins.Op, ins.Message = OpBased, strings.Join(parts[1:], " ")
		case "SLOP":
			ins.Op, ins.Message = OpSlop, strings.Join(parts[1:], " ")
		case "TELEMETRY_DETECTED":
			ins.Op, ins.Message = OpTelemetry, strings.Join(parts[1:], " ")
		case "REJECT_MICROSOFT":
			ins.Op = OpRejectMS
		case "BashKILL_PID":
			ins.Op = OpBashKill
		case "DROP_ALL_PACKETS":
			ins.Op = OpDropAll
		case "NUKE_CONNECTION":
			ins.Op = OpNuke
		case "HATE":
			ins.Op, ins.Message = OpHate, strings.Join(parts[1:], " ")
		case "REDIRECT":
			if len(parts) < 3 {
				return fmt.Errorf("line %d: REDIRECT requires 'port [num]'", lineNum)
			}
			ins.Op, ins.Value = OpRedirect, parts[2]
		case "SPOOF":
			if len(parts) < 2 {
				return fmt.Errorf("line %d: SPOOF requires an IP", lineNum)
			}
			ins.Op, ins.Value = OpSpoof, parts[1]
		case "ALERT":
			ins.Op, ins.Message = OpAlert, strings.Join(parts[1:], " ")
		case "EXEC":
			if len(parts) < 2 {
				return fmt.Errorf("line %d: EXEC requires a command", lineNum)
			}
			ins.Op, ins.Message = OpExec, strings.Join(parts[1:], " ")
		case "INPUT":
			if len(parts) < 2 {
				return fmt.Errorf("line %d: INPUT requires a variable name", lineNum)
			}
			ins.Op = OpInput
			ins.Value = parts[1]
			ins.Message = strings.Join(parts[2:], " ")
		case "HTTP":
			if len(parts) < 3 {
				return fmt.Errorf("line %d: HTTP requires method (GET/POST) and URL", lineNum)
			}
			method := strings.ToUpper(parts[1])
			if method == "GET" {
				if len(parts) < 4 {
					return fmt.Errorf("line %d: HTTP GET requires URL and variable name", lineNum)
				}
				ins.Op, ins.Value, ins.Message = OpFetch, parts[2], parts[3]
			} else if method == "POST" {
				if len(parts) < 4 {
					return fmt.Errorf("line %d: HTTP POST requires URL and body", lineNum)
				}
				ins.Op = OpPost
				ins.Message = parts[2] + " " + strings.Join(parts[3:], " ")
			}
		case "PRINT":
			ins.Op, ins.Message = OpPrint, strings.Join(parts[1:], " ")
		case "SLEEP":
			if len(parts) < 2 {
				return fmt.Errorf("line %d: SLEEP requires ms", lineNum)
			}
			ins.Op, ins.Value = OpSleep, parts[1]
			prepare(&ins)
		case "CALL":
			if len(parts) < 2 {
				return fmt.Errorf("line %d: CALL requires a name", lineNum)
			}
			ins.Op, ins.Value = OpCall, parts[1]
		case "ELSE":
			if !lastWasIf {
				return fmt.Errorf("line %d: ELSE must follow an IF statement", lineNum)
			}
			if len(parts) < 2 {
				return fmt.Errorf("line %d: ELSE missing action", lineNum)
			}
			ins.Op = OpElse
			action := strings.ToUpper(parts[1])
			if action == "PRINT" {
				ins.Value = "ELSE_PRINT"
				ins.Message = strings.Join(parts[2:], " ")
			} else if action == "HTTP" && len(parts) > 3 && strings.ToUpper(parts[2]) == "POST" {
				ins.Value = "ELSE_POST"
				ins.Message = parts[3] + " " + strings.Join(parts[4:], " ")
			} else if action == "CALL" || action == "BLOCK" || action == "BREAK" {
				ins.Value = "ELSE_" + action
				if len(parts) > 2 {
					ins.Message = parts[2]
				}
			}
		case "LOG":
			ins.Op, ins.Message = OpLog, strings.Join(parts[1:], " ")
		case "FETCH":
			if len(parts) < 2 {
				return fmt.Errorf("line %d: FETCH requires a URL", lineNum)
			}
			ins.Op, ins.Value = OpFetch, parts[1]
		case "IF":
			if len(parts) < 3 {
				return fmt.Errorf("line %d: IF missing arguments", lineNum)
			}
			currentIsIf = true

			actionIdx := -1
			for i, p := range parts {
				u := strings.ToUpper(p)
				if u == "PRINT" || u == "CALL" || u == "BLOCK" || u == "EXEC" || u == "HTTP" || u == "BREAK" {
					actionIdx = i
					break
				}
			}
			if actionIdx == -1 {
				return fmt.Errorf("line %d: IF missing action (PRINT/CALL/BLOCK)", lineNum)
			}

			if strings.ToUpper(parts[actionIdx]) == "HTTP" {
				if actionIdx+1 >= len(parts) || strings.ToUpper(parts[actionIdx+1]) != "POST" {
					return fmt.Errorf("line %d: HTTP must be followed by POST", lineNum)
				}
				ins.Op = OpIfPost
				ins.Value = strings.Join(parts[1:actionIdx], " ")
				ins.Message = parts[actionIdx+2] + " " + strings.Join(parts[actionIdx+3:], " ")
			} else {
				action := strings.ToUpper(parts[actionIdx])
				switch action {
				case "PRINT":
					ins.Op = OpIfPrint
				case "CALL":
					ins.Op = OpIfCall
				case "BLOCK":
					ins.Op = OpIfBlock
				case "EXEC":
					ins.Op = OpIfExec
				case "POST":
					ins.Op = OpIfPost
				case "BREAK":
					ins.Op = OpIfBreak
				}
				ins.Value = strings.Join(parts[1:actionIdx], " ")
				ins.Message = strings.Join(parts[actionIdx+1:], " ")
			}
		default:
			return fmt.Errorf("line %d: unknown or unsupported command '%s'", lineNum, cmd)
		}

		lastWasIf = currentIsIf
		prepare(&ins)
		stack[len(stack)-1] = append(stack[len(stack)-1], ins)
	}

	if len(ctrlStack) > 0 {
		return fmt.Errorf("compilation error: unclosed %s block (started before end of file)", ctrlStack[len(ctrlStack)-1].op)
	}

	destPath := strings.TrimSuffix(srcPath, ".shark") + ".ligma"
	dest, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer dest.Close()

	dest.Write([]byte("LIGMA02"))

	script := CompiledScript{
		Main:      stack[0],
		Functions: functions,
		Imports:   imports,
	}

	encoder := gob.NewEncoder(dest)
	if err := encoder.Encode(script); err != nil {
		return err
	}

	return nil
}

package plugins

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"os"
	"strings"
)

// Compile parses a .shark file and writes a .ligma binary.
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
	ctrlStack := []control{}

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
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

		if cmd == "ENDLOOP" {
			if len(ctrlStack) == 0 || ctrlStack[len(ctrlStack)-1].op != "LOOP" {
				return fmt.Errorf("line %d: ENDLOOP without LOOP", lineNum)
			}
			body := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			ctrl := ctrlStack[len(ctrlStack)-1]
			ctrlStack = ctrlStack[:len(ctrlStack)-1]
			stack[len(stack)-1] = append(stack[len(stack)-1], instruction{Op: "LOOP", Value: ctrl.val, Body: body})
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
			stack[len(stack)-1] = append(stack[len(stack)-1], instruction{Op: "WHILE", Value: ctrl.val, Body: body})
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
			ins.Op, ins.Value = "USE", path
		case "GET_ISP":
			if len(parts) < 3 {
				return fmt.Errorf("line %d: GET_ISP requires IP and variable", lineNum)
			}
			ins.Op, ins.Value, ins.Message = "GET_ISP", parts[1], parts[2]
		case "SET_HEADER":
			if len(parts) < 3 {
				return fmt.Errorf("line %d: SET_HEADER requires key and value", lineNum)
			}
			ins.Op, ins.Value, ins.Message = "SET_HEADER", parts[1], strings.Join(parts[2:], " ")
		case "GET_HEADER":
			if len(parts) < 3 {
				return fmt.Errorf("line %d: GET_HEADER requires key and variable", lineNum)
			}
			ins.Op, ins.Value, ins.Message = "GET_HEADER", parts[1], parts[2]
		case "SET":
			if len(parts) < 3 {
				return fmt.Errorf("line %d: SET requires var and val", lineNum)
			}
			if parts[2] == "=" {
				ins.Op = "SET_EXPR"
				ins.Value = parts[1]
				ins.Message = strings.Join(parts[3:], " ")
			} else {
				ins.Op, ins.Value, ins.Message = "SET", parts[1], strings.Join(parts[2:], " ")
			}
		case "TIME":
			if len(parts) < 2 {
				return fmt.Errorf("line %d: TIME requires a variable name", lineNum)
			}
			ins.Op, ins.Value = "TIME", parts[1]
		case "INCREMENT":
			if len(parts) < 2 {
				return fmt.Errorf("line %d: INCREMENT requires a variable", lineNum)
			}
			ins.Op, ins.Value = "INCREMENT", parts[1]
		case "BLOCK":
			ins.Op = "BLOCK"
		case "BASED":
			ins.Op, ins.Message = "BASED", strings.Join(parts[1:], " ")
		case "SLOP":
			ins.Op, ins.Message = "SLOP", strings.Join(parts[1:], " ")
		case "TELEMETRY_DETECTED":
			ins.Op, ins.Message = "TELEMETRY_DETECTED", strings.Join(parts[1:], " ")
		case "REJECT_MICROSOFT":
			ins.Op = "REJECT_MICROSOFT"
		case "BashKILL_PID":
			ins.Op = "BashKILL_PID"
		case "DROP_ALL_PACKETS":
			ins.Op = "DROP_ALL_PACKETS"
		case "NUKE_CONNECTION":
			ins.Op = "NUKE_CONNECTION"
		case "HATE":
			ins.Op, ins.Message = "HATE", strings.Join(parts[1:], " ")
		case "REDIRECT":
			if len(parts) < 3 {
				return fmt.Errorf("line %d: REDIRECT requires 'port [num]'", lineNum)
			}
			ins.Op, ins.Value = "REDIRECT", parts[2]
		case "SPOOF":
			if len(parts) < 2 {
				return fmt.Errorf("line %d: SPOOF requires an IP", lineNum)
			}
			ins.Op, ins.Value = "SPOOF", parts[1]
		case "ALERT":
			ins.Op, ins.Message = "ALERT", strings.Join(parts[1:], " ")
		case "EXEC":
			if len(parts) < 2 {
				return fmt.Errorf("line %d: EXEC requires a command", lineNum)
			}
			ins.Op, ins.Message = "EXEC", strings.Join(parts[1:], " ")
		case "INPUT":
			if len(parts) < 2 {
				return fmt.Errorf("line %d: INPUT requires a variable name", lineNum)
			}
			ins.Op = "INPUT"
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
				ins.Op, ins.Value, ins.Message = "HTTP_GET", parts[2], parts[3]
			} else if method == "POST" {
				if len(parts) < 4 {
					return fmt.Errorf("line %d: HTTP POST requires URL and body", lineNum)
				}
				ins.Op, ins.Value = "HTTP_POST", parts[2]
				if len(parts) > 4 {
					ins.Message = strings.Join(parts[3:len(parts)-1], " ") + " | " + parts[len(parts)-1]
				} else {
					ins.Message = strings.Join(parts[3:], " ")
				}
			}
		case "PRINT":
			ins.Op, ins.Message = "PRINT", strings.Join(parts[1:], " ")
		case "SLEEP":
			if len(parts) < 2 {
				return fmt.Errorf("line %d: SLEEP requires ms", lineNum)
			}
			ins.Op, ins.Value = "SLEEP", parts[1]
		case "CALL":
			if len(parts) < 2 {
				return fmt.Errorf("line %d: CALL requires a name", lineNum)
			}
			ins.Op, ins.Value = "CALL", parts[1]
		case "ELSE":
			if !lastWasIf {
				return fmt.Errorf("line %d: ELSE must follow an IF statement", lineNum)
			}
			if len(parts) < 2 {
				return fmt.Errorf("line %d: ELSE missing action", lineNum)
			}
			action := strings.ToUpper(parts[1])
			ins.Op = "ELSE_" + action
			if action == "PRINT" {
				ins.Message = strings.Join(parts[2:], " ")
			} else if action == "HTTP" && len(parts) > 3 && strings.ToUpper(parts[2]) == "POST" {
				ins.Op = "ELSE_POST"
				ins.Message = parts[3] + " " + strings.Join(parts[4:], " ")
			} else if action == "CALL" || action == "BLOCK" || action == "BREAK" {
				if len(parts) > 2 {
					ins.Value = parts[2]
				}
			}
		case "LOG":
			ins.Op, ins.Message = "LOG", strings.Join(parts[1:], " ")
		case "FETCH":
			if len(parts) < 2 {
				return fmt.Errorf("line %d: FETCH requires a URL", lineNum)
			}
			ins.Op, ins.Value = "FETCH", parts[1]
		case "IF":
			if len(parts) < 3 {
				return fmt.Errorf("line %d: IF missing arguments", lineNum)
			}
			currentIsIf = true

			// New logic: Find action word (PRINT/CALL/BLOCK) to separate condition
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
				ins.Op = "IF_COMPLEX_POST"
				ins.Value = strings.Join(parts[1:actionIdx], " ")
				ins.Message = parts[actionIdx+2] + " " + strings.Join(parts[actionIdx+3:], " ")
			} else {
				ins.Op = "IF_COMPLEX_" + strings.ToUpper(parts[actionIdx])
				ins.Value = strings.Join(parts[1:actionIdx], " ")
				ins.Message = strings.Join(parts[actionIdx+1:], " ")
			}

		default:
			return fmt.Errorf("line %d: unknown command %s", lineNum, cmd)
		}

		lastWasIf = currentIsIf
		stack[len(stack)-1] = append(stack[len(stack)-1], ins)
	}

	if len(ctrlStack) > 0 {
		return fmt.Errorf("build error: unclosed block %s", ctrlStack[len(ctrlStack)-1].op)
	}

	destPath := strings.TrimSuffix(srcPath, ".shark") + ".ligma"
	dest, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer dest.Close()

	// Write magic header to make it "proprietary"
	dest.Write([]byte("LIGMA01"))

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

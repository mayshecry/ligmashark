package plugins

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Compile parses a .shark file and writes a .ligma binary.
func Compile(srcPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	var instructions []instruction
	scanner := bufio.NewScanner(src)
	lineNum := 0

	var loopBuffer []instruction
	inLoop := false
	loopCount := 0

	var funcBuffer []instruction
	inFunc := false
	currentFuncName := ""

	var whileBuffer []instruction
	inWhile := false
	whileCond := ""

	functions := make(map[string][]instruction)
	imports := []string{}
	lastWasIf := false

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
			if inLoop {
				return fmt.Errorf("line %d: nested loops are not yet supported", lineNum)
			}
			if len(parts) < 2 {
				return fmt.Errorf("line %d: LOOP requires a count", lineNum)
			}
			count, err := strconv.Atoi(parts[1])
			if err != nil {
				return fmt.Errorf("line %d: invalid loop count", lineNum)
			}
			loopCount, inLoop, loopBuffer = count, true, []instruction{}
			continue
		}

		if cmd == "ENDLOOP" {
			if !inLoop {
				return fmt.Errorf("line %d: ENDLOOP without LOOP", lineNum)
			}

			target := &instructions
			if inFunc {
				target = &funcBuffer
			}

			for i := 0; i < loopCount; i++ {
				*target = append(*target, loopBuffer...)
			}
			inLoop = false
			continue
		}

		if cmd == "WHILE" {
			if inWhile {
				return fmt.Errorf("line %d: nested while loops not supported", lineNum)
			}
			whileCond = strings.Join(parts[1:], " ")
			inWhile, whileBuffer = true, []instruction{}
			continue
		}

		if cmd == "ENDWHILE" {
			if !inWhile {
				return fmt.Errorf("line %d: ENDWHILE without WHILE", lineNum)
			}
			ins := instruction{Op: "WHILE", Value: whileCond, Body: whileBuffer}
			instructions = append(instructions, ins)
			inWhile = false
			continue
		}

		if cmd == "FUNCTION" {
			if len(parts) < 2 {
				return fmt.Errorf("line %d: FUNCTION requires a name", lineNum)
			}
			if inFunc {
				return fmt.Errorf("line %d: nested functions not supported", lineNum)
			}
			currentFuncName, inFunc, funcBuffer = parts[1], true, []instruction{}
			continue
		}

		if cmd == "ENDFUNCTION" {
			if !inFunc {
				return fmt.Errorf("line %d: ENDFUNCTION without FUNCTION", lineNum)
			}
			functions[currentFuncName] = funcBuffer
			inFunc = false
			continue
		}

		var ins instruction
		currentIsIf := false
		switch cmd {
		case "USE":
			if len(parts) < 2 {
				return fmt.Errorf("line %d: USE requires a path", lineNum)
			}
			path := strings.TrimSuffix(parts[1], ";")
			imports = append(imports, path)
			ins.Op, ins.Value = "USE", path
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
			if len(parts) < 4 || strings.ToUpper(parts[1]) != "POST" {
				return fmt.Errorf("line %d: HTTP requires POST, URL and Body", lineNum)
			}
			ins.Op = "POST"
			ins.Message = parts[2] + " " + strings.Join(parts[3:], " ")
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
			} else if action == "CALL" || action == "BLOCK" {
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
				if u == "PRINT" || u == "CALL" || u == "BLOCK" || u == "EXEC" || u == "HTTP" {
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

		if inFunc {
			funcBuffer = append(funcBuffer, ins)
		} else if inWhile {
			whileBuffer = append(whileBuffer, ins)
		} else if inLoop {
			loopBuffer = append(loopBuffer, ins)
		} else {
			instructions = append(instructions, ins)
		}
	}

	if inLoop {
		return fmt.Errorf("build error: unclosed LOOP block")
	}
	if inFunc {
		return fmt.Errorf("build error: unclosed FUNCTION block: %s", currentFuncName)
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
		Main:      instructions,
		Functions: functions,
		Imports:   imports,
	}

	encoder := gob.NewEncoder(dest)
	if err := encoder.Encode(script); err != nil {
		return err
	}

	return nil
}

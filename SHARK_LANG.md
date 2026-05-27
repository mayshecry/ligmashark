# 🦈 SharkScript Language Reference

SharkScript is a lightweight scripting language for Ligmashark plugins. Scripts are written in `.shark` files and compiled into `.ligma` bytecode.

---

# 🚀 Compilation

Compile a SharkScript source file:

```bash
./ligmashark --compile my_plugin.shark
```

This produces:

```text
my_plugin.ligma
```

Move the compiled file into the `plugins/` directory to load it automatically.

---

# 📄 General Syntax

- One instruction per line
- Lines beginning with `#` are comments
- Empty lines are ignored
- Commands are case-insensitive (`print`, `PRINT`, and `Print` work)

Example:

```shark
# comment

PRINT Hello world
```

---

# 💬 Comments

Use `#` to create comments.

```shark
# This line is ignored
PRINT Hello
```

---

# 📦 Imports

Import external SharkScript modules.

## Syntax

```shark
USE path/to/file.shark;
```

## Example

```shark
USE common/network.shark;
```

Semicolons are optional but supported.

---

# 🖨️ Output & Logging

## PRINT

Prints text to terminal output.

### Syntax

```shark
PRINT message
```

### Example

```shark
PRINT Ligmashark initialized
```

---

## LOG

Logs a message.

### Syntax

```shark
LOG message
```

### Example

```shark
LOG Packet detected
```

---

## ALERT

Triggers an alert message.

### Syntax

```shark
ALERT message
```

### Example

```shark
ALERT Suspicious traffic detected
```

---

# ⚙️ Variables

## SET

Assigns a value to a variable.

### Syntax

```shark
SET variable value
```

### Example

```shark
SET username sharkuser
SET port 8080
```

---

## SET Expression Mode

If the third token is `=`, SharkScript switches to expression mode.

### Syntax

```shark
SET variable = expression
```

### Example

```shark
SET counter = x + 1
```

Internally this becomes a `SET_EXPR`.

---

## INCREMENT

Increments a variable.

### Syntax

```shark
INCREMENT variable
```

### Example

```shark
INCREMENT packetCount
```

---

# 🔁 Control Flow

## LOOP

Repeats instructions a fixed number of times.

### Syntax

```shark
LOOP count
    commands
ENDLOOP
```

### Example

```shark
LOOP 5
PRINT Hello
ENDLOOP
```

Output:

```text
Hello
Hello
Hello
Hello
Hello
```

### Notes

- Nested loops are **not supported**
- Count must be an integer

Invalid:

```shark
LOOP 5
    LOOP 2
    PRINT hi
    ENDLOOP
ENDLOOP
```

---

## WHILE

Runs a conditional loop.

### Syntax

```shark
WHILE condition
    commands
ENDWHILE
```

### Example

```shark
WHILE packets > 10
PRINT High traffic
ENDWHILE
```

### Notes

- Nested while loops are **not supported**
- Condition is stored as raw text

---

# 🧩 Functions

## FUNCTION

Defines a reusable function.

### Syntax

```shark
FUNCTION name
    commands
ENDFUNCTION
```

### Example

```shark
FUNCTION greet
PRINT Hello
ENDFUNCTION
```

---

## CALL

Calls a function.

### Syntax

```shark
CALL functionName
```

### Example

```shark
CALL greet
```

### Notes

- Nested functions are **not supported**

---

# 🌐 Networking

## HTTP POST

Send an HTTP POST request.

### Syntax

```shark
HTTP POST url body
```

### Example

```shark
HTTP POST https://example.com/api hello
```

### Discord Webhook Example

```shark
HTTP POST https://discord.com/api/webhooks/123/token {"content":"Packet detected"}
```

---

## FETCH

Fetches content from a URL.

### Syntax

```shark
FETCH url
```

### Example

```shark
FETCH https://example.com/config.json
```

---

## REDIRECT

Redirects traffic to a port.

### Syntax

```shark
REDIRECT port number
```

### Example

```shark
REDIRECT port 8080
```

---

## SPOOF

Spoofs an IP address.

### Syntax

```shark
SPOOF ip
```

### Example

```shark
SPOOF 127.0.0.1
```

---

# 🖥️ Command Execution

## EXEC

Executes a shell command.

### Syntax

```shark
EXEC command
```

### Example

```shark
EXEC curl https://example.com
```

### Discord Webhook Example

```shark
EXEC curl -H "Content-Type: application/json" -X POST -d "{\"content\":\"Ligmashark Alert\"}" https://discord.com/api/webhooks/ID/TOKEN
```

---

# 💤 Timing

## SLEEP

Sleeps for milliseconds.

### Syntax

```shark
SLEEP milliseconds
```

### Example

```shark
SLEEP 1000
```

---

# ❓ Conditional Logic

## IF

Conditional execution.

Supported actions:

- `PRINT`
- `CALL`
- `BLOCK`
- `EXEC`
- `HTTP POST`

### Syntax

```shark
IF condition PRINT message
```

### Example

```shark
IF packet_count > 10 PRINT High traffic
```

---

### CALL Example

```shark
IF suspicious CALL ban_user
```

---

### EXEC Example

```shark
IF malicious EXEC curl https://example.com
```

---

### HTTP Example

```shark
IF malicious HTTP POST https://site.com alert
```

---

### Discord Webhook Example

```shark
IF malicious HTTP POST https://discord.com/api/webhooks/ID/TOKEN {"content":"🚨 Malicious traffic detected"}
```

---

## ELSE

Must directly follow an `IF`.

### Syntax

```shark
ELSE action
```

Supported actions:

- `PRINT`
- `CALL`
- `BLOCK`
- `HTTP POST`

### Example

```shark
IF malicious PRINT Threat detected
ELSE PRINT Safe traffic
```

---

# 🛡️ Packet / Security Commands

## BLOCK

Blocks something (implementation-dependent).

### Syntax

```shark
BLOCK
```

---

## DROP_ALL_PACKETS

Drops all packets.

```shark
DROP_ALL_PACKETS
```

---

## NUKE_CONNECTION

Terminates a connection.

```shark
NUKE_CONNECTION
```

---

## BashKILL_PID

Kills a process ID.

```shark
BashKILL_PID
```

---

## REJECT_MICROSOFT

Rejects Microsoft telemetry/services.

```shark
REJECT_MICROSOFT
```

---

## TELEMETRY_DETECTED

Telemetry detection event.

```shark
TELEMETRY_DETECTED message
```

---

# 🤡 Meme / Flavor Commands

These commands are implemented by the compiler but runtime behavior depends on Ligmashark.

## BASED

```shark
BASED message
```

Example:

```shark
BASED Gigachad detected
```

---

## SLOP

```shark
SLOP message
```

---

## HATE

```shark
HATE message
```

---

# ❌ Compiler Errors

Common compile failures:

### Unknown command

```text
line X: unknown command
```

---

### Missing LOOP count

```text
line X: LOOP requires a count
```

---

### Nested loops

```text
line X: nested loops are not yet supported
```

---

### Missing IF action

```text
line X: IF missing action (PRINT/CALL/BLOCK)
```

---

### ELSE without IF

```text
line X: ELSE must follow an IF statement
```

---

### Unclosed LOOP

```text
build error: unclosed LOOP block
```

---

### Unclosed FUNCTION

```text
build error: unclosed FUNCTION block
```

# Inputs

+7. INPUT +Prompts the user for input and stores it in a variable. +bash +INPUT target_name Please enter a target name: +PRINT "Target set to: %target_name%" + +Note: In TUI mode, this will block packet processing until input is received. + 7. HTTP POST Sends a POST request with a JSON body.
---

# 🧪 Complete Example

```shark
# Discord alert plugin

FUNCTION notify
HTTP POST https://discord.com/api/webhooks/ID/TOKEN {"content":"🚨 Threat detected"}
ENDFUNCTION

PRINT Plugin loaded

LOOP 3
PRINT Monitoring traffic...
ENDLOOP

IF malicious CALL notify
ELSE PRINT Traffic clean

SLEEP 1000
```

# ⚠️ Current Limitations

- No nested `LOOP`
- No nested `WHILE`
- No nested `FUNCTION`
- `ELSE` must immediately follow `IF`
- `IF` supports only:
  - PRINT
  - CALL
  - BLOCK
  - EXEC
  - HTTP POST
- `HTTP` only supports `POST`
- Conditions are stored as raw strings (compiler does not validate logic)
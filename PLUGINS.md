# 🔌 Ligmashark Plugin System

Ligmashark supports dynamic plugins using Go's `plugin` package. This allows you to extend Ligmashark's functionality (e.g., custom logging, alerting, or data export) without modifying the core source code.

## 🛠️ How to create a plugin

Plugins are written in Go and must implement the `types.Plugin` interface.

### 1. The Interface
Your plugin must implement the following interface defined in `internal/types/types.go`:

```go
type Plugin interface {
	Name() string
	OnPacket(pkt *PacketData)
}
```

### 2. Example Plugin (`logger.go`)

Create a new file, for example `logger.go`:

```go
package main

import (
	"fmt"
	"ligmashark/internal/types"
)

type LoggerPlugin struct{}

func (l LoggerPlugin) Name() string {
	return "Simple Logger"
}

func (l LoggerPlugin) OnPacket(pkt *types.PacketData) {
	if pkt.IsMalicious {
		fmt.Printf("[ALERT] Malicious packet detected from %s to %s\n", pkt.SrcIP, pkt.DstIP)
	}
}

// Exported symbol must be named 'Plugin'
var Plugin LoggerPlugin
```

### 3. Compiling the Plugin
Plugins must be compiled as shared objects (`.so`).

```bash
go build -buildmode=plugin -o logger.so logger.go
```

**Note:** The plugin must be compiled with the exact same Go version and environment as the main Ligmashark binary.

### 4. Installing the Plugin
Move the compiled `.so` file to a directory named `plugins` in the same location where you run `ligmashark`:

```bash
mkdir -p plugins
mv logger.so plugins/
```

Ligmashark will automatically load any `.so` files found in the `plugins/` directory at startup.
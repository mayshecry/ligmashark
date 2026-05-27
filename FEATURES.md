# ✨ Ligmashark Features

### 🛰️ Real-time Detection
- **ISP Detection**: Automatically identifies the destination network (e.g., Google, Amazon, Comcast, Discord).
- **Service Mapping**: Recognizes common gaming ports (Minecraft, Source Engine, Rust) and web browsers.
- **Protocol Filtering**: Cycle through TCP, UDP, and ICMP filters instantly to isolate specific traffic types.

### 🛡️ Threat Intelligence
- **ThreatFox Integration**: Periodically fetches real-time IoCs (Indicators of Compromise) from `abuse.ch`.
- **Visual Alerts**: Malicious connections are highlighted in red in the process list and packet history.

### 🧠 AI Analysis
Ligmashark uses local AI to explain packet payloads in plain English.
- **Model**: Uses `qwen2.5:0.5b` via Ollama.
- **Privacy**: No data leaves your machine. The raw hex dump is sent to your local Ollama instance for summary.
- **Context Awareness**: The AI is tipped off about process names (e.g., Discord) to provide better context for UDP traffic.
- **Exportable Reports**: Generate detailed technical reports for any packet, including AI summaries, network metadata, and full hex dumps for offline analysis.

### 🔌 SharkScript Automation
- **Accessible Logic**: A DuckyScript-inspired syntax designed to be understood by everyone, not just Go developers.
- **Cross-Platform**: Unlike native plugins, SharkScript works seamlessly on both Linux and Windows.
- **Compiled & Secure**: Source `.shark` files are compiled into proprietary `.ligma` bytecode for high-performance execution.
- **Deep Integration**: Built-in support for conditional logic (IF/ELSE), loops, variables, math, and specialized network actions like HTTP POST, Redirect, and Spoofing.

### ⌨️ Navigation & Control
- **Auto-scroll Management**: Toggle auto-scroll to freeze the viewport, allowing you to inspect specific sequences while capture continues in the background.
- **Session Management**: Clear packet history and reset bandwidth counters for individual processes to start fresh analysis sessions.
- **Enhanced Navigation**: Optimized for speed with support for Home, End, and Vim-style keys (`G`) for navigating large packet buffers and process lists.

### 📊 Graph Mode
Accessed by pressing `g`, this mode provides high-level visualization of your network stack.
- **Throughput**: Real-time charts for Incoming and Outgoing bytes per second.
- **History**: Tracks the last 100 seconds of activity.
- **Top Talkers**: Displays the top 3 processes consuming the most bandwidth in the current session.

### 🔌 Extensibility
- **Plugin Support**: Load `.so` files at runtime to add custom alerting or logging logic.
- **SharkScript**: Use the internal DSL for rapid automation and alerting.

### 🖥️ Platform Support

#### Linux (Recommended)
- **Full Performance**: Uses the `any` interface for system-wide capture.
- **Plugin Support**: Native support for Go's `plugin` package.
- **Permissions**: Handles `CAP_NET_RAW` via `setcap` to avoid running everything as root.

#### Windows
- **Capture**: Requires Npcap/WinPcap and running as Administrator.
- **Limitations**: Go plugins are not currently supported on Windows.
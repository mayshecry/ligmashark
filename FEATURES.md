# ✨ Ligmashark Features

### 🛰️ Real-time Detection
- **ISP Detection**: Automatically identifies the destination network (e.g., Google, Amazon, Comcast, Discord).
- **Service Mapping**: Recognizes common gaming ports (Minecraft, Source Engine, Rust) and web browsers.

### 🛡️ Threat Intelligence
- **ThreatFox Integration**: Periodically fetches real-time IoCs (Indicators of Compromise) from `abuse.ch`.
- **Visual Alerts**: Malicious connections are highlighted in red in the process list and packet history.

### 🧠 AI Analysis
Ligmashark uses local AI to explain packet payloads in plain English.
- **Model**: Uses `qwen2.5:0.5b` via Ollama.
- **Privacy**: No data leaves your machine. The raw hex dump is sent to your local Ollama instance for summary.
- **Context Awareness**: The AI is tipped off about process names (e.g., Discord) to provide better context for UDP traffic.

### 📊 Graph Mode
Accessed by pressing `g`, this mode provides high-level visualization of your network stack.
- **Throughput**: Real-time charts for Incoming and Outgoing bytes per second.
- **History**: Tracks the last 100 seconds of activity.
- **Top Talkers**: Displays the top 3 processes consuming the most bandwidth in the current session.

### 🔌 Extensibility
- **Plugin Support**: Load `.so` files at runtime to add custom alerting or logging logic.

### 🖥️ Platform Support

#### Linux (Recommended)
- **Full Performance**: Uses the `any` interface for system-wide capture.
- **Plugin Support**: Native support for Go's `plugin` package.
- **Permissions**: Handles `CAP_NET_RAW` via `setcap` to avoid running everything as root.

#### Windows
- **Capture**: Requires Npcap/WinPcap and running as Administrator.
- **Limitations**: Go plugins are not currently supported on Windows.
# 🦈 Ligmashark

**Real-time network analyzer that actually shows you which process is talking to who.**

Most network tools just vomit raw packets at you. **Ligmashark** maps every connection directly to the **PID + Application**, identifies the ISP, and uses local AI (Ollama) to explain exactly what is happening inside the packet.

Built for Arch/Chad Linux users, self-hosters, security autists, and people who like knowing what their machine is actually doing.

![Ligmashark Preview](https://github.com/mayshecry/ligmashark/blob/main/screenshots/1.png)
![Process View](https://github.com/mayshecry/ligmashark/blob/main/screenshots/2.png)
![Packet Detail + AI Analysis](https://github.com/mayshecry/ligmashark/blob/main/screenshots/3.png)
![Help Menu](https://github.com/mayshecry/ligmashark/blob/main/screenshots/4.png)

---

## 📑 Index

1. [Features](#-features)
2. [Getting Started](#-getting-started)
   - [Requirements](#requirements)
   - [Installation](#installation)
3. [Usage & Hotkeys](#-usage--hotkeys)
4. [Advanced Features](#-advanced-features)
   - [AI Analysis](#ai-analysis)
   - [Graph Mode](#graph-mode)
   - [Plugin System](#plugin-system)
5. [Platform Support](#-platform-support)
6. [How It Works & Transparency](#-how-it-works--transparency)

## ✨ Features

- **Real-time ISP & Service Detection** — Identifies Discord, Minecraft, GitHub, browsers, etc.
- **Threat Intelligence Integration** — Real-time matching against **ThreatFox** IOCs; highlights malicious connections in red.
- **Dynamic Protocol Awareness** — Shallow sniffing of unencrypted traffic to extract HTTP Methods, Status Codes, and service hints.
- **Local AI Packet Analysis** — Uses Ollama (qwen2.5) to explain payloads in plain English
- **Clean Neovim-style TUI** — Beautiful, fast, and keyboard-driven
- **Graph Mode** — Visual real-time bandwidth tracking for system-wide traffic.
- **Extensible Plugin Support** — Create custom logic in Go to process packets on the fly.
- **Lightweight & Fast** — Written in Go with Bubble Tea + Lip Gloss

## 🚀 Getting Started

### Requirements
Ligmashark needs a few dependencies to capture and analyze traffic:
- **Linux** (Best experience) or **Windows**.
- **libpcap** headers (e.g., `libpcap-dev` on Debian or `libpcap` on Arch).
- **Go 1.22+** (to build from source).
- **Ollama** (Optional, for AI payload explanations).

### Installation
**Linux (Recommended):**
```bash
git clone https://github.com/mayshecry/ligmashark.git
cd ligmashark
chmod +x install.sh
sudo ./install.sh
```

Then just run:
```bash
ligmashark
```

Or even easier if your on arch (You use arch btw)

```bash
yay -S ligmashark-git
```

## ⌨️ Hotkeys

| Key              | Action                              |
|------------------|-------------------------------------|
| `Ctrl+C`         | Quit Ligmashark                     |
| `q` / `h` / `Esc`| Toggle Home Screen / Go back        |
| `?`              | Toggle Help Menu                    |
| `j` / `k`        | Navigate process list               |
| `Enter`          | Select process + view packet details|
| `u` / `d`        | Scroll packet viewport              |
| `/`              | Filter by ISP                       |
| `;`              | Search/Filter processes by name     |
| `p`              | Pause/Resume capture                |
| `i`              | Re-select network interface         |
| `g`              | Toggle Graph Mode                   |
| `s`              | Cycle filter mode                   |

## 🧠 AI Analysis

Ligmashark automatically uses **Ollama** + `qwen2.5:0.5b`:

1. Install Ollama: `curl -fsSL https://ollama.com/install.sh | sh`
2. Run `ollama run qwen2.5:0.5b` once (or let Ligmashark pull it)
3. Select any packet → Press Enter → Get AI breakdown

## 🛠️ Requirements

- Linux (Arch, Debian, Fedora tested)
- Root / `CAP_NET_RAW` privileges (for packet capture)
- Go 1.22+ (only needed if building manually)
- Ollama (for AI features)

## 🛡️ How It Works & Transparency

Ligmashark is designed with privacy and performance in mind. Here is how the engine handles your data:

### 1. Process Mapping (The "Magic")
Ligmashark uses `libpcap` to capture raw packets. To map a packet to a process, it inspects the source and destination ports. It then queries the Linux kernel's networking stack (via the `/proc` filesystem) to see which Process ID (PID) owns that specific socket. This is done entirely on your machine without overhead.

### 2. Local AI (Privacy First)
Unlike other tools that send data to OpenAI or Claude, Ligmashark uses **Ollama**.
- **Your data never leaves your machine.**
- Analysis is performed by a local model (`qwen2.5:0.5b`).
- If Ollama isn't running, the AI features simply remain disabled.

### 3. External Requests
To provide context, the tool makes only two types of external calls:
- **ISP Lookups**: Queries `ip-api.com` to tell you who owns a destination IP.
- **Threat Intel**: Periodically fetches a public JSON blocklist from `ThreatFox (abuse.ch)` to identify known malicious C2 servers.

### 4. Security
Ligmashark requires `CAP_NET_RAW` to capture packets. The included `install.sh` uses `setcap` to grant this specific permission to the binary so you don't have to run the entire TUI as `root`.

---
*Built because I got tired of guessing which background service was phoning home. Now you can see it all in real time.*

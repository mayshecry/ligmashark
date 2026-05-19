# 🦈 Ligmashark

Ligmashark is a powerful, terminal-based network analyzer for Linux designed for developers and security enthusiasts. Unlike traditional sniffers that show a wall of raw data, Ligmashark maps every incoming and outgoing packet to the specific **Process ID (PID)** and **Application Name** running on your system.

It combines network telemetry with AI-powered payload analysis and automated ISP identification to give you a complete picture of your system's "chatter."

## ✨ Features

*   **Process-to-Packet Mapping**: Automatically associates network traffic with local processes using socket-to-PID resolution.
*   **ISP & Service Identification**: Real-time lookups for destination ISPs and common service signatures (e.g., Discord Voice, Minecraft, Web Browsers).
*   **AI Payload Analysis**: Integrates with local Ollama instances (specifically `qwen2.5:0.5b`) to explain packet payloads in plain English.
*   **Distro-Agnostic TUI**: A beautiful terminal interface built with Bubble Tea and Lip Gloss, featuring Neovim-inspired navigation.
*   **Intelligent Filtering**: Toggle between viewing all traffic, only foreground applications, or only background system services.

## 🚀 Installation

To install Ligmashark and all its dependencies (including `libpcap`), run the provided installation script:

```bash
chmod +x install.sh
sudo ./install.sh
```

This script will:
1. Detect your Linux distribution (Ubuntu/Debian, Arch, or Fedora).
2. Install necessary build tools and packet capture libraries.
3. Compile the Go binary.
4. Move the binary to `/usr/local/bin/ligmashark` for global access.

## ⌨️ Hotkeys

| Key | Action |
|-----|--------|
| `q` / `Esc` | Quit Ligmashark / Return to previous view |
| `?` | Toggle Help Menu |
| `j` / `k` | Navigate process list (Up/Down) |
| `Enter` | Select process / Open detailed packet inspection |
| `u` / `d` | Scroll traffic viewport (Up/Down) |
| `/` | Filter processes by ISP string |
| `p` | Pause/Resume real-time packet capture |
| `s` | Cycle Process Filter (Everything ➔ Foreground ➔ Background) |
| `h` | Return to Landing Page |

## 🧠 AI Analysis Setup

Ligmashark uses **Ollama** for local AI processing.
1. Install Ollama: `curl -fsSL https://ollama.com/install.sh | sh`
2. Ligmashark will automatically attempt to start the Ollama server and pull the `qwen2.5:0.5b` model on first launch if they aren't available.
3. Once ready, select a packet and press `Enter` to see the AI's technical breakdown of the payload.

## 🛠️ Requirements

*   **Go**: 1.22 or higher.
*   **Privileges**: Packet capture requires root/sudo privileges (the app will prompt for elevation automatically if needed).
*   **Dependencies**: `libpcap` (installed via `install.sh`).

## 🤝 Contributing

Created by **heavenzone** (@mayshecry on GitHub). Feel free to open issues or submit pull requests to improve the protocol analysis or service identification logic.

## Future?

I'll be working on windows support but as i daily drive linux that just made more sense >,<
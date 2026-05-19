
# 🦈 Ligmashark

**Real-time network analyzer that actually shows you which process is talking to who.**

Most network tools just vomit raw packets at you.  
**Ligmashark** maps every connection directly to the **PID + Application**, tells you the ISP, and even uses local AI (Ollama) to explain what the f*ck is in the packet.

Built for Arch/Chad Linux users, self-hosters, security autists, and people who like knowing what their machine is actually doing.

![Ligmashark Preview](https://github.com/mayshecry/ligmashark/blob/main/screenshots/1.png)
![Process View](https://github.com/mayshecry/ligmashark/blob/main/screenshots/2.png)
![Packet Detail + AI Analysis](https://github.com/mayshecry/ligmashark/blob/main/screenshots/3.png)
![Help Menu](https://github.com/mayshecry/ligmashark/blob/main/screenshots/4.png)

## ✨ Features

- **Process-to-Packet Mapping** — See exactly which app/process is responsible for every connection
- **Real-time ISP & Service Detection** — Identifies Discord, Minecraft, GitHub, browsers, etc.
- **Local AI Packet Analysis** — Uses Ollama (qwen2.5) to explain payloads in plain English
- **Clean Neovim-style TUI** — Beautiful, fast, and keyboard-driven
- **Smart Filters** — Everything / Foreground apps only / Background services only
- **Lightweight & Fast** — Written in Go with Bubble Tea + Lip Gloss

## 🚀 Installation

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
| `q` / `Esc`      | Quit / Go back                      |
| `?`              | Toggle Help Menu                    |
| `j` / `k`        | Navigate process list               |
| `Enter`          | Select process + view packet details|
| `u` / `d`        | Scroll packet viewport              |
| `/`              | Filter by ISP                       |
| `p`              | Pause/Resume capture                |
| `s`              | Cycle filter mode                   |
| `h`              | Return to home screen               |

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

## Why I Built This

Because I got tired of guessing which Electron app or background service was phoning home. Now I can see everything in real time.


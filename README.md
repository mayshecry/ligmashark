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

1. [🚀 Getting Started](#-getting-started)
2. [✨ Core Features](FEATURES.md)
3. [⌨️ Usage & Hotkeys](USAGE.md)
4. [🔌 Plugin Development](PLUGINS.md)
5. [🛡️ Internals & Privacy](INTERNALS.md)
6. [🖥️ Platform Support](FEATURES.md#platform-support)

## 🚀 Getting Started

### Requirements
Ligmashark needs a few dependencies to capture and analyze traffic:
- **Linux** (Best) or **Windows**.
- **libpcap** headers (e.g. `libpcap-dev`).
- **Go 1.22+**.
- **Ollama** (Optional, for AI features).

### Installation

**Linux (Recommended):**
```bash
git clone https://github.com/mayshecry/ligmashark.git
cd ligmashark
chmod +x install.sh
sudo ./install.sh
```

**Arch Linux (AUR):**
```bash
yay -S ligmashark-git
```

---
*Built because I got tired of guessing which background service was phoning home. Now you can see it all in real time.*

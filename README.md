# 🦈 Ligmashark

**Real-time network analyzer that actually shows you which process is talking to who.**

Most network tools just vomit raw packets at you. **Ligmashark** maps every connection directly to the **PID + Application**, identifies the ISP, and uses local AI (Ollama) to explain exactly what is happening inside the packet.

Built for Arch/Chad Linux users, self-hosters, security autists, and people who like knowing what their machine is actually doing.

![Ligmashark Preview](https://github.com/mayshecry/ligmashark/blob/main/screenshots/1.png)
![Process View](https://github.com/mayshecry/ligmashark/blob/main/screenshots/2.png)
![Packet Detail + AI Analysis](https://github.com/mayshecry/ligmashark/blob/main/screenshots/3.png)
![Help Menu](https://github.com/mayshecry/ligmashark/blob/main/screenshots/4.png)

---
## 🔌 SharkScript

Ligmashark features its own lightweight programming language called **SharkScript**. 

The developer (**Mayshecry**) had enough of complicated shit, so he created a language that everyone can understand. It looks identical to **DuckyScript**, but instead of firing keystrokes at a USB ducky, it's designed for packet manipulation and network automation on normal devices.

Check out the [SharkScript Language Reference](SHARK_LANG.md) to get started.

---

## 📑 Index

1. [🚀 Getting Started](#-getting-started)
2. [✨ Core Features](docs/FEATURES.md)
3. [⌨️ Usage & Hotkeys](docs/USAGE.md)
4. [🔌 SharkScript Reference](SHARK_LANG.md)
5. [🔌 Plugin Development](docs/PLUGINS.md)
6. [🛡️ Internals & Privacy](docs/INTERNALS.md)
7. [🖥️ Platform Support](docs/FEATURES.md#platform-support)

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

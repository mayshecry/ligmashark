
<h1 align="center">🦈 Ligmashark</h1>
<p align="center">
  <strong>The network monitor that actually tells you which process is being a whore on your machine.</strong>
</p>

<div align="center">
  <img src="https://github.com/mayshecry/ligmashark/blob/main/screenshots/1.png" width="48%" />
  <img src="https://github.com/mayshecry/ligmashark/blob/main/screenshots/2.png" width="48%" />
  <img src="https://github.com/mayshecry/ligmashark/blob/main/screenshots/3.png" width="48%" />
</div>

---

### Why Ligmashark?

Most network tools suck:

- **Wireshark**: Raw packet vomit. Good luck figuring out which program is responsible.
- **nethogs / iftop**: Shows bandwidth but hides the real culprit.
- Everything else: Bloated, full of telemetry, or just bad.

I got tired of guessing what the fuck my computer was doing in the background at 3AM, so I built **Ligmashark**.

---

## What is it?

**Ligmashark** is a real-time **process-aware** network analyzer. It maps every single connection to the actual **PID + process name**, detects ISPs and services, highlights threats, uses local AI to explain packets, and comes with its own scripting language.

Built for Arch users, self-hosters, privacy autists, and security schizos who want to know what their machine is actually doing.

---

## ✨ Core Features

- **Process Mapping** — The killer feature. Every connection is linked to the real process.
- **ISP & Service Detection** — Automatically identifies Google, Amazon, Discord, Cloudflare, gaming services, etc.
- **Threat Intelligence** — ThreatFox integration. Malicious connections highlighted in red.
- **Local AI Analysis** — Uses Ollama (`qwen2.5:0.5b`) to explain packet payloads in plain English. 100% offline.
- **Graph Mode** — Press `g` for real-time bandwidth charts + top talkers.
- **SharkScript** — Custom scripting language for automation and alerts.
- **Plugin System** — Both `.ligma` scripts and Go `.so` plugins supported.

---

## 🦈 SharkScript

I got tired of complicated plugin systems, so I made my own language.

**Simple, compiled, and fast.**

**Example:**

```shark
# Discord alert when malicious traffic is detected
FUNCTION notify
    HTTP POST https://discord.com/api/webhooks/... {"content":"🚨 Malicious traffic from %PROCESS% (%PID%)"}
ENDFUNCTION

IF malicious CALL notify

# Reject Microsoft telemetry
IF CONTAINS "microsoft" REJECT_MICROSOFT

PRINT Monitoring traffic...
```

**How to use:**
1. Write script → `script.shark`
2. Compile: `ligmashark --compile script.shark`
3. Drop `script.ligma` into `plugins/`

Full language reference: **[SHARK_LANG.md](SHARK_LANG.md)**

---

## 🚀 Installation

### Arch Linux (Recommended)
```bash
yay -S ligmashark-git
```

### Manual (Linux)
```bash
git clone https://github.com/mayshecry/ligmashark.git
cd ligmashark
chmod +x install.sh
sudo ./install.sh
ligmashark
```

**Windows**: Works with Npcap (run as Administrator), but Linux is recommended.

---

## Hotkeys

| Key              | Action                              |
|------------------|-------------------------------------|
| `q` / `Esc`      | Back / Close detail view            |
| `h`              | Toggle overview                     |
| `?`              | Help menu                           |
| `j` / `k`        | Navigate process list               |
| `Enter`          | View packet details                 |
| `g`              | Toggle Graph Mode                   |
| `p`              | Pause/Resume capture                |
| `/`              | Filter by ISP                       |
| `s`              | Toggle process filter               |

Full list → [USAGE.md](USAGE.md)

---

## Tech & Philosophy

- Written in **Go**
- Uses `gopacket` + `libpcap`
- Process mapping via `/proc` (Linux) with smart caching
- Privacy-first: Local Ollama only, minimal external calls
- Capability dropping on Linux (`CAP_NET_RAW`)

**Philosophy:**
```txt
Minimal. Clean. No telemetry.
No J*bs. No bloat. No bullshit.
Just good code.
```

---

## Who is this for?

- Self-hosters & homelab chads
- Privacy maxxers
- Security researchers
- Terminal autists
- People who hate black-box networking

---

Star if you find it useful. Issues and PRs welcome (just don’t be a comkid).

---

*Made with sleep deprivation, nightcore, and pure hatred for bad software.*

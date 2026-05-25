# 🛡️ How It Works & Transparency

### 1. Process Mapping (The "Magic")
Ligmashark uses `libpcap` to capture raw packets. To map a packet to a process, it inspects source and destination ports. It then queries the kernel's networking stack (via `gopsutil` which reads `/proc` on Linux or uses `GetExtendedTcpTable` on Windows) to find the PID owning that specific socket. 

**Optimization**: Ligmashark caches connection states and local interface IPs every 2 seconds to ensure that mapping doesn't introduce lag during high-throughput capture.

### 2. Local AI (Privacy First)
Unlike other tools that send data to OpenAI or Claude, Ligmashark uses **Ollama**.
- **Offline**: Your data never leaves your machine.
- **Shallow Sniffing**: Only the application layer payload is sent to the model.

### 3. External Requests
Ligmashark only makes two types of external calls:
- **ISP Lookups**: Queries `ip-api.com` for remote IP context. These are cached in memory for the duration of the session.
- **Threat Intel**: Fetches a JSON blocklist from `ThreatFox (abuse.ch)` once at startup.

### 4. Security & Permissions
Capture requires raw socket access:
- **Linux**: The `install.sh` uses `setcap cap_net_raw,cap_net_admin=eip` on the binary. This allows you to run it as a standard user while only giving the binary the specific network permissions it needs.
- **Windows**: Requires Administrator privileges to interface with the Npcap driver.

### 5. TCP Assembly
For HTTP traffic, Ligmashark uses `gopacket/tcpassembly` to reconstruct streams. This allows it to identify HTTP methods (GET/POST) even when packets are fragmented.
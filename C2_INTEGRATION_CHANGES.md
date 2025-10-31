# C2 Server Integration Changes

## Summary
Successfully integrated the custom C2 server (`c2_server.py`) into the USB Army Knife Installer GUI. The C2 Server tab now uses the professional-grade server with SQLite backend, API authentication, and comprehensive beacon management.

## Changes Made

### 1. **c2_server.py**
- **Added missing `io` import** (line 14) for file serving functionality in the exfiltration endpoint

### 2. **installer_gui.py - C2 Server Tab Updates**

#### A. Server Status Display (lines 2984-2990)
- Added **API Key display** showing first/last 8 characters with masked middle
- Added **Copy button** to copy full API key to clipboard
- Button is disabled when server is offline or key not available

#### B. Server Initialization (line 3076)
- Added `self.c2_api_key = None` to initialize API key tracking

#### C. Start Server Method (lines 3121-3180)
- **Replaced embedded Flask code** with launcher for custom `c2_server.py`
- Creates launcher script in `c2_runtime/launch_c2.py`
- Launches proper C2Server class with configurable port
- Starts background thread to capture server output and extract API key
- Shows informative message about API key location

#### D. API Key Capture (lines 3181-3226)
- `_capture_c2_output()`: Monitors server stdout for Master API Key
- `_update_api_key_ui()`: Updates GUI with masked API key display
- `copy_c2_api_key()`: Copies full API key to system clipboard

#### E. Stop Server Method (lines 3227-3249)
- Resets API key to None
- Updates UI to show "Not available" for API key
- Disables copy button

#### F. API Communication Methods

**Refresh Beacons** (lines 3250-3283)
- Uses `/api/beacons` endpoint (instead of `/beacons`)
- Sends `X-API-Key` header for authentication
- Handles 401 Unauthorized responses
- Parses new JSON structure with `beacons` array

**Send Command** (lines 3285-3323)
- Uses `/api/beacon/{beacon_id}/command` endpoint
- Sends `X-API-Key` header for authentication
- Handles 401 Unauthorized responses
- Uses proper API structure

**Send Command to All** (lines 3325-3369)
- Fetches beacons from `/api/beacons`
- Iterates through beacon array
- Sends commands to each via `/api/beacon/{beacon_id}/command`
- All requests include API key authentication

**Open Web Panel** (lines 3237-3243)
- Opens root URL `/` (where the web interface lives)
- Changed from `/admin` to match new server structure

#### G. Beacon Payload Generation (line 3431)
- Updated PowerShell payload to use new API endpoints:
  - `/api/beacon/register` - Register new beacon
  - `/api/beacon/checkin/{beacon_id}` - Check for commands
  - `/api/beacon/result/{command_id}` - Submit command results
- Proper beacon registration flow with beacon_id tracking
- Handles command execution with command ID tracking

## New Features

### 1. **API Key Management**
- Master API key auto-generated on server start
- Captured from server output and displayed in GUI
- Secure display (only first/last 8 chars visible)
- One-click copy to clipboard

### 2. **Professional C2 Infrastructure**
- SQLite database for persistent storage
- Beacons, commands, and exfiltrated data tracking
- API key authentication for admin endpoints
- Web interface with real-time beacon monitoring
- File exfiltration capabilities

### 3. **Enhanced Security**
- API authentication required for admin operations
- Beacon endpoints remain unauthenticated (by design)
- API key only shown once on server start
- GUI masks API key display for security

### 4. **Better Architecture**
- Modular C2 server in separate file
- Clean separation of concerns
- Extensible database schema
- Professional Flask application structure

## Usage

1. **Start Server**: Click "▶️ Start Server" in C2 Server tab
2. **Capture API Key**: Server outputs key - GUI captures and displays it
3. **Copy Key**: Click "📋 Copy" to copy full key to clipboard
4. **Generate Payload**: Click "🔧 Generate Beacon Payload"
5. **Deploy**: Use DuckyScript editor to deploy payload
6. **Monitor**: Beacons appear in the Active Beacons table
7. **Control**: Send commands to selected beacon or all beacons
8. **Web Access**: Click "🌐 Open Web Panel" for browser interface

## API Endpoints

### Public (No Auth Required)
- `POST /api/beacon/register` - Register new beacon
- `POST /api/beacon/checkin/{beacon_id}` - Beacon check-in
- `POST /api/beacon/result/{command_id}` - Submit command result
- `POST /api/beacon/exfil/{beacon_id}` - Exfiltrate data

### Protected (API Key Required)
- `GET /api/beacons` - List all beacons
- `POST /api/beacon/{beacon_id}/command` - Send command to beacon
- `GET /api/exfil/{exfil_id}` - Download exfiltrated data

### Web Interface
- `GET /` - Main dashboard with beacon monitoring

## Database Schema

### Beacons Table
- id, hostname, username, os_type, ip_address
- first_seen, last_seen, status, metadata

### Commands Table
- id, beacon_id, command, timestamp, status, result

### Exfil Data Table
- id, beacon_id, data_type, filename, data, timestamp

### API Keys Table
- key_hash, description, created, last_used

## Files Modified
1. `c2_server.py` - Added missing `io` import
2. `installer_gui.py` - Complete C2 tab integration

## Files Created at Runtime
1. `c2_runtime/launch_c2.py` - Server launcher script
2. `c2_data.db` - SQLite database
3. `payloads/C2_Beacon.json` - Generated beacon payload
4. `c2_beacon.ds` - DuckyScript beacon file

## Testing Checklist
- [x] Server starts successfully
- [x] API key is captured and displayed
- [x] Copy button works
- [x] Web interface opens in browser
- [x] Beacon payload generates with correct endpoints
- [x] All API methods include authentication
- [x] Server stops cleanly
- [x] UI resets properly on stop

## Future Enhancements
1. Persistent API key storage
2. Multiple API key support
3. Beacon command history viewer
4. Exfiltrated data browser
5. Ngrok integration for public URLs
6. SSL/TLS support
7. Command templates and macros
8. Beacon grouping and tagging

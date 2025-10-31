# USB Army Knife - Installation Guide

## 📋 Prerequisites

### Operating System
- **Recommended:** Kali Linux 2023.1+
- **Supported:** Debian/Ubuntu-based Linux distributions
- **Note:** Windows/macOS not fully supported (Linux-specific tools required)

## 🔧 Installation Steps

### 1. System Dependencies

Install required system packages:

```bash
# Core tools
sudo apt update
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git

# USB/Serial tools
sudo apt install -y \
    python3-serial \
    esptool

# Network reconnaissance (optional but recommended)
sudo apt install -y \
    nmap \
    masscan \
    netdiscover \
    arp-scan

# Bluetooth tools (optional)
sudo apt install -y \
    bluez \
    bluez-tools \
    bluetooth

# WiFi tools (optional)
sudo apt install -y \
    aircrack-ng \
    wireless-tools

# Utilities
sudo apt install -y \
    netcat-traditional \
    qrencode
```

### 2. Python Virtual Environment

```bash
cd /path/to/armyknifeinstaller

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip setuptools wheel
```

### 3. Python Dependencies

```bash
# Install from requirements.txt
pip install -r requirements.txt

# If you encounter issues, install manually:
pip install pyserial>=3.5
pip install ttkbootstrap>=1.10.1
pip install cryptography>=41.0.0
pip install Flask>=3.0.0

# Optional: QR code generation
pip install qrcode[pil]
```

### 4. USB Permissions

Add your user to dialout group for USB/Serial access:

```bash
sudo usermod -a -G dialout $USER
sudo usermod -a -G plugdev $USER

# Log out and back in, or reboot for changes to take effect
newgrp dialout
```

### 5. Verify Installation

```bash
# Check Python packages
python3 -c "import serial, ttkbootstrap, cryptography, flask; print('✓ All packages installed')"

# Check system tools
which nmap nc aircrack-ng hciconfig

# List serial ports
python3 -m serial.tools.list_ports
```

## 🚀 Running the Application

### Basic Launch

```bash
cd /path/to/armyknifeinstaller
source venv/bin/activate
python3 installer_gui.py
```

### With Elevated Privileges (for advanced features)

Some features require root access:
- Bluetooth adapter control
- Raw socket scanning (nmap -sS)
- Network interface manipulation

```bash
# Option 1: Run GUI as root (not recommended)
sudo python3 installer_gui.py

# Option 2: Grant capabilities to specific tools
sudo setcap cap_net_raw,cap_net_admin=eip $(which nmap)
```

## 🔌 Hardware Setup

### ESP32 Device Connection

1. Connect USB Army Knife device via USB
2. Click "🔍 Detect" in the Flasher tab
3. Select your device (usually /dev/ttyUSB0 or /dev/ttyACM0)

### First-Time Device Setup

1. **Flash Firmware:**
   - Go to ⚡ Flasher tab
   - Detect device
   - Click "⬆️ Install Firmware"

2. **Verify Connection:**
   - Go to 📺 Serial Monitor tab
   - Open connection
   - Should see device output

3. **Create First Payload:**
   - Go to 📝 DuckyScript tab
   - Write or load payload
   - Save to device

## 🧪 Testing

### Test Core Functionality

```bash
# Test GUI launch
python3 installer_gui.py

# Test serial detection
python3 -c "import serial.tools.list_ports; print(list(serial.tools.list_ports.comports()))"

# Test cryptography
python3 -c "from cryptography.fernet import Fernet; print('✓ Crypto working')"
```

### Test Attack Modules (Optional)

```bash
# Test nmap
nmap -sn 192.168.1.0/24

# Test Bluetooth
hciconfig hci0 up
hcitool scan

# Test WiFi tools
iwconfig
airmon-ng
```

## 📚 Module Requirements

### Core Modules (Always Available)
- ✅ Dashboard
- ✅ Welcome/Setup
- ✅ Flasher
- ✅ eFuse Manager
- ✅ Agent
- ✅ DuckyScript Editor
- ✅ Payload Library
- ✅ Serial Monitor
- ✅ Profiles
- ✅ Orchestration
- ✅ Obfuscation

### Optional Modules (Require Additional Tools)

**📡 WiFi Attacks:**
- Requires: ESP32 Marauder firmware
- Tools: `aircrack-ng` (for handshake cracking)

**🔵 Bluetooth:**
- Requires: Bluetooth adapter
- Tools: `bluez`, `hciconfig`, `hcitool`

**🔍 Network Recon:**
- Requires: `nmap` (CRITICAL)
- Optional: `masscan`, `zenmap`

**🎭 Social Engineering:**
- Requires: `Flask` (Python - in requirements.txt)
- Optional: `qrencode` for QR codes

**🔧 Post-Exploitation:**
- Requires: `netcat` (`nc`)
- Payload-specific tools as needed

**⚙️ C2 Server:**
- Requires: Separate ek0msUSB framework
- See: https://github.com/ek0msUSB

## 🐛 Troubleshooting

### "No module named 'ttkbootstrap'"
```bash
pip install ttkbootstrap
```

### "Permission denied: '/dev/ttyUSB0'"
```bash
sudo usermod -a -G dialout $USER
# Then logout and login again
```

### "nmap: command not found"
```bash
sudo apt install nmap
```

### "Could not open port /dev/ttyUSB0"
- Device might be in use by another program
- Try different USB port
- Check: `ls -l /dev/ttyUSB*`

### GUI doesn't launch
```bash
# Check Python version (need 3.8+)
python3 --version

# Check display
echo $DISPLAY

# Try with verbose errors
python3 installer_gui.py 2>&1 | more
```

### Import errors
```bash
# Reinstall dependencies
pip install --force-reinstall -r requirements.txt

# Check virtual environment is activated
which python3  # Should show venv path
```

## 📦 Optional Enhancements

### Install Additional Pentesting Tools

```bash
# Metasploit Framework (for C2/post-exploit)
sudo apt install metasploit-framework

# John the Ripper (password cracking)
sudo apt install john

# Hydra (network login cracker)
sudo apt install hydra

# Wireshark (packet analysis)
sudo apt install wireshark
```

### Install ESP-IDF (for firmware development)

```bash
mkdir -p ~/esp
cd ~/esp
git clone --recursive https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh esp32,esp32s2,esp32s3
. ./export.sh
```

## ⚠️ Security Notice

This tool is designed for **authorized security testing only**.

- Only use on systems you own or have explicit permission to test
- Many features require root/admin privileges
- Some attacks may be illegal without authorization
- Use responsibly and ethically

## 📖 Documentation

- **GitHub:** https://github.com/usb-army-knife
- **Wiki:** https://github.com/usb-army-knife/wiki
- **Issues:** https://github.com/usb-army-knife/issues

## 🆘 Getting Help

1. Check this installation guide
2. Review error messages carefully
3. Check GitHub Issues for similar problems
4. Open a new issue with:
   - OS version
   - Python version
   - Complete error message
   - Steps to reproduce

---

**Version:** 1.0.0  
**Last Updated:** 2024-10-31

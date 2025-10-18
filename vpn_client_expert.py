import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import json, os, time, base64, hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CFG_PATH = "config.json"
TRUST_PATH = "trusted_server.json"

DEFAULT_CFG = {
    "server_ip": "127.0.0.1",
    "server_port": 8080,
    "request_timeout_seconds": 8,
    "history_size": 10
}

DELIM = b"<<END>>"
RECV_BUFFER = 4096

def load_config():
    if os.path.exists(CFG_PATH):
        try:
            with open(CFG_PATH, "r") as f:
                cfg = json.load(f)
            merged = DEFAULT_CFG.copy()
            merged.update(cfg)
            return merged
        except Exception:
            pass
    return DEFAULT_CFG.copy()

def load_trusted_fingerprint():
    if os.path.exists(TRUST_PATH):
        try:
            with open(TRUST_PATH, "r") as f:
                data = json.load(f)
            return data.get("fingerprint")
        except Exception:
            pass
    return None

def save_trusted_fingerprint(fp_hex):
    try:
        with open(TRUST_PATH, "w") as f:
            json.dump({"fingerprint": fp_hex}, f)
    except Exception as e:
        print("Save trust failed:", e)

def recv_until_delim(sock):
    data = b""
    while True:
        chunk = sock.recv(RECV_BUFFER)
        if not chunk:
            return None
        data += chunk
        if DELIM in data:
            before, _, _ = data.partition(DELIM)
            return before

def send_with_delim(sock, payload_bytes):
    sock.sendall(payload_bytes + DELIM)

class VPNClientApp:
    def __init__(self, root):
        self.cfg = load_config()
        self.trusted_fingerprint = load_trusted_fingerprint()
        self.root = root
        self.root.title("VPN Client Dashboard (Expert Edition)")
        self.root.geometry("850x650")
        self.root.configure(bg="#1E1E1E")
        
        # Set theme colors
        self.colors = {
            "bg": "#1E1E1E",
            "card_bg": "#252526",
            "accent": "#007ACC",
            "accent_hover": "#005A9E",
            "success": "#4EC9B0",
            "warning": "#FFCC02",
            "error": "#F44747",
            "text_primary": "#FFFFFF",
            "text_secondary": "#CCCCCC",
            "border": "#3E3E42"
        }
        
        self.client_socket = None
        self.connected = False
        self.aes_key = None
        self.server_fingerprint = None
        
        # Configure styles
        self.setup_styles()
        self.create_ui()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure custom styles
        style.configure("Custom.TFrame", background=self.colors["bg"])
        style.configure("Card.TFrame", background=self.colors["card_bg"], relief="flat", borderwidth=1)
        style.configure("Title.TLabel", background=self.colors["bg"], foreground=self.colors["text_primary"], font=("Segoe UI", 14, "bold"))
        style.configure("Subtitle.TLabel", background=self.colors["card_bg"], foreground=self.colors["text_secondary"], font=("Segoe UI", 10))
        style.configure("Normal.TLabel", background=self.colors["card_bg"], foreground=self.colors["text_primary"], font=("Segoe UI", 9))
        
        # Button styles
        style.configure("Accent.TButton", 
                       background=self.colors["accent"],
                       foreground=self.colors["text_primary"],
                       focuscolor="none",
                       borderwidth=0,
                       font=("Segoe UI", 9, "bold"))
        style.map("Accent.TButton",
                 background=[('active', self.colors["accent_hover"]),
                           ('pressed', self.colors["accent_hover"])])
        
        style.configure("Danger.TButton", 
                       background=self.colors["error"],
                       foreground=self.colors["text_primary"],
                       focuscolor="none",
                       borderwidth=0,
                       font=("Segoe UI", 9, "bold"))
        style.map("Danger.TButton",
                 background=[('active', "#D13434"),
                           ('pressed', "#D13434")])
        
        # Entry styles
        style.configure("Custom.TEntry", 
                       fieldbackground=self.colors["card_bg"],
                       foreground=self.colors["text_primary"],
                       borderwidth=1,
                       relief="solid")

    def create_ui(self):
        # Header section
        header_frame = ttk.Frame(self.root, style="Custom.TFrame")
        header_frame.pack(fill=tk.X, padx=20, pady=(20, 10))
        
        title_label = ttk.Label(header_frame, text="🔒 VPN Client Expert", style="Title.TLabel")
        title_label.pack(side=tk.LEFT)
        
        # Status indicator
        status_frame = ttk.Frame(header_frame, style="Custom.TFrame")
        status_frame.pack(side=tk.RIGHT)
        
        ttk.Label(status_frame, text="Status:", style="Normal.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        self.status_var = tk.StringVar(value="Disconnected")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, 
                                     style="Normal.TLabel", foreground=self.colors["error"])
        self.status_label.pack(side=tk.LEFT)
        
        # Connection card
        connection_card = ttk.Frame(self.root, style="Card.TFrame")
        connection_card.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(connection_card, text="Server Connection", style="Subtitle.TLabel").grid(row=0, column=0, sticky="w", padx=15, pady=(15, 10))
        
        # Server configuration inputs
        input_frame = ttk.Frame(connection_card, style="Card.TFrame")
        input_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 15))
        
        ttk.Label(input_frame, text="Server IP:", style="Normal.TLabel").grid(row=0, column=0, padx=(0, 5), pady=5, sticky="w")
        self.server_ip_entry = ttk.Entry(input_frame, width=18, style="Custom.TEntry")
        self.server_ip_entry.insert(0, self.cfg["server_ip"])
        self.server_ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        ttk.Label(input_frame, text="Port:", style="Normal.TLabel").grid(row=0, column=2, padx=(20, 5), pady=5, sticky="w")
        self.port_entry = ttk.Entry(input_frame, width=8, style="Custom.TEntry")
        self.port_entry.insert(0, str(self.cfg["server_port"]))
        self.port_entry.grid(row=0, column=3, padx=5, pady=5, sticky="w")
        
        # Connection buttons
        button_frame = ttk.Frame(connection_card, style="Card.TFrame")
        button_frame.grid(row=2, column=0, sticky="w", padx=15, pady=(0, 15))
        
        self.connect_btn = ttk.Button(button_frame, text="Connect", command=self.connect_to_server, style="Accent.TButton", width=12)
        self.connect_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.disconnect_btn = ttk.Button(button_frame, text="Disconnect", command=self.disconnect, style="Danger.TButton", width=12)
        self.disconnect_btn.pack(side=tk.LEFT)
        
        # Request card
        request_card = ttk.Frame(self.root, style="Card.TFrame")
        request_card.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(request_card, text="URL Request", style="Subtitle.TLabel").grid(row=0, column=0, sticky="w", padx=15, pady=(15, 10))
        
        url_frame = ttk.Frame(request_card, style="Card.TFrame")
        url_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 15))
        
        ttk.Label(url_frame, text="Enter URL:", style="Normal.TLabel").grid(row=0, column=0, padx=(0, 10), pady=5, sticky="w")
        self.url_entry = ttk.Entry(url_frame, width=60, style="Custom.TEntry")
        self.url_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        self.send_btn = ttk.Button(url_frame, text="Send Request", command=self.send_request, style="Accent.TButton", width=15)
        self.send_btn.grid(row=0, column=2, padx=(15, 0), pady=5)
        
        url_frame.columnconfigure(1, weight=1)
        
        # Logs card
        logs_card = ttk.Frame(self.root, style="Card.TFrame")
        logs_card.pack(fill=tk.BOTH, expand=True, padx=20, pady=(10, 20))
        
        ttk.Label(logs_card, text="Connection Logs", style="Subtitle.TLabel").grid(row=0, column=0, sticky="w", padx=15, pady=15)
        
        # Create custom text widget with better styling
        self.log_box = scrolledtext.ScrolledText(
            logs_card, 
            wrap=tk.WORD, 
            width=95, 
            height=25,
            bg=self.colors["card_bg"],
            fg=self.colors["text_primary"],
            insertbackground=self.colors["text_primary"],
            selectbackground=self.colors["accent"],
            borderwidth=0,
            relief="flat",
            font=("Consolas", 9)
        )
        self.log_box.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))
        self.log_box.config(state=tk.DISABLED)
        
        logs_card.columnconfigure(0, weight=1)
        logs_card.rowconfigure(1, weight=1)

    def log(self, msg):
        self.log_box.config(state=tk.NORMAL)
        
        # Color coding based on message type
        if msg.startswith("[OK]"):
            tag = "success"
        elif msg.startswith("[ERR]") or "ERROR" in msg:
            tag = "error"
        elif "⚠️" in msg or "Warning" in msg:
            tag = "warning"
        else:
            tag = "normal"
            
        # Configure tags for colored text
        self.log_box.tag_config("success", foreground=self.colors["success"])
        self.log_box.tag_config("error", foreground=self.colors["error"])
        self.log_box.tag_config("warning", foreground=self.colors["warning"])
        self.log_box.tag_config("normal", foreground=self.colors["text_primary"])
        
        # Insert with appropriate tag
        self.log_box.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {msg}\n", tag)
        self.log_box.see(tk.END)
        self.log_box.config(state=tk.DISABLED)

    def compute_fingerprint(self, pubkey_pem):
        digest = hashlib.sha256(pubkey_pem).hexdigest()
        return ":".join([digest[i:i+4] for i in range(0,len(digest),4)])

    def connect_to_server(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.server_ip_entry.get().strip(), int(self.port_entry.get())))
            pubkey_pem = recv_until_delim(sock)
            server_pub = serialization.load_pem_public_key(pubkey_pem)
            self.server_fingerprint = self.compute_fingerprint(pubkey_pem)
            self.log(f"Server fingerprint: {self.server_fingerprint}")
            aes_key = AESGCM.generate_key(bit_length=256)
            enc_key = server_pub.encrypt(
                aes_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            send_with_delim(sock, base64.b64encode(enc_key))
            self.aes_key = aes_key
            self.client_socket = sock
            self.status_var.set("Connected (encrypted)")
            self.status_label.config(foreground=self.colors["success"])
            self.log("Handshake complete — encrypted channel established.")
        except Exception as e:
            messagebox.showerror("Connection failed", str(e))

    def disconnect(self):
        if self.client_socket:
            self.client_socket.close()
        self.client_socket = None
        self.aes_key = None
        self.status_var.set("Disconnected")
        self.status_label.config(foreground=self.colors["error"])
        self.log("Disconnected from server.")

    def send_request(self):
        if not self.client_socket or not self.aes_key:
            messagebox.showwarning("Warning", "Not connected!")
            return
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Warning", "Enter a URL.")
            return
        threading.Thread(target=self._send_thread, args=(url,), daemon=True).start()

    def _send_thread(self, url):
        aesgcm = AESGCM(self.aes_key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, url.encode(), None)
        send_with_delim(self.client_socket, base64.b64encode(nonce + ct))

        data = b""
        while True:
            part = self.client_socket.recv(RECV_BUFFER)
            if not part:
                self.log("Connection closed by server.")
                self.disconnect()
                return
            data += part
            if DELIM in data:
                break
        before, _, _ = data.partition(DELIM)
        dec = base64.b64decode(before)
        nonce, ct = dec[:12], dec[12:]
        plain = AESGCM(self.aes_key).decrypt(nonce, ct, None)
        msg = plain.decode(errors="ignore")

        # Structured Expert-Level Output
        if msg.startswith("SUCCESS"):
            _, trace, status, size, latency = msg.split("|")
            self.log(f"[OK]  URL={url}")
            self.log(f"      STATUS={status}  SIZE={size}  LATENCY={latency}  TRACE={trace}")
        elif msg.startswith("ERROR"):
            _, trace, etype, emsg, latency = msg.split("|", 4)
            self.log(f"[ERR] URL={url}")
            self.log(f"      TYPE={etype}  MESSAGE={emsg}  LATENCY={latency}  TRACE={trace}")
        else:
            self.log(f"⚠️ Unknown message: {msg}")

if __name__ == "__main__":
    root = tk.Tk()
    app = VPNClientApp(root)
    root.protocol("WM_DELETE_WINDOW", app.disconnect)
    root.mainloop()
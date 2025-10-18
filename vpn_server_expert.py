import socket
import threading
import requests
import json
import os
import base64
import time
import uuid

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configuration
CFG_PATH = "config.json"
DEFAULT_CFG = {
    "server_ip": "0.0.0.0",
    "server_port": 8080,
    "request_timeout_seconds": 8
}

def load_config():
    if os.path.exists(CFG_PATH):
        try:
            with open(CFG_PATH, "r") as f:
                cfg = json.load(f)
            return {
                "server_ip": cfg.get("server_ip", DEFAULT_CFG["server_ip"]),
                "server_port": int(cfg.get("server_port", DEFAULT_CFG["server_port"])),
                "request_timeout_seconds": int(cfg.get("request_timeout_seconds", DEFAULT_CFG["request_timeout_seconds"]))
            }
        except Exception as e:
            print("Config load error, using defaults:", e)
    return DEFAULT_CFG

CFG = load_config()
SERVER_HOST = CFG["server_ip"]
SERVER_PORT = CFG["server_port"]
REQUEST_TIMEOUT = CFG["request_timeout_seconds"]

DELIM = b"<<END>>"
RECV_BUFFER = 4096

# Generate RSA keypair once at startup
RSA_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_PUBLIC_PEM = RSA_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

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

def encrypt_and_frame(aes_key: bytes, plaintext_str: str) -> bytes:
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext_str.encode("utf-8"), associated_data=None)
    return base64.b64encode(nonce + ct)

def handle_client(client_socket, address):
    print(f"[+] Client connected from {address}")
    aes_key = None
    try:
        # Step 1: Send server RSA public key
        send_with_delim(client_socket, RSA_PUBLIC_PEM)

        # Step 2: Receive AES key
        enc_key_b64 = recv_until_delim(client_socket)
        if enc_key_b64 is None:
            print("[!] Client disconnected before sending AES key")
            return

        enc_key = base64.b64decode(enc_key_b64)
        aes_key = RSA_PRIVATE_KEY.decrypt(
            enc_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        print(f"[+] AES key established with {address} ({len(aes_key)} bytes)")

        # Step 3: Handle encrypted requests
        while True:
            enc_msg_b64 = recv_until_delim(client_socket)
            if enc_msg_b64 is None:
                break

            try:
                enc_msg = base64.b64decode(enc_msg_b64)
                nonce = enc_msg[:12]
                ciphertext = enc_msg[12:]
                aesgcm = AESGCM(aes_key)
                plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
                target_url = plaintext.decode("utf-8", errors="ignore").strip()
            except Exception as e:
                err_text = f"ERROR|{uuid.uuid4().hex[:8]}|decrypt_failed|{str(e)}|0 ms"
                send_with_delim(client_socket, encrypt_and_frame(aes_key, err_text))
                continue

            if not target_url:
                continue

            print(f"[REQ] {address} → {target_url}")
            start_time = time.time()
            trace_id = str(uuid.uuid4())[:8]

            try:
                resp = requests.get(target_url, timeout=REQUEST_TIMEOUT)
                latency = int((time.time() - start_time) * 1000)
                msg = f"SUCCESS|{trace_id}|HTTP {resp.status_code}|{len(resp.content)} bytes|{latency} ms"
            except Exception as e:
                latency = int((time.time() - start_time) * 1000)
                msg = f"ERROR|{trace_id}|fetch_failed|{str(e)}|{latency} ms"

            out_bytes = encrypt_and_frame(aes_key, msg)
            send_with_delim(client_socket, out_bytes)

    except Exception as e:
        print(f"[!] Client handler exception: {e}")
    finally:
        client_socket.close()
        print(f"[-] Client disconnected: {address}")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((SERVER_HOST, SERVER_PORT))
    server.listen(5)
    print(f"[*] Encrypted VPN Server running on {SERVER_HOST}:{SERVER_PORT}")

    try:
        while True:
            client, addr = server.accept()
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[!] Server shutting down")
    finally:
        server.close()

if __name__ == "__main__":
    main()

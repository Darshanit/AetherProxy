# AetherProxy
Perfect ✅ — here’s a **complete, polished, and professional README.md** that’s suitable for GitHub, a portfolio, or documentation use.

It includes full technical context, usage instructions, architecture overview, visuals-in-words (since we can’t embed images here), and professional formatting.

---

```markdown
# 🔐 Encrypted Client–Server Communication System (Python)

> **A custom-built, end-to-end encrypted communication system using RSA and AES-GCM — designed to simulate a VPN-like secure tunnel for learning and experimentation.**

---

## 📘 Overview

This project demonstrates how to build a **secure encrypted channel** between a **Python client** and a **Python server**, using **modern cryptographic techniques** (RSA + AES-GCM).  
It’s not a full VPN, but it **mimics a VPN’s encryption and trust model** for sending data securely — specifically, encrypted **HTTP request/response exchanges**.

The system consists of two main components:

- 🖥️ **`vpn_server.py`** — Acts as the secure gateway.  
  It accepts encrypted connections, performs a key exchange, decrypts requests, fetches web content, and returns structured encrypted results.

- 💻 **`vpn_client.py`** — A Tkinter-based GUI application.  
  It connects securely to the server, encrypts URL requests, and displays results such as HTTP status, latency, and data size in a clean, real-time log view.

---

## ⚙️ Core Features

| Feature                         | Description                                                              |
| ------------------------------- | ------------------------------------------------------------------------ |
| 🔐 **AES-256-GCM Encryption**   | Ensures confidentiality, integrity, and authenticity of transmitted data |
| 🗝️ **RSA-2048 Key Exchange**    | Securely exchanges the AES session key between client and server         |
| 🧩 **Fingerprint Trust System** | Detects if the server’s RSA key changes (prevents impersonation)         |
| 🧾 **Structured Log Output**    | Displays rich logs with timestamps, HTTP status, latency, and trace IDs  |
| 🕒 **Performance Metrics**      | Includes latency tracking and payload size                               |
| 🪶 **Lightweight GUI**          | Built with Tkinter for an intuitive dashboard experience                 |
| ⚠️ **Key Change Detection**     | Warns user if the server’s identity has changed since last connection    |

---

## 🧠 Architecture Overview

Here’s how the system works internally:

### 1️⃣ Handshake Phase (Key Exchange)

1. The **client** connects to the **server** via TCP.
2. The **server** sends its RSA **public key**.
3. The **client** verifies or stores the server’s **fingerprint** (SHA-256 hash of the key).
4. The **client** generates a random **AES-256 key** and encrypts it using RSA-OAEP.
5. The **server** decrypts the AES key using its **private key**.
6. Both sides now share the same AES key — a secure channel is established.

### 2️⃣ Data Exchange Phase (Encrypted Requests)

1. The client encrypts a **URL request** (e.g., `https://google.com`) using AES-GCM.
2. The server decrypts it, fetches the web page via `requests.get()`, and records:
   - HTTP status (e.g., `HTTP 200`)
   - Response body size
   - Latency (in milliseconds)
   - A short **trace ID** for request correlation
3. The server encrypts and sends back a structured summary:
```

SUCCESS|a9c42d71|HTTP 200|13142 bytes|188 ms

```
4. The client decrypts and logs it as:
```

[OK] URL=[https://google.com](https://google.com)
STATUS=HTTP 200 SIZE=13142 bytes LATENCY=188 ms TRACE=a9c42d71

```

### 3️⃣ Trust Verification (Security)
- The first time the client connects, it shows the server’s fingerprint:
```

Server fingerprint: 08bf:f803:7e69:0903:6345:a81b:8243:d851:...

```
- You can click **“Trust this key”** to save it in `trusted_server.json`.
- On future connections, if the key changes, the client warns you immediately — similar to how SSH warns about changed host fingerprints.

---

## 🧩 Project Structure

```

📦 encrypted_vpn_project/
├── vpn_client.py # Client application with GUI + encryption
├── vpn_server.py # Secure server handling encrypted requests
├── config.json # Optional configuration file
├── trusted_server.json # Stores trusted server fingerprint
└── README.md # Project documentation

````

---

## 🛠️ Installation

### 1️⃣ Requirements
- Python **3.8+**
- The following Python libraries:
  ```bash
  pip install cryptography requests
````

> `tkinter` comes preinstalled on most systems (Linux, Windows, macOS).

---

## 🚀 Usage Guide

### Step 1. Start the Server

On your host or VPS:

```bash
python vpn_server.py
```

Expected console output:

```
[*] Encrypted VPN Server running on 0.0.0.0:8080
```

### Step 2. Start the Client

On your local machine:

```bash
python vpn_client.py
```

A GUI window will open.

1. Enter the server IP and port (default 8080).
2. Click **Connect** to establish the encrypted handshake.
3. The GUI will display:

   ```
   Server fingerprint: <SHA256 Fingerprint>
   Handshake complete — encrypted channel established.
   ```

4. Enter a URL (e.g., `https://google.com`) and click **Send**.
5. View structured logs in the live log window.

---

## 🧾 Example Output

### 🧠 Client (GUI Log)

```
21:15:33 - Server fingerprint: 08bf:f803:7e69:0903:6345:a81b:8243:d851
21:15:33 - Handshake complete — encrypted channel established.
21:15:47 - [OK]  URL=https://google.com
21:15:47 -       STATUS=HTTP 200  SIZE=13142 bytes  LATENCY=188 ms  TRACE=a9c42d71
```

### 🖥️ Server (Console)

```
[+] Client connected from ('127.0.0.1', 52134)
[REQ] ('127.0.0.1', 52134) → https://google.com
[TRACE a9c42d71] SUCCESS HTTP 200 (13142 bytes, 188 ms)
[-] Client disconnected: ('127.0.0.1', 52134)
```

---

## 📊 Log Fields Explained

| Field         | Description                                                |
| ------------- | ---------------------------------------------------------- |
| `URL`         | The requested web resource sent by the client              |
| `STATUS`      | HTTP response status code (e.g., `HTTP 200`)               |
| `SIZE`        | Size of fetched web page (in bytes)                        |
| `LATENCY`     | Round-trip time (ms) between request and response          |
| `TRACE`       | Unique trace ID (per request) for correlation between logs |
| `FINGERPRINT` | SHA-256 hash of server’s RSA public key                    |

---

## 🔐 Security Design

| Mechanism                   | Purpose                                                  |
| --------------------------- | -------------------------------------------------------- |
| **RSA-OAEP (2048-bit)**     | Securely transmits the AES key during handshake          |
| **AES-GCM (256-bit)**       | Provides authenticated encryption for all data           |
| **SHA-256 Fingerprints**    | Detects key changes (prevents man-in-the-middle attacks) |
| **Base64 Framing**          | Safely transports binary ciphertext over TCP             |
| **Unique Nonce (12 bytes)** | Prevents replay attacks per AES-GCM encryption           |

---

## ⚠️ Limitations

While it mimics some behaviors of a VPN, this project is **not a full VPN**:

| Feature                           | Status | Description                                  |
| --------------------------------- | ------ | -------------------------------------------- |
| Network-level tunneling (Layer 3) | ❌     | Operates only at application layer           |
| System-wide routing               | ❌     | Encrypts only requests sent from this client |
| Multiple client sessions          | ⚙️     | Possible but single-threaded for simplicity  |
| Client authentication             | ⚠️     | Basic trust system only (no login)           |
| Full webpage rendering            | ❌     | Only fetches HTML data and metadata          |

---

## 🧭 Educational Value

This project is an excellent **learning resource** for:

- Cryptography (RSA, AES-GCM, nonces, fingerprints)
- Secure communication protocols
- Client–server design patterns
- GUI + socket integration
- Logging, tracing, and observability in networked systems

---

## 🧰 Tech Stack

| Component     | Library                                                  |
| ------------- | -------------------------------------------------------- |
| Cryptography  | [`cryptography`](https://pypi.org/project/cryptography/) |
| HTTP Requests | [`requests`](https://pypi.org/project/requests/)         |
| GUI Framework | `tkinter` (built-in)                                     |
| Language      | Python 3.8+                                              |
| Platform      | Cross-platform (Windows, macOS, Linux)                   |

---

## 🧱 Future Enhancements

- [ ] Add **mutual authentication** (client-side certificates or tokens)
- [ ] Include **JSON-based telemetry** for analytics/log export
- [ ] Support **multiple concurrent clients**
- [ ] Extend to **UDP + DTLS** for lower-latency communication
- [ ] Build a **Layer 3 version** using TUN interfaces (see `vpn_tunnel_project`)
- [ ] Add **configurable encryption modes** (ChaCha20, AES-CBC, etc.)

---

## 🧾 License

This project is released for **educational and research purposes only.**
It should not be used for production or security-critical environments.

---

## 👨‍💻 Author

**Developed by:** _DancinRythm_
**Purpose:** Educational experiment in cryptography, secure networking, and protocol design.
**Version:** 2.0 (Expert Edition)

---

> _"Security through understanding, not obscurity."_
> — Designed for learners who want to go beyond `https://` and explore how encryption really works under the hood.

```

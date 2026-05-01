# Secure File Transfer Protocol (SFTP-Hybrid)

A research implementation of a hybrid cryptographic file transfer protocol built in Python. Combines **RSA-2048** for key exchange and **AES-256-CBC** for file encryption, with **HMAC-SHA256** integrity verification — mirroring the design principles of TLS while exposing the underlying mechanics.

> **Academic Project** — Built as part of a cryptography and network security research initiative. Guided by a faculty advisor in cryptography.

---

## How It Works

The protocol operates in four phases over a raw TCP socket connection:

```
Receiver                                          Sender
────────                                          ──────
Generate RSA key pair
Send public key  ────────── HELLO ──────────────► 
                                                  Generate AES-256 session key
                                                  Generate HMAC-SHA256 key
                                                  Encrypt both keys with RSA public key
             ◄────────── KEY_EXCHANGE ────────── Send encrypted key bundle
Decrypt bundle with private key
Recover AES key + HMAC key
             ◄────────── FILE_HEADER ────────── Send filename, size, IV, HMAC digest
             ◄──────── FILE_CHUNK × N ────────── Stream encrypted 64KB chunks
             ◄────────── TRANSFER_END ─────────── Signal completion
Decrypt file with AES key
Verify HMAC integrity
Send ACK ────────────── ACK ───────────────────►
```

**Key design decisions:**
- RSA encrypts only the AES session key (~68 bytes), never the file itself
- AES-256-CBC encrypts the file in 64 KB chunks — supports files of any size including 30 GB+
- A fresh AES session key and IV are generated per transfer (session-level forward secrecy)
- HMAC uses a separate key from AES (encrypt-then-MAC approach)
- `hmac.compare_digest()` prevents timing side-channel attacks during verification

---

## Project Structure

```
secure-file-transfer/
│
├── exceptions.py       — Custom exception hierarchy
├── keygen.py           — RSA-2048 key pair generator (CLI)
├── crypto_utils.py     — Cryptographic engine (RSA, AES, HMAC, SHA-256)
├── protocol.py         — Packet framing and handshake protocol
├── logger.py           — Session logging with JSON transfer history
├── sender.py           — Socket server + CLI (sends the file)
├── receiver.py         — Socket client + CLI (receives the file)
│
├── keys/               — RSA key pairs (gitignored — never commit)
├── logs/               — Transfer session logs (gitignored)
│
└── tests/
    ├── test_crypto.py  — Unit tests for crypto engine
    └── test_protocol.py — Unit tests for packet framing
```

---

## Security Properties

| Property | Implementation |
|---|---|
| Confidentiality | AES-256-CBC — symmetric encryption of file data |
| Key exchange security | RSA-2048 with OAEP-SHA256 padding |
| Integrity | HMAC-SHA256 with a dedicated key |
| Timing attack resistance | `hmac.compare_digest()` for constant-time comparison |
| Key isolation | AES key and HMAC key are always separate |
| File type agnostic | Operates on raw bytes — any file format supported |
| Large file support | 64 KB chunked streaming — no RAM limit |

---

## Installation

**Requirements:** Python 3.10+

```bash
# Clone the repository
git https://github.com/Tushar-S-nath/secure-file-transfer.git
cd secure-file-transfer

# Install the only dependency
pip install pycryptodome
```

---

## Quick Start

### Step 1 — Generate RSA key pairs (both parties)

```bash
# Sender generates their keys
python keygen.py --name sender

# Receiver generates their keys
python keygen.py --name receiver

# Keys are saved to keys/
# keys/sender_private.pem   ← never share this
# keys/sender_public.pem    ← share this with the other party
```

### Step 2 — Run on same network

```bash
# On receiver's machine — start listening
python receiver.py --key receiver --port 9999

# On sender's machine — send a file
python sender.py --file document.pdf --host 192.168.1.X --port 9999 --key sender
```

### Step 3 — Run across different networks (using ngrok)

```bash
# On receiver's machine
ngrok tcp 9999
# Copy the address: tcp://X.tcp.ngrok.io:XXXXX

python receiver.py --key receiver --port 9999

# On sender's machine
python sender.py --file document.pdf --host X.tcp.ngrok.io --port XXXXX --key sender
```

---

## Running the Self-Tests

```bash
# Test the crypto engine (RSA, AES, HMAC round-trips)
python crypto_utils.py

# Test the packet framing protocol
python protocol.py

# View past transfer history
python logger.py
```

Expected output for crypto test:
```
[*] Running crypto self-test ...

    AES key  : ...  (32 bytes)
    IV       : ...  (16 bytes)
    HMAC key : ...  (32 bytes)

    Bundle size      : 68 bytes
    RSA ciphertext   : ...  (256 bytes)
    RSA round-trip   : PASSED ✓
    AES round-trip   : PASSED ✓  (200 KB payload)
    HMAC verify      : PASSED ✓
    SHA-256 checksum : ...

[✓] All crypto self-tests passed. Engine is ready.
```

---

## Comparison with TLS

This project implements a simplified version of the TLS 1.2 RSA key exchange mode:

| Feature | This Project | TLS 1.2 (RSA mode) |
|---|---|---|
| Key exchange | RSA-2048 OAEP | RSA (certificates) |
| Symmetric encryption | AES-256-CBC | AES-256-GCM or CBC |
| Integrity | HMAC-SHA256 | HMAC or AEAD |
| Authentication | None (no certificates) | X.509 certificates |
| Forward secrecy | Session-level only | Full (with DHE/ECDHE) |
| Replay protection | None | Sequence numbers |

The main limitation compared to TLS is the absence of certificate-based authentication, meaning this protocol is vulnerable to man-in-the-middle attacks if the public key exchange is not verified out-of-band.

---

## References

1. Rivest, R., Shamir, A., & Adleman, L. (1978). *A Method for Obtaining Digital Signatures and Public-Key Cryptosystems.* Communications of the ACM, 21(2), 120–126.
2. NIST. (2023). *Advanced Encryption Standard (AES).* FIPS Publication 197. https://csrc.nist.gov/pubs/fips/197/final
3. Zou, L. et al. (2020). *Hybrid Encryption Algorithm Based on AES and RSA in File Encryption.* Springer LNEE.
4. Al-Tudjman, F. et al. (2017). *Secure Data Encryption Through a Combination of AES, RSA and HMAC.* ETASR, 7(4).
5. Sy, E. et al. (2019). *Towards Forward Secure Internet Traffic.* arXiv:1907.00231.
6. Nikzad, M. & Atas, K. (2024). *When RSA Fails: Exploiting Prime Selection Vulnerabilities.* arXiv:2512.22720.

---

## Authors

-  Tushar Subhra Devanath — Cryptographic engine, key generation, protocol design, session logging
- **[CR]** — Network layer, sender/receiver CLI, unit tests

**Academic Advisor:** [Professor's Name], Department of [Department], [University]

---

## License

MIT License — free to use for educational and research purposes.
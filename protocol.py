#!/usr/bin/env python3
"""
protocol.py — Packet Framing & Handshake Protocol
Defines the wire format and handshake sequence for the Secure File Transfer Protocol.

Packet structure (every packet sent over the socket):
  [4 bytes — packet type][4 bytes — payload length][N bytes — payload]

Handshake sequence:
  1. Receiver  →  Sender   : HELLO (sends receiver's public key)
  2. Sender    →  Receiver : KEY_EXCHANGE (sends RSA-encrypted AES+HMAC bundle)
  3. Sender    →  Receiver : FILE_HEADER (filename, file size, total chunks, HMAC)
  4. Sender    →  Receiver : FILE_CHUNK × N (encrypted file data)
  5. Sender    →  Receiver : TRANSFER_END (signals completion)
  6. Receiver  →  Sender   : ACK or ERROR

Part of the Secure File Transfer Protocol (SFTP-Hybrid) project.
"""

import os
import json
import socket
import struct
from enum import IntEnum
from typing import Tuple, Optional

from exceptions import PacketError, HandshakeError, SessionError


# ── Constants ──────────────────────────────────────────────────────────────────
PROTOCOL_VERSION  = 1
HEADER_SIZE       = 8          # 4 bytes type + 4 bytes length
MAX_PACKET_SIZE   = 67108864   # 64 MB hard cap per packet (safety limit)
SOCKET_TIMEOUT    = 30         # seconds before a recv/send times out
RECV_BUFFER       = 4096       # socket receive buffer size


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — PACKET TYPES
# ══════════════════════════════════════════════════════════════════════════════

class PacketType(IntEnum):
    """
    Every packet sent over the wire starts with one of these 4-byte type codes.
    Using IntEnum means we can pack/unpack them directly with struct.
    """
    HELLO         = 0x01   # receiver → sender: "I am here, here is my public key"
    KEY_EXCHANGE  = 0x02   # sender → receiver: RSA-encrypted AES+HMAC bundle
    FILE_HEADER   = 0x03   # sender → receiver: file metadata (name, size, chunks, hmac)
    FILE_CHUNK    = 0x04   # sender → receiver: one encrypted 64KB chunk
    TRANSFER_END  = 0x05   # sender → receiver: all chunks sent
    ACK           = 0x06   # receiver → sender: transfer verified successfully
    ERROR         = 0x07   # either direction: something went wrong
    PING          = 0x08   # keepalive ping
    PONG          = 0x09   # keepalive pong response


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — PACKET FRAMING (Low-level send/recv)
# ══════════════════════════════════════════════════════════════════════════════

def pack_packet(ptype: PacketType, payload: bytes) -> bytes:
    """
    Serialize a packet into wire format:
      [4-byte type (big-endian)][4-byte payload length (big-endian)][payload]

    Args:
        ptype   : one of the PacketType enum values
        payload : raw bytes to send as the packet body

    Returns:
        Complete packet bytes ready to send over the socket
    """
    if len(payload) > MAX_PACKET_SIZE:
        raise PacketError(
            "Payload exceeds maximum packet size.",
            details=f"Size: {len(payload)} bytes, limit: {MAX_PACKET_SIZE} bytes"
        )
    header = struct.pack(">II", int(ptype), len(payload))
    return header + payload


def unpack_header(header_bytes: bytes) -> Tuple[PacketType, int]:
    """
    Parse the 8-byte packet header to get packet type and payload length.

    Args:
        header_bytes : exactly 8 bytes read from the socket

    Returns:
        (PacketType, payload_length)
    """
    if len(header_bytes) != HEADER_SIZE:
        raise PacketError(
            "Malformed packet header.",
            details=f"Expected {HEADER_SIZE} bytes, got {len(header_bytes)}"
        )
    try:
        type_code, length = struct.unpack(">II", header_bytes)
        return PacketType(type_code), length
    except (struct.error, ValueError) as e:
        raise PacketError("Failed to parse packet header.", details=str(e))


def send_packet(sock: socket.socket, ptype: PacketType, payload: bytes) -> None:
    """
    Frame and send a complete packet over a socket.
    Uses sendall() to guarantee the full packet is sent even on slow connections.

    Args:
        sock    : connected socket object
        ptype   : packet type
        payload : raw bytes payload
    """
    try:
        packet = pack_packet(ptype, payload)
        sock.sendall(packet)
    except (OSError, BrokenPipeError) as e:
        raise SessionError("Failed to send packet.", details=str(e))


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """
    Receive exactly n bytes from the socket, blocking until all arrive.
    This is necessary because TCP is a stream protocol — a single recv()
    call may return fewer bytes than requested.

    Args:
        sock : connected socket
        n    : exact number of bytes to receive

    Returns:
        Exactly n bytes

    Raises:
        SessionError if the connection is closed before n bytes arrive
    """
    data = b""
    while len(data) < n:
        try:
            chunk = sock.recv(min(RECV_BUFFER, n - len(data)))
            if not chunk:
                raise SessionError(
                    "Connection closed unexpectedly.",
                    details=f"Expected {n} bytes, received {len(data)}"
                )
            data += chunk
        except OSError as e:
            raise SessionError("Socket receive error.", details=str(e))
    return data


def recv_packet(sock: socket.socket) -> Tuple[PacketType, bytes]:
    """
    Receive one complete packet from the socket.
    First reads the 8-byte header, then reads exactly payload_length bytes.

    Returns:
        (PacketType, payload_bytes)
    """
    header  = recv_exact(sock, HEADER_SIZE)
    ptype, length = unpack_header(header)

    if length > MAX_PACKET_SIZE:
        raise PacketError(
            "Incoming packet exceeds size limit — possible attack.",
            details=f"Claimed size: {length} bytes"
        )

    payload = recv_exact(sock, length) if length > 0 else b""
    return ptype, payload


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — PAYLOAD BUILDERS & PARSERS
# ══════════════════════════════════════════════════════════════════════════════

def build_hello(public_key_pem: bytes) -> bytes:
    """HELLO payload — just the raw PEM bytes of the receiver's public key."""
    return public_key_pem


def parse_hello(payload: bytes) -> bytes:
    """Parse HELLO payload → returns public key PEM bytes."""
    if not payload.startswith(b"-----BEGIN"):
        raise HandshakeError(
            "Invalid HELLO payload — not a valid PEM key.",
            details=f"First bytes: {payload[:20]}"
        )
    return payload


def build_key_exchange(encrypted_bundle: bytes) -> bytes:
    """KEY_EXCHANGE payload — the RSA-encrypted (AES key + HMAC key) bundle."""
    return encrypted_bundle


def parse_key_exchange(payload: bytes) -> bytes:
    """Parse KEY_EXCHANGE payload → returns encrypted bundle bytes."""
    return payload


# ── Mutual authentication variants ──────────────────────────────────────
# NEW, separate payload formats — build_hello/parse_hello and
# build_key_exchange/parse_key_exchange above are left completely
# unchanged (still used when a transfer doesn't opt into mutual auth via
# --peer). These carry an identity name and, for KEY_EXCHANGE, a
# signature proving the sender's identity. See crypto_utils.py's
# "Identity: Fingerprinting and RSA Signatures" section for the
# verification side.

def build_hello_named(public_key_pem: bytes, name: str, challenge_nonce: bytes) -> bytes:
    """
    Named HELLO payload for mutual authentication + replay protection.
    Carries the sender's public key, their claimed identity name (so
    the receiving side can verify the presented key against a locally
    trusted copy — crypto_utils.verify_peer_identity), AND a fresh
    challenge_nonce generated for THIS connection attempt only.

    The other side must bind challenge_nonce into its signed
    key-exchange bundle (see crypto_utils.generate_challenge_nonce for
    why this prevents replaying a captured old session).
    """
    payload = {
        "name": name,
        "public_key": public_key_pem.decode("utf-8"),
        "challenge_nonce": challenge_nonce.hex(),
    }
    return json.dumps(payload).encode("utf-8")


def parse_hello_named(payload: bytes) -> dict:
    """
    Parse a named HELLO payload (see build_hello_named).

    Returns:
        {"name": str, "public_key": bytes, "challenge_nonce": bytes}
    """
    try:
        obj = json.loads(payload.decode("utf-8"))
        name = obj["name"]
        public_key_pem = obj["public_key"].encode("utf-8")
        challenge_nonce = bytes.fromhex(obj["challenge_nonce"])
        if not public_key_pem.startswith(b"-----BEGIN"):
            raise ValueError("public_key field is not a valid PEM key")
        if len(challenge_nonce) < 16:
            raise ValueError("challenge_nonce too short — expected 16 bytes")
        return {"name": name, "public_key": public_key_pem, "challenge_nonce": challenge_nonce}
    except (json.JSONDecodeError, KeyError, ValueError, UnicodeDecodeError) as e:
        raise HandshakeError("Invalid named HELLO payload.", details=str(e))


def build_key_exchange_signed(encrypted_bundle: bytes, sender_name: str, signature: bytes) -> bytes:
    """
    KEY_EXCHANGE payload carrying a signature that proves the sender's
    identity, for mutual authentication. The sender signs
    `encrypted_bundle` with its OWN private key
    (crypto_utils.sign_data); the receiver verifies that signature
    against the LOCALLY trusted public key for `sender_name` — the
    sender's public key itself is never transmitted here, deliberately,
    so the receiver can only ever trust a key it already had on file.

    Wire format (binary, not JSON — encrypted_bundle and signature are
    both raw high-entropy bytes, which don't round-trip cleanly through
    JSON without base64 overhead):
        [4-byte name length][name utf-8]
        [4-byte signature length][signature]
        [encrypted_bundle — remainder of payload]
    """
    name_bytes = sender_name.encode("utf-8")
    out  = struct.pack(">I", len(name_bytes)) + name_bytes
    out += struct.pack(">I", len(signature)) + signature
    out += encrypted_bundle
    return out


def parse_key_exchange_signed(payload: bytes) -> dict:
    """
    Parse a signed KEY_EXCHANGE payload (see build_key_exchange_signed).

    Returns:
        {"sender_name": str, "signature": bytes, "encrypted_bundle": bytes}
    """
    try:
        offset = 0
        name_len = struct.unpack(">I", payload[offset:offset + 4])[0]
        offset += 4
        sender_name = payload[offset:offset + name_len].decode("utf-8")
        offset += name_len

        sig_len = struct.unpack(">I", payload[offset:offset + 4])[0]
        offset += 4
        signature = payload[offset:offset + sig_len]
        offset += sig_len

        encrypted_bundle = payload[offset:]
        if not sender_name or not signature or not encrypted_bundle:
            raise ValueError("One or more fields empty in signed KEY_EXCHANGE payload")

        return {
            "sender_name": sender_name,
            "signature": signature,
            "encrypted_bundle": encrypted_bundle,
        }
    except (struct.error, UnicodeDecodeError, IndexError, ValueError) as e:
        raise HandshakeError("Invalid signed KEY_EXCHANGE payload.", details=str(e))


def build_file_header(
    filename: str,
    file_size: int,
    total_chunks: int,
    iv: bytes = None,
    hmac_digest: bytes = None,
    chunk_size: int = 65536,
    cipher_mode: str = "AES-256-CBC",
    nonce: bytes = None,
) -> bytes:
    """
    FILE_HEADER payload — JSON-encoded file metadata.
    Sent before any file chunks so the receiver knows what to expect.

    Fields:
        filename     : original filename (basename only, no path)
        file_size    : total file size in bytes
        total_chunks : how many FILE_CHUNK packets to expect
        version      : protocol version number
        chunk_size   : plaintext bytes per chunk the sender used
        cipher_mode  : "AES-256-CBC" (default) or "AES-256-GCM"
        iv           : AES-CBC initialization vector, hex-encoded.
                       Required for cipher_mode="AES-256-CBC".
        hmac         : whole-file HMAC-SHA256, hex-encoded.
                       Required for cipher_mode="AES-256-CBC".
                       Not used for GCM (each chunk self-authenticates).
        nonce        : 8-byte GCM session base nonce, hex-encoded.
                       Required for cipher_mode="AES-256-GCM".

    Backward compatible: existing callers that only pass iv/hmac_digest
    (not cipher_mode/nonce) get cipher_mode="AES-256-CBC" by default,
    identical to the original CBC-only header shape.
    """
    if cipher_mode == "AES-256-CBC" and (iv is None or hmac_digest is None):
        raise ValueError("AES-256-CBC header requires both iv and hmac_digest.")
    if cipher_mode == "AES-256-GCM" and nonce is None:
        raise ValueError("AES-256-GCM header requires nonce.")

    meta = {
        "filename"     : os.path.basename(filename),
        "file_size"    : file_size,
        "total_chunks" : total_chunks,
        "version"      : PROTOCOL_VERSION,
        "chunk_size"   : chunk_size,
        "cipher_mode"  : cipher_mode,
        "iv"           : iv.hex() if iv is not None else None,
        "hmac"         : hmac_digest.hex() if hmac_digest is not None else None,
        "nonce"        : nonce.hex() if nonce is not None else None,
    }
    return json.dumps(meta).encode("utf-8")


def parse_file_header(payload: bytes) -> dict:
    """
    Parse FILE_HEADER payload → returns metadata dict.
    Decodes hex fields back to bytes (only the ones actually present —
    a GCM header has no iv/hmac, a CBC header has no nonce).
    "cipher_mode" defaults to "AES-256-CBC" if absent, for headers built
    before this field existed.

    Validates that the fields REQUIRED for the header's cipher_mode are
    actually present, even though individual fields are optional at the
    JSON level (since which ones are required depends on cipher_mode).
    """
    try:
        meta = json.loads(payload.decode("utf-8"))

        for required in ("filename", "file_size", "total_chunks"):
            if required not in meta:
                raise KeyError(required)

        cipher_mode = meta.setdefault("cipher_mode", "AES-256-CBC")
        if cipher_mode == "AES-256-CBC":
            if not meta.get("iv") or not meta.get("hmac"):
                raise KeyError("iv/hmac (required for AES-256-CBC)")
        elif cipher_mode == "AES-256-GCM":
            if not meta.get("nonce"):
                raise KeyError("nonce (required for AES-256-GCM)")

        if meta.get("iv"):
            meta["iv"] = bytes.fromhex(meta["iv"])
        if meta.get("hmac"):
            meta["hmac"] = bytes.fromhex(meta["hmac"])
        if meta.get("nonce"):
            meta["nonce"] = bytes.fromhex(meta["nonce"])
        return meta
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        raise PacketError("Failed to parse FILE_HEADER payload.", details=str(e))


def build_file_chunk(encrypted_chunk: bytes) -> bytes:
    """FILE_CHUNK payload — raw encrypted bytes of one 64 KB chunk."""
    return encrypted_chunk


def build_transfer_end() -> bytes:
    """TRANSFER_END payload — empty, just signals that all chunks were sent."""
    return b""


def build_ack(message: str = "Transfer verified successfully.") -> bytes:
    """ACK payload — a UTF-8 confirmation message."""
    return message.encode("utf-8")


def build_error(message: str) -> bytes:
    """ERROR payload — a UTF-8 error description."""
    return message.encode("utf-8")


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — HIGH-LEVEL HANDSHAKE HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def perform_sender_handshake(
    sock: socket.socket,
    bundle_or_builder
) -> None:
    """
    Sender side of the handshake:
      1. Wait for HELLO from receiver, extracting their public key PEM.
      2. Obtain the RSA-encrypted (AES key + HMAC key) bundle.
      3. Send KEY_EXCHANGE with the encrypted bundle.

    `bundle_or_builder` accepts two forms, for two different callers:

      * bytes — an already-encrypted bundle. This is the original API,
        for a caller that (for whatever reason) already has the
        receiver's public key and pre-built the bundle before calling
        this function. Used by the existing test suite.

      * callable — a function `builder(receiver_pubkey_pem: bytes) ->
        bytes`. This lets a caller build the bundle *after* this
        function receives the real HELLO and extracts the receiver's
        public key, without the caller needing its own separate
        recv_packet() call for HELLO (which would otherwise try to
        read a second HELLO that's never sent, since only one is ever
        transmitted). sender.py uses this form.

    Args:
        sock               : connected socket to the receiver
        bundle_or_builder  : RSA-encrypted bundle bytes, or a callable
                              as described above.
    """
    # Step 1 — Expect HELLO, extracting the receiver's public key PEM
    # (needed for the callable form; harmless to parse either way).
    ptype, hello_payload = recv_packet(sock)
    if ptype != PacketType.HELLO:
        raise HandshakeError(
            "Expected HELLO from receiver.",
            details=f"Got packet type: {ptype}"
        )

    if callable(bundle_or_builder):
        receiver_pubkey_pem = parse_hello(hello_payload)
        encrypted_bundle = bundle_or_builder(receiver_pubkey_pem)
    else:
        encrypted_bundle = bundle_or_builder

    # Step 2 — Send KEY_EXCHANGE
    send_packet(sock, PacketType.KEY_EXCHANGE, build_key_exchange(encrypted_bundle))


def perform_receiver_handshake(
    sock: socket.socket,
    public_key_pem: bytes
) -> bytes:
    """
    Receiver side of the handshake:
      1. Send HELLO with public key to the sender
      2. Wait for KEY_EXCHANGE containing the encrypted bundle

    Args:
        sock           : connected socket to the sender
        public_key_pem : receiver's RSA public key in PEM format

    Returns:
        The encrypted bundle bytes (caller decrypts with private key)
    """
    # Step 1 — Send HELLO
    send_packet(sock, PacketType.HELLO, build_hello(public_key_pem))

    # Step 2 — Wait for KEY_EXCHANGE
    ptype, payload = recv_packet(sock)
    if ptype != PacketType.KEY_EXCHANGE:
        raise HandshakeError(
            "Expected KEY_EXCHANGE from sender.",
            details=f"Got packet type: {ptype}"
        )
    return parse_key_exchange(payload)


def send_ping(sock: socket.socket) -> None:
    """Send a PING keepalive packet."""
    send_packet(sock, PacketType.PING, b"ping")


def expect_pong(sock: socket.socket) -> None:
    """Wait for a PONG response to a PING."""
    ptype, _ = recv_packet(sock)
    if ptype != PacketType.PONG:
        raise SessionError("Expected PONG response.", details=f"Got: {ptype}")


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — SELF TEST
# ══════════════════════════════════════════════════════════════════════════════

def run_protocol_test() -> None:
    """
    Test packet framing round-trip entirely in memory — no socket needed.
    Verifies that pack → unpack → parse produces identical data.
    """
    print("\n[*] Running protocol self-test ...\n")

    # Test 1 — Basic pack/unpack
    payload  = b"Hello, secure world!"
    packet   = pack_packet(PacketType.FILE_CHUNK, payload)
    ptype, length = unpack_header(packet[:HEADER_SIZE])
    recovered = packet[HEADER_SIZE:]

    assert ptype   == PacketType.FILE_CHUNK, "Packet type mismatch"
    assert length  == len(payload),           "Length mismatch"
    assert recovered == payload,              "Payload mismatch"
    print("    Pack/unpack round-trip  : PASSED ✓")

    # Test 2 — FILE_HEADER build/parse
    iv           = os.urandom(16)
    hmac_digest  = os.urandom(32)
    header_bytes = build_file_header("secret_doc.pdf", 1048576, 16, iv, hmac_digest)
    meta         = parse_file_header(header_bytes)

    assert meta["filename"]     == "secret_doc.pdf"
    assert meta["file_size"]    == 1048576
    assert meta["total_chunks"] == 16
    assert meta["iv"]           == iv
    assert meta["hmac"]         == hmac_digest
    print("    FILE_HEADER round-trip  : PASSED ✓")

    # Test 3 — HELLO build/parse
    fake_pem = b"-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----"
    parsed   = parse_hello(build_hello(fake_pem))
    assert parsed == fake_pem
    print("    HELLO round-trip        : PASSED ✓")

    # Test 4 — Oversized packet rejection
    try:
        pack_packet(PacketType.FILE_CHUNK, b"x" * (MAX_PACKET_SIZE + 1))
        assert False, "Should have raised PacketError"
    except PacketError:
        print("    Oversized packet guard  : PASSED ✓")

    print("\n[✓] All protocol self-tests passed.\n")


if __name__ == "__main__":
    run_protocol_test()
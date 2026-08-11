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


def build_file_header(
    filename: str,
    file_size: int,
    total_chunks: int,
    iv: bytes,
    hmac_digest: bytes,
    chunk_size: int = 65536,
) -> bytes:
    """
    FILE_HEADER payload — JSON-encoded file metadata.
    Sent before any file chunks so the receiver knows what to expect.

    Fields:
        filename     : original filename (basename only, no path)
        file_size    : total file size in bytes
        total_chunks : how many FILE_CHUNK packets to expect
        iv           : AES initialization vector (hex-encoded)
        hmac         : HMAC-SHA256 of the plaintext file (hex-encoded)
        version      : protocol version number
        chunk_size   : plaintext bytes per chunk the sender used (needed
                       by the receiver's progress display; defaults to
                       the historical 64 KB for callers that don't pass
                       one, e.g. existing tests)
    """
    meta = {
        "filename"     : os.path.basename(filename),
        "file_size"    : file_size,
        "total_chunks" : total_chunks,
        "iv"           : iv.hex(),
        "hmac"         : hmac_digest.hex(),
        "version"      : PROTOCOL_VERSION,
        "chunk_size"   : chunk_size,
    }
    return json.dumps(meta).encode("utf-8")


def parse_file_header(payload: bytes) -> dict:
    """
    Parse FILE_HEADER payload → returns metadata dict.
    Decodes hex fields back to bytes.
    """
    try:
        meta = json.loads(payload.decode("utf-8"))
        meta["iv"]   = bytes.fromhex(meta["iv"])
        meta["hmac"] = bytes.fromhex(meta["hmac"])
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
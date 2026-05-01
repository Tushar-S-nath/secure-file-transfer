#!/usr/bin/env python3
"""
sender.py — Secure File Transfer Sender
========================================
Acts as a TCP socket SERVER. Waits for a receiver to connect, performs the
cryptographic handshake, then encrypts and streams a file using AES-256-CBC
with HMAC-SHA256 integrity verification.

Usage:
    python sender.py --file <path> --port <port> --key <name>
    python sender.py --file secret.zip --host 0.0.0.0 --port 9999 --key alice

Handshake Flow (Sender side):
    1. Listen for incoming connection
    2. Receive HELLO packet → extract receiver's RSA public key PEM
    3. Generate AES-256 session key + HMAC key + IV
    4. Bundle keys → RSA-encrypt with receiver's public key
    5. Call perform_sender_handshake() → sends KEY_EXCHANGE packet
    6. Compute HMAC of plaintext file
    7. Send FILE_HEADER (filename, size, total_chunks, IV, HMAC digest)
    8. Stream FILE_CHUNK packets (64 KB encrypted chunks)
    9. Send TRANSFER_END
   10. Wait for ACK from receiver
"""

import argparse
import os
import socket
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Graceful import with helpful error messages
# ---------------------------------------------------------------------------
try:
    from crypto_utils import (
        generate_session_key,
        generate_hmac_key,
        bundle_keys,
        rsa_encrypt,
        encrypt_file_stream,
        compute_hmac,
        compute_sha256,
        compute_total_chunks,
    )
    from protocol import (
        send_packet,
        recv_packet,
        PacketType,
        perform_sender_handshake,
        build_file_header,
        build_file_chunk,
        build_transfer_end,
        build_error,
        parse_hello,
    )
    from keygen import load_private_key, load_public_key
    from logger import TransferSession, log_info, log_error
    from exceptions import (
        SecureTransferError,
        HandshakeError,
        SessionError,
        IntegrityError,
    )
except ImportError as exc:
    print(f"[FATAL] Missing dependency: {exc}")
    print("Ensure all project modules are in the same directory and pycryptodome is installed.")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CHUNK_SIZE     = 64 * 1024   # 64 KB — matches crypto_utils CHUNK_SIZE
DEFAULT_PORT   = 9999
DEFAULT_HOST   = "0.0.0.0"   # Listen on all interfaces
SOCKET_TIMEOUT = 60          # Seconds to wait for receiver to connect
ACK_TIMEOUT    = 120         # Seconds to wait for final ACK (large files)
BACKLOG        = 1           # Accept one connection at a time


# ---------------------------------------------------------------------------
# Progress Display
# ---------------------------------------------------------------------------
class ProgressBar:
    """Terminal progress bar with transfer speed and ETA."""

    def __init__(self, total_chunks: int, filename: str):
        self.total      = total_chunks
        self.current    = 0
        self.filename   = filename
        self.start_time = time.time()
        self.bar_width  = 40

    def update(self, chunk_num: int):
        self.current = chunk_num
        elapsed  = time.time() - self.start_time
        pct      = self.current / self.total if self.total else 1
        filled   = int(self.bar_width * pct)
        bar      = "█" * filled + "░" * (self.bar_width - filled)

        speed     = (self.current * CHUNK_SIZE) / (elapsed + 1e-9)
        speed_str = self._fmt_speed(speed)

        eta     = (self.total - self.current) * CHUNK_SIZE / (speed + 1e-9)
        eta_str = self._fmt_time(eta) if self.current < self.total else "Done"

        print(
            f"\r  [{bar}] {pct*100:5.1f}%  "
            f"Chunk {self.current}/{self.total}  "
            f"{speed_str}  ETA {eta_str}   ",
            end="", flush=True,
        )

    def finish(self):
        self.update(self.total)
        elapsed = time.time() - self.start_time
        print(f"\n  ✓ All chunks sent in {self._fmt_time(elapsed)}")

    @staticmethod
    def _fmt_speed(bps: float) -> str:
        if bps >= 1_000_000: return f"{bps/1_000_000:.1f} MB/s"
        if bps >= 1_000:     return f"{bps/1_000:.1f} KB/s"
        return f"{bps:.0f} B/s"

    @staticmethod
    def _fmt_time(secs: float) -> str:
        secs = int(secs)
        if secs >= 3600: return f"{secs//3600}h {(secs%3600)//60}m"
        if secs >= 60:   return f"{secs//60}m {secs%60}s"
        return f"{secs}s"


# ---------------------------------------------------------------------------
# Core Transfer Logic
# ---------------------------------------------------------------------------
def perform_transfer(conn: socket.socket, file_path: Path, session: TransferSession):
    """
    Execute the full handshake + file transfer over an established socket.

    Args:
        conn:       Accepted client socket (the receiver).
        file_path:  Path to the plaintext file to send.
        session:    TransferSession logger instance.
    """
    filename = file_path.name
    file_size = file_path.stat().st_size

    # compute_total_chunks(filepath: str) — takes a path, not (size, chunk_size)
    total_chunks = compute_total_chunks(str(file_path))

    # ── Step 1: Receive HELLO → extract receiver's public key ──────────────
    # We receive HELLO ourselves here so we can extract the public key PEM.
    # perform_sender_handshake() also calls recv_packet() internally — it will
    # receive the NEXT packet (KEY_EXCHANGE direction doesn't apply here, see
    # protocol.py: it re-receives HELLO to validate, so we must NOT call
    # recv_packet here first).
    #
    # Reading protocol.py carefully:
    #   perform_sender_handshake(sock, encrypted_bundle):
    #     1. recv_packet(sock)  → expects HELLO (consumes it)
    #     2. send_packet(sock, KEY_EXCHANGE, encrypted_bundle)
    #
    # So the correct flow is:
    #   - We generate keys and build the encrypted bundle BEFORE calling handshake
    #   - But we need the receiver's public key to encrypt — so we must peek at
    #     the HELLO first... except perform_sender_handshake consumes it.
    #
    # Solution: receive HELLO ourselves, extract pubkey, build bundle, then
    # call perform_sender_handshake but bypass its internal recv by passing
    # a pre-built bundle. Since perform_sender_handshake re-receives HELLO
    # from the socket, we need to use a different approach:
    #   receive HELLO → extract pubkey → generate keys → encrypt bundle →
    #   manually send KEY_EXCHANGE (skip perform_sender_handshake's recv step)
    #
    # We replicate what perform_sender_handshake does but with the pubkey we
    # already have, since the function's recv would block (HELLO already consumed).

    log_info("Waiting for HELLO from receiver…")
    ptype, hello_payload = recv_packet(conn)
    if ptype != PacketType.HELLO:
        raise HandshakeError(f"Expected HELLO, got {ptype}")

    # parse_hello validates and returns the raw PEM bytes
    try:
        receiver_pubkey_pem = parse_hello(hello_payload)
    except Exception as exc:
        raise HandshakeError(f"Invalid HELLO payload: {exc}") from exc

    log_info("HELLO received — receiver public key extracted.")

    # ── Step 2: Generate session keys + encrypt bundle ─────────────────────
    log_info("Generating session keys and performing handshake…")
    try:
        from Crypto.PublicKey import RSA
        receiver_pubkey = RSA.import_key(receiver_pubkey_pem)

        aes_key, iv = generate_session_key()   # returns (aes_key, iv)
        hmac_key    = generate_hmac_key()

        bundle           = bundle_keys(aes_key, hmac_key)
        encrypted_bundle = rsa_encrypt(receiver_pubkey, bundle)
    except Exception as exc:
        raise HandshakeError(f"Key generation/encryption failed: {exc}") from exc

    # ── Step 3: Send KEY_EXCHANGE ───────────────────────────────────────────
    # perform_sender_handshake(sock, encrypted_bundle):
    #   internally calls recv_packet → expects HELLO (already consumed above!)
    # So we skip it and send KEY_EXCHANGE directly, which is all it does after
    # receiving HELLO.
    try:
        from protocol import build_key_exchange
        send_packet(conn, PacketType.KEY_EXCHANGE, build_key_exchange(encrypted_bundle))
    except Exception as exc:
        raise HandshakeError(f"Failed to send KEY_EXCHANGE: {exc}") from exc

    log_info("Handshake complete — session keys established.")

    # ── Step 4: Compute HMAC + checksum of plaintext file ──────────────────
    log_info(f"Computing HMAC-SHA256 of '{filename}' ({file_size:,} bytes)…")
    try:
        # compute_hmac(hmac_key, filepath) — key first, path second
        hmac_digest   = compute_hmac(hmac_key, str(file_path))
        file_checksum = compute_sha256(str(file_path))
    except Exception as exc:
        raise SessionError(f"Failed to compute file integrity values: {exc}") from exc

    log_info(f"SHA-256  : {file_checksum}")
    log_info(f"HMAC-256 : {hmac_digest.hex()[:32]}…")

    # ── Step 5: Send FILE_HEADER ────────────────────────────────────────────
    # build_file_header(filename, file_size, total_chunks, iv, hmac_digest)
    header_payload = build_file_header(
        filename     = filename,
        file_size    = file_size,
        total_chunks = total_chunks,
        iv           = iv,
        hmac_digest  = hmac_digest,
    )
    send_packet(conn, PacketType.FILE_HEADER, header_payload)
    log_info(f"FILE_HEADER sent → {total_chunks} chunk(s) of {CHUNK_SIZE // 1024} KB")

    # ── Step 6: Stream FILE_CHUNK packets ───────────────────────────────────
    # encrypt_file_stream(filepath, aes_key, iv) — no chunk_size argument
    # build_file_chunk(encrypted_chunk)          — no chunk number argument
    log_info(f"Streaming '{filename}'…")
    progress  = ProgressBar(total_chunks, filename)
    chunk_num = 0

    try:
        for encrypted_chunk in encrypt_file_stream(str(file_path), aes_key, iv):
            chunk_num += 1
            send_packet(conn, PacketType.FILE_CHUNK, build_file_chunk(encrypted_chunk))
            progress.update(chunk_num)

        progress.finish()

    except Exception as exc:
        print()  # newline after progress bar
        try:
            send_packet(conn, PacketType.ERROR, build_error(str(exc)))
        except Exception:
            pass
        raise SessionError(
            f"File streaming failed at chunk {chunk_num}: {exc}"
        ) from exc

    # ── Step 7: Send TRANSFER_END ───────────────────────────────────────────
    send_packet(conn, PacketType.TRANSFER_END, build_transfer_end())
    log_info("TRANSFER_END sent — waiting for ACK…")

    # ── Step 8: Receive ACK ─────────────────────────────────────────────────
    conn.settimeout(ACK_TIMEOUT)
    try:
        ptype, ack_payload = recv_packet(conn)
    except socket.timeout:
        raise SessionError("Timed out waiting for ACK from receiver.")

    if ptype == PacketType.ERROR:
        raise IntegrityError(
            f"Receiver reported error: {ack_payload.decode(errors='replace')}"
        )
    if ptype != PacketType.ACK:
        raise SessionError(f"Expected ACK, got {ptype}")

    log_info("✓ ACK received — receiver confirmed integrity.")

    # Mark session complete with checksum
    session.bytes_transferred = file_size
    session.complete(checksum=file_checksum)


# ---------------------------------------------------------------------------
# Server Lifecycle
# ---------------------------------------------------------------------------
def run_server(file_path: Path, host: str, port: int):
    """
    Start the TCP server, accept one receiver, run the full transfer, shut down.
    """
    if not file_path.exists():
        log_error(f"File not found: {file_path}")
        sys.exit(1)
    if not file_path.is_file():
        log_error(f"Not a regular file: {file_path}")
        sys.exit(1)

    print("=" * 60)
    print("  Secure File Transfer — SENDER")
    print("=" * 60)
    print(f"  File    : {file_path}  ({file_path.stat().st_size:,} bytes)")
    print(f"  Listen  : {host}:{port}")
    print("=" * 60)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_sock.bind((host, port))
        server_sock.listen(BACKLOG)
        server_sock.settimeout(SOCKET_TIMEOUT)
        log_info(f"Listening on {host}:{port} — waiting for receiver…")

        try:
            conn, addr = server_sock.accept()
        except socket.timeout:
            log_error(f"No receiver connected within {SOCKET_TIMEOUT}s. Exiting.")
            sys.exit(1)

        peer_address = f"{addr[0]}:{addr[1]}"

        # TransferSession(role, filepath, peer_address)
        session = TransferSession(
            role="sender",
            filepath=str(file_path),
            peer_address=peer_address,
        )
        log_info(f"Receiver connected from {peer_address}")

        try:
            with conn:
                conn.settimeout(ACK_TIMEOUT)
                perform_transfer(conn, file_path, session)
                print(f"\n  ✓ Transfer complete.")

        except HandshakeError as exc:
            log_error(f"Handshake error: {exc}")
            session.fail(str(exc))
            sys.exit(2)

        except IntegrityError as exc:
            log_error(f"Integrity error: {exc}")
            session.fail(str(exc))
            sys.exit(3)

        except SessionError as exc:
            log_error(f"Session error: {exc}")
            session.fail(str(exc))
            sys.exit(4)

        except SecureTransferError as exc:
            log_error(f"Transfer error: {exc}")
            session.fail(str(exc))
            sys.exit(5)

        except (ConnectionResetError, BrokenPipeError) as exc:
            log_error(f"Connection lost: {exc}")
            session.fail(str(exc))
            sys.exit(6)

    except OSError as exc:
        log_error(f"Could not bind to {host}:{port} — {exc}")
        sys.exit(1)

    finally:
        server_sock.close()


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sender",
        description=(
            "Secure File Transfer — Sender\n"
            "Starts a TCP server, waits for a receiver, performs RSA/AES handshake,\n"
            "then streams the encrypted file with HMAC-SHA256 integrity verification."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python sender.py --file secret.zip --port 9999 --key alice\n"
            "  python sender.py --file data.tar.gz --host 0.0.0.0 --port 5000 --key alice\n\n"
            "Testing locally (two terminals):\n"
            "  Terminal 1:  python sender.py --file test.txt --port 9999 --key alice\n"
            "  Terminal 2:  python receiver.py --port 9999 --key bob --output ./received\n\n"
            "Cross-network (ngrok):\n"
            "  ngrok tcp 9999\n"
            "  Share the ngrok host:port with the receiver."
        ),
    )
    parser.add_argument(
        "--file", "-f",
        required=True,
        metavar="PATH",
        help="Path to the file to send.",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        metavar="HOST",
        help=f"Host/IP to listen on. Default: {DEFAULT_HOST} (all interfaces).",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=DEFAULT_PORT,
        metavar="PORT",
        help=f"TCP port to listen on. Default: {DEFAULT_PORT}.",
    )
    parser.add_argument(
        "--key", "-k",
        required=True,
        metavar="NAME",
        help="Key name prefix (e.g. 'alice' → keys/alice_private.pem).",
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version="secure-file-transfer sender v1.0.0",
    )
    return parser


def main():
    parser = build_arg_parser()
    args   = parser.parse_args()

    if not (1 <= args.port <= 65535):
        parser.error(f"Invalid port: {args.port}. Must be between 1 and 65535.")

    try:
        load_private_key(args.key)
        log_info(f"Sender private key loaded: '{args.key}'")
    except Exception as exc:
        parser.error(f"Failed to load private key '{args.key}': {exc}")

    run_server(Path(args.file).resolve(), args.host, args.port)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
receiver.py — Secure File Transfer Receiver
=============================================
Acts as a TCP socket CLIENT. Connects to the sender, performs the
cryptographic handshake, receives and decrypts the file stream, verifies
HMAC-SHA256 integrity, and saves the file to disk.

Usage:
    python receiver.py --port <port> --key <name> --output <dir>
    python receiver.py --host 192.168.1.5 --port 9999 --key bob --output ./received

Handshake Flow (Receiver side):
    1. Connect to sender
    2. Send HELLO packet containing own RSA public key PEM
    3. Receive KEY_EXCHANGE packet → RSA-decrypt with private key → recover AES key + HMAC key
    4. Receive FILE_HEADER → extract filename, size, total_chunks, IV, HMAC digest
    5. Receive FILE_CHUNK packets → collect encrypted chunks
    6. Receive TRANSFER_END → decrypt full stream → verify HMAC
    7. Send ACK (or ERROR if verification fails)
    8. Move decrypted file to final output path
"""

import argparse
import os
import shutil
import socket
import sys
import tempfile
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Graceful import with helpful error messages
# ---------------------------------------------------------------------------
try:
    from crypto_utils import (
        rsa_decrypt,
        unbundle_keys,
        decrypt_file_stream,
        verify_hmac,
        compute_sha256,
    )
    from protocol import (
        send_packet,
        recv_packet,
        PacketType,
        perform_receiver_handshake,
        parse_file_header,
        build_ack,
        build_error,
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
CHUNK_SIZE      = 64 * 1024   # Must match sender's chunk size
DEFAULT_PORT    = 9999
DEFAULT_HOST    = "127.0.0.1"
CONNECT_TIMEOUT = 30          # Seconds to wait for connection to sender
RECV_TIMEOUT    = 120         # Seconds to wait between packets


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
        print(f"\n  ✓ All chunks received in {self._fmt_time(elapsed)}")

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
def perform_transfer(
    conn: socket.socket,
    private_key,
    public_key_pem: bytes,
    output_dir: Path,
    session: TransferSession,
) -> Path:
    """
    Execute the full handshake + file reception over an established socket.

    Args:
        conn:           Connected socket to the sender.
        private_key:    Receiver's RSA private key object.
        public_key_pem: Receiver's RSA public key in PEM bytes (sent in HELLO).
        output_dir:     Directory where the received file will be saved.
        session:        TransferSession logger instance.

    Returns:
        Path to the saved output file.
    """

    # ── Step 1: Handshake ───────────────────────────────────────────────────
    # perform_receiver_handshake(sock, public_key_pem) → encrypted_bundle bytes
    log_info("Sending HELLO with receiver public key…")
    try:
        encrypted_bundle = perform_receiver_handshake(conn, public_key_pem)
    except Exception as exc:
        raise HandshakeError(f"Handshake failed: {exc}") from exc

    # Decrypt the bundle with our private key to recover AES key + HMAC key
    try:
        raw_bundle = rsa_decrypt(private_key, encrypted_bundle)
        aes_key, hmac_key = unbundle_keys(raw_bundle)
    except Exception as exc:
        raise HandshakeError(f"Key bundle decryption failed: {exc}") from exc

    log_info("Handshake complete — session keys recovered.")

    # ── Step 2: Receive FILE_HEADER ─────────────────────────────────────────
    log_info("Waiting for FILE_HEADER…")
    conn.settimeout(RECV_TIMEOUT)
    ptype, header_payload = recv_packet(conn)
    if ptype != PacketType.FILE_HEADER:
        raise SessionError(f"Expected FILE_HEADER, got {ptype}")

    try:
        header       = parse_file_header(header_payload)
        filename     = header["filename"]
        file_size    = header["file_size"]
        total_chunks = header["total_chunks"]
        iv           = header["iv"]     # bytes (parse_file_header decodes hex → bytes)
        hmac_digest  = header["hmac"]   # bytes — key is "hmac", not "hmac_digest"
    except Exception as exc:
        raise SessionError(f"Failed to parse FILE_HEADER: {exc}") from exc

    log_info(
        f"Incoming file : '{filename}'  "
        f"({file_size:,} bytes, {total_chunks} chunk(s))"
    )

    # ── Step 3: Receive FILE_CHUNK packets, collect encrypted chunks ────────
    # decrypt_file_stream() takes a generator of encrypted chunks — we collect
    # them here and pass as a generator so memory usage stays bounded.
    encrypted_chunks = []

    log_info(f"Receiving '{filename}'…")
    progress = ProgressBar(total_chunks, filename)

    try:
        chunks_received = 0
        while True:
            conn.settimeout(RECV_TIMEOUT)
            ptype, payload = recv_packet(conn)

            if ptype == PacketType.FILE_CHUNK:
                # build_file_chunk() returns raw encrypted bytes — no prefix to strip
                encrypted_chunks.append(payload)
                chunks_received += 1
                progress.update(chunks_received)

            elif ptype == PacketType.TRANSFER_END:
                progress.finish()
                log_info(
                    f"TRANSFER_END received — "
                    f"{chunks_received}/{total_chunks} chunks."
                )
                break

            elif ptype == PacketType.ERROR:
                raise SessionError(
                    f"Sender reported an error: {payload.decode(errors='replace')}"
                )

            else:
                raise SessionError(
                    f"Unexpected packet type during transfer: {ptype}"
                )

        if chunks_received != total_chunks:
            raise SessionError(
                f"Chunk count mismatch: "
                f"expected {total_chunks}, received {chunks_received}"
            )

    except Exception:
        raise

    # ── Step 4: Decrypt the collected chunks to a temp file ─────────────────
    tmp_decrypted = tempfile.NamedTemporaryFile(
        delete=False, suffix=".dec", dir=tempfile.gettempdir()
    )
    tmp_decrypted_path = Path(tmp_decrypted.name)
    tmp_decrypted.close()

    log_info("Decrypting received data…")
    try:
        # decrypt_file_stream(encrypted_chunks_iter, aes_key, iv, output_path, total_chunks)
        decrypt_file_stream(
            iter(encrypted_chunks),
            aes_key,
            iv,
            str(tmp_decrypted_path),
            total_chunks,
        )
    except Exception as exc:
        tmp_decrypted_path.unlink(missing_ok=True)
        raise SessionError(f"Decryption failed: {exc}") from exc

    # ── Step 5: Verify HMAC ─────────────────────────────────────────────────
    log_info("Verifying HMAC-SHA256 integrity…")
    try:
        # verify_hmac(hmac_key, filepath, expected_hmac) → True or raises IntegrityError
        verify_hmac(hmac_key, str(tmp_decrypted_path), hmac_digest)
    except IntegrityError:
        tmp_decrypted_path.unlink(missing_ok=True)
        send_packet(
            conn, PacketType.ERROR,
            build_error("HMAC verification failed — file corrupted or tampered.")
        )
        raise
    except Exception as exc:
        tmp_decrypted_path.unlink(missing_ok=True)
        raise IntegrityError(f"HMAC verification error: {exc}") from exc

    checksum = compute_sha256(str(tmp_decrypted_path))
    log_info(f"✓ HMAC verified.  SHA-256: {checksum}")

    # ── Step 6: Send ACK ────────────────────────────────────────────────────
    send_packet(conn, PacketType.ACK, build_ack())
    log_info("ACK sent to sender.")

    # ── Step 7: Move decrypted file to final output path ────────────────────
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / filename

    # Avoid overwriting — append a counter if file already exists
    if output_path.exists():
        stem    = output_path.stem
        suffix  = output_path.suffix
        counter = 1
        while output_path.exists():
            output_path = output_dir / f"{stem}_{counter}{suffix}"
            counter += 1
        log_info(f"File already exists — saving as '{output_path.name}'")

    shutil.move(str(tmp_decrypted_path), str(output_path))
    log_info(f"✓ File saved to: {output_path}")

    # Update session with final info and mark complete
    session.bytes_transferred = file_size
    session.complete(checksum=checksum)

    return output_path


# ---------------------------------------------------------------------------
# Client Lifecycle
# ---------------------------------------------------------------------------
def run_client(host: str, port: int, key_name: str, output_dir: Path):
    """Connect to the sender and run the full secure file reception flow."""

    print("=" * 60)
    print("  Secure File Transfer — RECEIVER")
    print("=" * 60)
    print(f"  Connecting to : {host}:{port}")
    print(f"  Key name      : {key_name}")
    print(f"  Output dir    : {output_dir}")
    print("=" * 60)

    # Load keys — private for decryption, public PEM bytes for HELLO packet
    try:
        private_key = load_private_key(key_name)
        public_key  = load_public_key(key_name)
        public_key_pem = public_key.export_key(format="PEM")  # bytes
        log_info(f"RSA key pair loaded: '{key_name}'")
    except Exception as exc:
        log_error(f"Failed to load keys '{key_name}': {exc}")
        sys.exit(1)

    log_info(f"Connecting to sender at {host}:{port}…")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)

    try:
        sock.connect((host, port))
    except socket.timeout:
        log_error(
            f"Connection timed out after {CONNECT_TIMEOUT}s. "
            "Is the sender running?"
        )
        sys.exit(1)
    except ConnectionRefusedError:
        log_error(f"Connection refused at {host}:{port}. Start the sender first.")
        sys.exit(1)
    except OSError as exc:
        log_error(f"Connection failed: {exc}")
        sys.exit(1)

    log_info(f"Connected to sender at {host}:{port}")

    # TransferSession(role, filepath, peer_address)
    # filepath is output_dir here since we don't know filename yet
    session = TransferSession(
        role="receiver",
        filepath=str(output_dir),
        peer_address=f"{host}:{port}",
    )

    try:
        with sock:
            sock.settimeout(RECV_TIMEOUT)
            output_path = perform_transfer(
                sock, private_key, public_key_pem, output_dir, session
            )

            print(f"\n  ✓ Transfer complete → {output_path}")

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
        log_error(f"Connection lost mid-transfer: {exc}")
        session.fail(str(exc))
        sys.exit(6)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="receiver",
        description=(
            "Secure File Transfer — Receiver\n"
            "Connects to a sender, performs RSA/AES handshake,\n"
            "receives and decrypts the file, verifies HMAC-SHA256 integrity."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python receiver.py --port 9999 --key bob --output ./received\n"
            "  python receiver.py --host 192.168.1.10 --port 9999 --key bob\n\n"
            "Testing locally (two terminals):\n"
            "  Terminal 1:  python sender.py --file test.txt --port 9999 --key alice\n"
            "  Terminal 2:  python receiver.py --port 9999 --key bob --output ./received\n\n"
            "Cross-network (ngrok):\n"
            "  Sender runs:   ngrok tcp 9999\n"
            "  Receiver runs: python receiver.py --host <ngrok-host> --port <ngrok-port> --key bob"
        ),
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        metavar="HOST",
        help=f"Sender's host/IP address. Default: {DEFAULT_HOST}.",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=DEFAULT_PORT,
        metavar="PORT",
        help=f"Sender's TCP port. Default: {DEFAULT_PORT}.",
    )
    parser.add_argument(
        "--key", "-k",
        required=True,
        metavar="NAME",
        help="Key name for your RSA key pair (e.g. 'bob' → keys/bob_private.pem).",
    )
    parser.add_argument(
        "--output", "-o",
        default="./received",
        metavar="DIR",
        help="Directory to save the received file. Default: ./received",
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version="secure-file-transfer receiver v1.0.0",
    )
    return parser


def main():
    parser  = build_arg_parser()
    args    = parser.parse_args()

    if not (1 <= args.port <= 65535):
        parser.error(f"Invalid port: {args.port}. Must be between 1 and 65535.")

    run_client(
        host       = args.host,
        port       = args.port,
        key_name   = args.key,
        output_dir = Path(args.output),
    )


if __name__ == "__main__":
    main()
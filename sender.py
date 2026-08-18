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
import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Optional

try:
    import resource   # Unix/Linux/macOS only — used for --bench-report peak RSS
    _HAS_RESOURCE = True
except ImportError:
    _HAS_RESOURCE = False   # e.g. native Windows without WSL

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
        generate_session_key_gcm,
        bundle_keys_gcm,
        encrypt_file_stream_gcm,
        verify_peer_identity,
        sign_data,
        compute_key_fingerprint,
        derive_hybrid_session_key,
    )
    from Crypto.Random import get_random_bytes
    from protocol import (
        send_packet,
        recv_packet,
        PacketType,
        perform_sender_handshake,
        build_file_header,
        build_file_chunk,
        build_transfer_end,
        build_error,
        parse_hello_named,
        build_key_exchange_signed,
    )
    from keygen import load_private_key, load_public_key
    from logger import TransferSession, log_info, log_error
    from exceptions import (
        SecureTransferError,
        HandshakeError,
        SessionError,
        IntegrityError,
        AuthenticationError,
    )
except ImportError as exc:
    print(f"[FATAL] Missing dependency: {exc}")
    print("Ensure all project modules are in the same directory and pycryptodome is installed.")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_CHUNK_SIZE = 64 * 1024   # 64 KB — historical default, matches crypto_utils
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

    def __init__(self, total_chunks: int, filename: str, chunk_size: int = DEFAULT_CHUNK_SIZE):
        self.total      = total_chunks
        self.current    = 0
        self.filename   = filename
        self.chunk_size = chunk_size
        self.start_time = time.time()
        self.bar_width  = 40

    def update(self, chunk_num: int):
        self.current = chunk_num
        elapsed  = time.time() - self.start_time
        pct      = self.current / self.total if self.total else 1
        filled   = int(self.bar_width * pct)
        bar      = "█" * filled + "░" * (self.bar_width - filled)

        speed     = (self.current * self.chunk_size) / (elapsed + 1e-9)
        speed_str = self._fmt_speed(speed)

        eta     = (self.total - self.current) * self.chunk_size / (speed + 1e-9)
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
def perform_transfer(
    conn: socket.socket,
    file_path: Path,
    session: TransferSession,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    cipher_mode: str = "AES-256-GCM",
    peer_name: str = None,
    own_name: str = None,
    own_private_key=None,
    post_quantum: bool = False,
) -> dict:
    """
    Execute the full handshake + file transfer over an established socket.

    Args:
        conn:        Accepted client socket (the receiver).
        file_path:   Path to the plaintext file to send.
        session:     TransferSession logger instance.
        chunk_size:  Plaintext bytes per chunk (must be a multiple of 16 —
                     see crypto_utils.encrypt_file_stream). Defaults to the
                     historical 64 KB. Exposed for the benchmark suite's
                     chunk-size sweep.
        cipher_mode: "AES-256-GCM" (default) or "AES-256-CBC". GCM is the
                     recommended mode — no padding step, per-chunk
                     authentication, no separate HMAC pass. CBC is kept
                     available for comparison/benchmarking against the
                     original design (see paper Results section).
        peer_name:   If given, enables MUTUAL AUTHENTICATION: the receiver
                     must present a HELLO claiming this exact name, with a
                     public key matching the locally trusted copy at
                     keys/<peer_name>_public.pem — and this sender signs
                     its key-exchange bundle with own_private_key so the
                     receiver can verify OUR identity too. If None
                     (default), falls back to the original unauthenticated
                     handshake — unchanged behavior for existing callers.
        own_name:        This sender's own identity name (required if
                          peer_name is set — used in the signature).
        own_private_key: This sender's own RSA private key object
                          (required if peer_name is set — used to sign).
        post_quantum:    If True, ALSO combines an ML-KEM-768 encapsulated
                          secret with the RSA secret via HKDF (see
                          crypto_utils.derive_hybrid_session_key), so the
                          session key resists a future quantum attack on
                          RSA. Requires peer_name to be set — post-quantum
                          mode reuses the same named-HELLO/signed-KEY_EXCHANGE
                          wire format mutual auth already needs, rather than
                          adding yet another separate handshake variant.
                          Requires the receiver to also have generated an
                          ML-KEM keypair (keygen.py --post-quantum) and to
                          also pass post_quantum=True.

    Returns:
        A stats dict with wall-clock timings (handshake_seconds,
        bulk_transfer_seconds, ack_wait_seconds, total_seconds) measured
        around the REAL send()/recv() calls on this socket — not just the
        in-memory encryption loop. Used by --bench-report; harmless/ignored
        for normal (non-benchmark) runs.
    """
    if cipher_mode not in ("AES-256-GCM", "AES-256-CBC"):
        raise ValueError(f"Unknown cipher_mode: {cipher_mode!r}")
    if peer_name is not None and (own_name is None or own_private_key is None):
        raise ValueError("peer_name requires own_name and own_private_key (mutual auth needs both to sign).")
    if post_quantum and peer_name is None:
        raise ValueError("post_quantum requires peer_name (mutual auth) to also be enabled — see docstring.")

    filename = file_path.name
    file_size = file_path.stat().st_size

    total_chunks = compute_total_chunks(str(file_path), chunk_size=chunk_size)

    t_start = time.perf_counter()

    # ── Steps 1-3: HELLO → generate session keys → KEY_EXCHANGE ────────────
    log_info(f"Performing handshake with receiver… (cipher_mode={cipher_mode}"
             f"{f', mutual auth as {own_name} expecting {peer_name}' if peer_name else ''})")
    session_keys = {}

    if peer_name is not None:
        # ── Mutual-auth handshake ───────────────────────────────────────
        # We own this exchange directly (not perform_sender_handshake's
        # callback pattern) since the wire format differs: named HELLO in,
        # signed KEY_EXCHANGE out.
        ptype, hello_payload = recv_packet(conn)
        if ptype != PacketType.HELLO:
            raise HandshakeError(f"Expected HELLO, got {ptype}")
        try:
            hello = parse_hello_named(hello_payload)
        except Exception as exc:
            raise HandshakeError(
                f"Failed to parse named HELLO — is the receiver also using "
                f"--peer? {exc}"
            ) from exc

        if hello["name"] != peer_name:
            raise AuthenticationError(
                f"Receiver claimed identity '{hello['name']}', expected '{peer_name}'.",
                details="Refusing to proceed — this could be a wrong peer or an impersonation attempt."
            )

        # verify_peer_identity checks the PRESENTED key's fingerprint
        # against our LOCALLY trusted keys/<peer_name>_public.pem, and
        # returns that trusted copy (not the presented one) to encrypt
        # with — belt and suspenders, though at this point they're
        # guaranteed to match.
        receiver_pubkey = verify_peer_identity(peer_name, hello["public_key"])
        log_info(f"✓ Receiver identity verified: '{peer_name}' "
                 f"(fingerprint {compute_key_fingerprint(receiver_pubkey)[:16]}…)")

        if post_quantum:
            if hello["mlkem_public_key"] is None:
                raise HandshakeError(
                    "Post-quantum mode requested (--post-quantum) but the "
                    "receiver's HELLO did not include an ML-KEM public key "
                    "— is the receiver also using --post-quantum?"
                )
            from cryptography.hazmat.primitives.asymmetric import mlkem as _mlkem
            receiver_mlkem_pubkey = _mlkem.MLKEM768PublicKey.from_public_bytes(hello["mlkem_public_key"])
            mlkem_secret, mlkem_ciphertext = receiver_mlkem_pubkey.encapsulate()
            log_info("✓ ML-KEM-768 encapsulation complete (post-quantum secret established)")

            # A fresh random secret, RSA-OAEP encrypted — this is the
            # "classical" half of the hybrid. Note this is a raw secret
            # fed into the KDF below, not the AES key itself directly
            # (unlike the non-PQ path, which encrypts the AES key/bundle
            # straight up).
            rsa_secret = get_random_bytes(32)
            encrypted_bundle = rsa_encrypt(receiver_pubkey, rsa_secret)

            # How many bytes of key material this cipher_mode needs.
            if cipher_mode == "AES-256-GCM":
                needed_bytes = 32 + 8    # aes_key + base_nonce
            else:
                needed_bytes = 32 + 16 + 32   # aes_key + iv + hmac_key

            combined = derive_hybrid_session_key(rsa_secret, mlkem_secret, key_length=needed_bytes)

            if cipher_mode == "AES-256-GCM":
                session_keys["aes_key"]    = combined[:32]
                session_keys["base_nonce"] = combined[32:40]
            else:
                session_keys["aes_key"]  = combined[:32]
                session_keys["iv"]       = combined[32:48]
                session_keys["hmac_key"] = combined[48:80]
        else:
            mlkem_ciphertext = None
            if cipher_mode == "AES-256-GCM":
                aes_key, base_nonce = generate_session_key_gcm()
                session_keys["aes_key"]    = aes_key
                session_keys["base_nonce"] = base_nonce
                bundle = bundle_keys_gcm(aes_key)
            else:
                aes_key, iv = generate_session_key()
                hmac_key    = generate_hmac_key()
                session_keys["aes_key"]  = aes_key
                session_keys["iv"]       = iv
                session_keys["hmac_key"] = hmac_key
                bundle = bundle_keys(aes_key, hmac_key)
            encrypted_bundle = rsa_encrypt(receiver_pubkey, bundle)

        # Sign (encrypted_bundle + challenge_nonce + mlkem_ciphertext), NOT
        # just encrypted_bundle — this is the sender's half of replay
        # protection, extended to also bind the ML-KEM ciphertext (so it
        # can't be swapped in transit without invalidating the signature).
        # The nonce came from THIS receiver's THIS HELLO, so our signature
        # can never be validly replayed against a future connection (which
        # will present a different, fresh nonce).
        signature_input = encrypted_bundle + hello["challenge_nonce"] + (mlkem_ciphertext or b"")
        signature = sign_data(own_private_key, signature_input)
        log_info(f"✓ Key-exchange bundle signed as '{own_name}' (bound to this session's challenge"
                 f"{', includes ML-KEM ciphertext' if post_quantum else ''})")

        try:
            send_packet(
                conn, PacketType.KEY_EXCHANGE,
                build_key_exchange_signed(encrypted_bundle, own_name, signature, mlkem_ciphertext=mlkem_ciphertext)
            )
        except Exception as exc:
            raise HandshakeError(f"Failed to send signed KEY_EXCHANGE: {exc}") from exc

    else:
        # ── Original, unauthenticated handshake (unchanged) ─────────────
        # perform_sender_handshake() owns the whole exchange: it receives
        # HELLO, extracts the receiver's public key PEM, hands that PEM to
        # our build_bundle() callback (which generates the session key(s)
        # and RSA-encrypts them), and sends the resulting bundle as
        # KEY_EXCHANGE. session_keys is populated as a side effect so we
        # can use the key material afterward, since it's only generated
        # *inside* the callback (after we've actually seen the receiver's
        # public key).
        def build_bundle(receiver_pubkey_pem: bytes) -> bytes:
            from Crypto.PublicKey import RSA
            receiver_pubkey = RSA.import_key(receiver_pubkey_pem)

            if cipher_mode == "AES-256-GCM":
                aes_key, base_nonce = generate_session_key_gcm()
                session_keys["aes_key"]     = aes_key
                session_keys["base_nonce"]  = base_nonce
                bundle = bundle_keys_gcm(aes_key)
            else:
                aes_key, iv = generate_session_key()
                hmac_key    = generate_hmac_key()
                session_keys["aes_key"]  = aes_key
                session_keys["iv"]       = iv
                session_keys["hmac_key"] = hmac_key
                bundle = bundle_keys(aes_key, hmac_key)

            return rsa_encrypt(receiver_pubkey, bundle)

        try:
            perform_sender_handshake(conn, build_bundle)
        except Exception as exc:
            raise HandshakeError(f"Handshake failed: {exc}") from exc

    aes_key = session_keys["aes_key"]

    t_handshake_done = time.perf_counter()
    log_info(f"Handshake complete — session keys established. "
             f"({t_handshake_done - t_start:.4f}s)")

    # ── Step 4: For CBC only — compute whole-file HMAC + checksum ──────────
    # GCM skips this entirely: authentication happens per-chunk during
    # streaming (Step 6), not as a separate whole-file pass beforehand.
    # compute_sha256 is always computed either way — it is NOT a security
    # mechanism, just an informational checksum used for logging/display.
    file_checksum = compute_sha256(str(file_path))
    log_info(f"SHA-256  : {file_checksum}")

    if cipher_mode == "AES-256-CBC":
        log_info(f"Computing HMAC-SHA256 of '{filename}' ({file_size:,} bytes)…")
        try:
            hmac_digest = compute_hmac(session_keys["hmac_key"], str(file_path))
        except Exception as exc:
            raise SessionError(f"Failed to compute file integrity values: {exc}") from exc
        log_info(f"HMAC-256 : {hmac_digest.hex()[:32]}…")

    # ── Step 5: Send FILE_HEADER ────────────────────────────────────────────
    # Bulk-transfer timing starts here — this is the phase whose latency
    # comes from real send() calls over the socket, as opposed to handshake
    # latency (above) or local-only HMAC/checksum computation (just above,
    # not included in either bucket since it never touches the socket).
    t_bulk_start = time.perf_counter()

    if cipher_mode == "AES-256-GCM":
        header_payload = build_file_header(
            filename     = filename,
            file_size    = file_size,
            total_chunks = total_chunks,
            chunk_size   = chunk_size,
            cipher_mode  = cipher_mode,
            nonce        = session_keys["base_nonce"],
        )
    else:
        header_payload = build_file_header(
            filename     = filename,
            file_size    = file_size,
            total_chunks = total_chunks,
            iv           = session_keys["iv"],
            hmac_digest  = hmac_digest,
            chunk_size   = chunk_size,
            cipher_mode  = cipher_mode,
        )
    send_packet(conn, PacketType.FILE_HEADER, header_payload)
    log_info(f"FILE_HEADER sent → {total_chunks} chunk(s) of {chunk_size // 1024} KB")

    # ── Step 6: Stream FILE_CHUNK packets ───────────────────────────────────
    log_info(f"Streaming '{filename}'…")
    progress  = ProgressBar(total_chunks, filename, chunk_size=chunk_size)
    chunk_num = 0

    if cipher_mode == "AES-256-GCM":
        chunk_generator = encrypt_file_stream_gcm(
            str(file_path), aes_key, session_keys["base_nonce"], chunk_size=chunk_size
        )
    else:
        chunk_generator = encrypt_file_stream(
            str(file_path), aes_key, session_keys["iv"], chunk_size=chunk_size
        )

    try:
        for encrypted_chunk in chunk_generator:
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
    t_bulk_done = time.perf_counter()
    log_info(f"TRANSFER_END sent — waiting for ACK… "
             f"(bulk transfer: {t_bulk_done - t_bulk_start:.4f}s)")

    # ── Step 8: Receive ACK ─────────────────────────────────────────────────
    conn.settimeout(ACK_TIMEOUT)
    try:
        ptype, ack_payload = recv_packet(conn)
    except socket.timeout:
        raise SessionError("Timed out waiting for ACK from receiver.")

    t_end = time.perf_counter()

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

    return {
        "role"                  : "sender",
        "cipher_mode"           : cipher_mode,
        "file_size_bytes"       : file_size,
        "chunk_size_bytes"      : chunk_size,
        "total_chunks"          : total_chunks,
        "handshake_seconds"     : t_handshake_done - t_start,
        "bulk_transfer_seconds" : t_bulk_done - t_bulk_start,
        "ack_wait_seconds"      : t_end - t_bulk_done,
        "total_seconds"         : t_end - t_start,
        "peak_rss_kb"           : _peak_rss_kb(),
        "checksum"              : file_checksum,
    }


def _peak_rss_kb() -> Optional[int]:
    """Peak resident set size of this process, in KB, for the whole process
    lifetime so far (Linux/macOS via getrusage's high-water-mark semantics).
    Returns None on platforms without the resource module (e.g. native
    Windows) rather than raising — memory profiling is best-effort."""
    if not _HAS_RESOURCE:
        return None
    # ru_maxrss is KB on Linux, bytes on macOS — normalize to KB.
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return raw if sys.platform != "darwin" else raw // 1024


# ---------------------------------------------------------------------------
# Server Lifecycle
# ---------------------------------------------------------------------------
def run_server(
    file_path: Path,
    host: str,
    port: int,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    bench_report: Optional[Path] = None,
    cipher_mode: str = "AES-256-GCM",
    peer_name: str = None,
    own_name: str = None,
    own_private_key=None,
    post_quantum: bool = False,
):
    """
    Start the TCP server, accept one receiver, run the full transfer, shut down.

    Args:
        chunk_size:    plaintext bytes per chunk (see perform_transfer).
        bench_report:  if given, write a JSON file here with the stats dict
                        returned by perform_transfer (timings, peak RSS,
                        etc.) after the transfer finishes — success or
                        failure. Used by the benchmark suite; no effect on
                        normal transfers when omitted.
        cipher_mode:   "AES-256-GCM" (default) or "AES-256-CBC".
        peer_name, own_name, own_private_key: mutual authentication —
            see perform_transfer's docstring.
        post_quantum: hybrid RSA + ML-KEM key exchange — see
            perform_transfer's docstring. Requires peer_name.
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

        stats = None
        exit_code = 0
        try:
            with conn:
                conn.settimeout(ACK_TIMEOUT)
                stats = perform_transfer(
                    conn, file_path, session, chunk_size=chunk_size, cipher_mode=cipher_mode,
                    peer_name=peer_name, own_name=own_name, own_private_key=own_private_key,
                    post_quantum=post_quantum,
                )
                print(f"\n  ✓ Transfer complete.")

        except HandshakeError as exc:
            log_error(f"Handshake error: {exc}")
            session.fail(str(exc))
            exit_code = 2

        except IntegrityError as exc:
            log_error(f"Integrity error: {exc}")
            session.fail(str(exc))
            exit_code = 3

        except SessionError as exc:
            log_error(f"Session error: {exc}")
            session.fail(str(exc))
            exit_code = 4

        except SecureTransferError as exc:
            log_error(f"Transfer error: {exc}")
            session.fail(str(exc))
            exit_code = 5

        except (ConnectionResetError, BrokenPipeError) as exc:
            log_error(f"Connection lost: {exc}")
            session.fail(str(exc))
            exit_code = 6

        finally:
            if bench_report is not None:
                report = stats if stats is not None else {
                    "role": "sender", "status": "failed", "exit_code": exit_code,
                    "chunk_size_bytes": chunk_size, "peak_rss_kb": _peak_rss_kb(),
                }
                report.setdefault("status", "success")
                try:
                    bench_report.parent.mkdir(parents=True, exist_ok=True)
                    with open(bench_report, "w") as f:
                        json.dump(report, f, indent=2)
                except OSError as exc:
                    log_error(f"Failed to write bench report to {bench_report}: {exc}")

        if exit_code != 0:
            sys.exit(exit_code)

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
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        metavar="BYTES",
        help=(
            f"Plaintext bytes per chunk before encryption. Default: "
            f"{DEFAULT_CHUNK_SIZE} (64 KB). Must be a multiple of 16 "
            "(AES-CBC block size)."
        ),
    )
    parser.add_argument(
        "--cipher-mode",
        choices=["gcm", "cbc"],
        default="gcm",
        help=(
            "AES cipher mode. 'gcm' (default, recommended): authenticated "
            "encryption, no padding step, per-chunk integrity. 'cbc': the "
            "original CBC+HMAC design, kept for comparison/benchmarking."
        ),
    )
    parser.add_argument(
        "--peer",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Enable mutual authentication: the receiver must present this "
            "exact identity name with a public key matching "
            "keys/<name>_public.pem, and we sign the key exchange with our "
            "own --key so the receiver can verify us too. Requires the "
            "receiver to also run with --peer. Omit for the original "
            "unauthenticated handshake."
        ),
    )
    parser.add_argument(
        "--post-quantum", "--pq",
        action="store_true",
        help=(
            "Combine an ML-KEM-768 encapsulated secret with the RSA secret "
            "(via HKDF) so the session key resists a future quantum attack "
            "on RSA. Requires --peer, and requires --key's identity to have "
            "an ML-KEM keypair (keygen.py --post-quantum). Requires the "
            "receiver to also use --post-quantum."
        ),
    )
    parser.add_argument(
        "--bench-report",
        type=str,
        default=None,
        metavar="PATH",
        help=(
            "Write a JSON file with per-transfer timing/memory stats "
            "(handshake vs. bulk-transfer latency, peak RSS) to PATH after "
            "the transfer finishes. Used by the benchmark suite; has no "
            "effect on the transfer itself."
        ),
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

    if args.chunk_size <= 0 or args.chunk_size % 16 != 0:
        parser.error(
            f"Invalid --chunk-size: {args.chunk_size}. Must be a positive "
            "multiple of 16 (AES-CBC block size)."
        )

    try:
        own_private_key = load_private_key(args.key)
        log_info(f"Sender private key loaded: '{args.key}'")
    except Exception as exc:
        parser.error(f"Failed to load private key '{args.key}': {exc}")

    if args.post_quantum and not args.peer:
        parser.error("--post-quantum requires --peer (mutual authentication) to also be set.")

    if args.peer:
        log_info(f"Mutual authentication enabled — expecting receiver '{args.peer}', signing as '{args.key}'"
                  + (" [post-quantum: ML-KEM-768 + RSA hybrid]" if args.post_quantum else ""))

    run_server(
        Path(args.file).resolve(),
        args.host,
        args.port,
        chunk_size=args.chunk_size,
        bench_report=Path(args.bench_report) if args.bench_report else None,
        cipher_mode="AES-256-GCM" if args.cipher_mode == "gcm" else "AES-256-CBC",
        peer_name=args.peer,
        own_name=args.key if args.peer else None,
        own_private_key=own_private_key if args.peer else None,
        post_quantum=args.post_quantum,
    )


if __name__ == "__main__":
    main()
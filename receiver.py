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
import json
import os
import shutil
import socket
import sys
import tempfile
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
        rsa_decrypt,
        unbundle_keys,
        decrypt_file_stream,
        verify_hmac,
        compute_sha256,
        unbundle_keys_gcm,
        decrypt_file_stream_gcm,
        verify_peer_identity,
        verify_signature,
        generate_challenge_nonce,
        derive_hybrid_session_key,
    )
    from protocol import (
        send_packet,
        recv_packet,
        PacketType,
        perform_receiver_handshake,
        parse_file_header,
        build_ack,
        build_error,
        build_hello_named,
        parse_key_exchange_signed,
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
DEFAULT_CHUNK_SIZE = 64 * 1024   # historical default fallback; actual chunk_size
                                  # used for THIS transfer is read from FILE_HEADER
                                  # (only affects the progress-bar speed/ETA display —
                                  # decrypt_file_stream() itself doesn't need it, see
                                  # crypto_utils.decrypt_file_stream docstring)
DEFAULT_PORT    = 9999
DEFAULT_HOST    = "127.0.0.1"
CONNECT_TIMEOUT = 30          # Seconds to wait for connection to sender
RECV_TIMEOUT    = 120         # Seconds to wait between packets

# Padding-oracle mitigation: ONE generic message used for every kind of
# post-handshake verification failure (CBC padding failure, HMAC mismatch,
# or any other decrypt-time error). Never send a message that reveals
# WHICH check failed — see the SECURITY NOTE in perform_transfer() below.
GENERIC_VERIFICATION_ERROR = "Transfer verification failed."

# Small fixed delay before responding to any verification failure, to
# reduce (not eliminate) timing distinguishability between a fast
# padding-removal failure and a slower full-HMAC-recompute failure. This
# is a practical mitigation, not a constant-time guarantee — see the
# paper's Security Analysis for the honest limits of this approach.
FAILURE_RESPONSE_DELAY_SECONDS = 0.25


def _send_generic_failure(conn: socket.socket) -> None:
    """Send the same generic ERROR packet regardless of whether the
    underlying failure was a CBC padding error, an HMAC mismatch, or
    something else — see GENERIC_VERIFICATION_ERROR."""
    time.sleep(FAILURE_RESPONSE_DELAY_SECONDS)
    try:
        send_packet(conn, PacketType.ERROR, build_error(GENERIC_VERIFICATION_ERROR))
    except OSError:
        # Connection may already be gone (e.g. sender disconnected) —
        # nothing more we can do, and this must not raise over the
        # original error being handled by the caller.
        pass


def _peak_rss_kb() -> Optional[int]:
    """Peak resident set size of this process, in KB, for the whole process
    lifetime so far. Returns None on platforms without the resource module."""
    if not _HAS_RESOURCE:
        return None
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return raw if sys.platform != "darwin" else raw // 1024


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
def _receive_encrypted_chunks(conn: socket.socket, total_chunks: int, progress: "ProgressBar"):
    """
    Generator: pulls FILE_CHUNK packets off the socket one at a time and
    yields their encrypted payloads, so decrypt_file_stream() can decrypt
    and write each chunk to disk as it arrives instead of the caller
    buffering the entire encrypted file in memory first.

    This is what keeps peak memory bounded by chunk_size rather than
    growing with file size. (Previously this receiver collected every
    encrypted chunk into a Python list -- encrypted_chunks = [];
    .append() per chunk -- before decrypting any of it, despite an inline
    comment claiming this kept memory bounded. It didn't: peak RSS scaled
    with file size, contradicting the README's "constant <10MB footprint"
    claim. The benchmark suite's peak_rss_kb measurements confirmed this
    empirically before this fix.)

    Any network or protocol error is raised as a SecureTransferError
    subclass rather than left as a bare OSError. This matters because
    decrypt_file_stream() wraps this generator's iteration in a
    try/except (OSError, IOError) intended to catch local file-WRITE
    errors -- a raw ConnectionResetError (which IS an OSError subclass)
    propagating up from recv_packet() would otherwise get relabeled as a
    misleading "File write error during decryption." SecureTransferError
    is not an OSError subclass, so it passes through that handler
    untouched and reaches perform_transfer()'s own except clause intact.

    Raises:
        SessionError on chunk-count mismatch, a sender-reported ERROR
        packet, an unexpected packet type, or any network-level failure.
    """
    chunks_received = 0
    while True:
        try:
            conn.settimeout(RECV_TIMEOUT)
            ptype, payload = recv_packet(conn)
        except SecureTransferError:
            raise
        except OSError as exc:
            raise SessionError(
                f"Socket error while receiving chunk {chunks_received + 1}: {exc}"
            ) from exc

        if ptype == PacketType.FILE_CHUNK:
            chunks_received += 1
            progress.update(chunks_received)
            yield payload

        elif ptype == PacketType.TRANSFER_END:
            progress.finish()
            if chunks_received != total_chunks:
                raise SessionError(
                    f"Chunk count mismatch: "
                    f"expected {total_chunks}, received {chunks_received}"
                )
            log_info(f"TRANSFER_END received — {chunks_received}/{total_chunks} chunks.")
            return

        elif ptype == PacketType.ERROR:
            raise SessionError(
                f"Sender reported an error: {payload.decode(errors='replace')}"
            )

        else:
            raise SessionError(
                f"Unexpected packet type during transfer: {ptype}"
            )


def perform_transfer(
    conn: socket.socket,
    private_key,
    public_key_pem: bytes,
    output_dir: Path,
    session: TransferSession,
    peer_name: str = None,
    own_name: str = None,
    post_quantum: bool = False,
    own_mlkem_private_key=None,
    own_mlkem_public_key_bytes: bytes = None,
) -> tuple:
    """
    Execute the full handshake + file reception over an established socket.

    Args:
        conn:           Connected socket to the sender.
        private_key:    Receiver's RSA private key object.
        public_key_pem: Receiver's RSA public key in PEM bytes (sent in HELLO).
        output_dir:     Directory where the received file will be saved.
        session:        TransferSession logger instance.
        peer_name:      If given, enables MUTUAL AUTHENTICATION: we send a
                        named HELLO claiming own_name, and require the
                        sender's KEY_EXCHANGE to be signed by a key
                        matching the locally trusted copy at
                        keys/<peer_name>_public.pem. If None (default),
                        falls back to the original unauthenticated
                        handshake — unchanged behavior for existing callers.
        own_name:       This receiver's own identity name (required if
                        peer_name is set — sent in the named HELLO).
        post_quantum:   If True, ALSO includes our ML-KEM-768 public key
                        in the named HELLO, and decapsulates the ML-KEM
                        ciphertext the sender sends back, combining that
                        secret with the RSA secret via HKDF (see
                        crypto_utils.derive_hybrid_session_key) — see
                        sender.py's perform_transfer docstring for the
                        full rationale. Requires peer_name.
        own_mlkem_private_key:      This receiver's ML-KEM private key
                                    object (required if post_quantum).
        own_mlkem_public_key_bytes: This receiver's ML-KEM public key,
                                    raw bytes (required if post_quantum).

    Returns:
        (output_path, stats) where stats is a dict of wall-clock timings
        (handshake_seconds, bulk_transfer_seconds measured around the REAL
        recv() calls, decrypt_seconds, hmac_verify_seconds, total_seconds)
        and peak_rss_kb. Used by --bench-report; harmless for normal runs.
    """
    if peer_name is not None and own_name is None:
        raise ValueError("peer_name requires own_name (mutual auth needs it for our own HELLO).")
    if post_quantum and peer_name is None:
        raise ValueError("post_quantum requires peer_name (mutual auth) to also be enabled.")
    if post_quantum and (own_mlkem_private_key is None or own_mlkem_public_key_bytes is None):
        raise ValueError("post_quantum requires own_mlkem_private_key and own_mlkem_public_key_bytes.")

    t_start = time.perf_counter()

    # ── Step 1: Handshake ───────────────────────────────────────────────────
    if peer_name is not None:
        # ── Mutual-auth handshake + replay protection ───────────────────
        # challenge_nonce is fresh random bytes generated for THIS
        # connection attempt only (crypto_utils.generate_challenge_nonce).
        # The sender must sign encrypted_bundle + challenge_nonce, not
        # just encrypted_bundle — this is what makes a captured old
        # session unreplayable against a new connection: the replayed
        # signature was computed over a DIFFERENT (old) nonce, so it
        # won't match what we verify against here.
        challenge_nonce = generate_challenge_nonce()
        log_info(f"Sending named HELLO as '{own_name}' (mutual auth, expecting sender '{peer_name}')"
                 f"{', post-quantum (ML-KEM-768 + RSA)' if post_quantum else ''}…")
        try:
            send_packet(
                conn, PacketType.HELLO,
                build_hello_named(
                    public_key_pem, own_name, challenge_nonce,
                    mlkem_public_key=own_mlkem_public_key_bytes if post_quantum else None,
                )
            )
            ptype, kx_payload = recv_packet(conn)
        except Exception as exc:
            raise HandshakeError(f"Handshake failed: {exc}") from exc

        if ptype != PacketType.KEY_EXCHANGE:
            raise HandshakeError(f"Expected KEY_EXCHANGE, got {ptype}")

        try:
            kx = parse_key_exchange_signed(kx_payload)
        except Exception as exc:
            raise HandshakeError(
                f"Failed to parse signed KEY_EXCHANGE — is the sender also "
                f"using --peer? {exc}"
            ) from exc

        if kx["sender_name"] != peer_name:
            raise AuthenticationError(
                f"Sender claimed identity '{kx['sender_name']}', expected '{peer_name}'.",
                details="Refusing to proceed — this could be a wrong peer or an impersonation attempt."
            )

        # Look up the LOCALLY trusted public key for the claimed sender —
        # the sender's key is never transmitted on the wire in the signed
        # KEY_EXCHANGE format, deliberately, so this can only ever verify
        # against a key we already had on file.
        try:
            with open(os.path.join("keys", f"{peer_name}_public.pem"), "rb") as f:
                sender_trusted_pubkey_pem = f.read()
        except OSError as exc:
            raise AuthenticationError(
                f"No trusted public key on file for '{peer_name}'.",
                details=f"Expected at: keys/{peer_name}_public.pem ({exc})"
            )
        from Crypto.PublicKey import RSA as _RSA
        sender_trusted_pubkey = _RSA.import_key(sender_trusted_pubkey_pem)

        if post_quantum and not kx["mlkem_ciphertext"]:
            raise HandshakeError(
                "post_quantum requested but the sender's KEY_EXCHANGE did "
                "not include an ML-KEM ciphertext — is the sender also "
                "using --post-quantum?"
            )

        # Verifying over (encrypted_bundle + challenge_nonce [+ mlkem_ciphertext]),
        # NOT just encrypted_bundle, is the actual replay-protection check
        # (a signature captured from a past session was computed over that
        # past session's different nonce, and will fail here) — extended to
        # also bind the ML-KEM ciphertext so it can't be swapped in transit.
        signature_input = kx["encrypted_bundle"] + challenge_nonce + (kx["mlkem_ciphertext"] or b"")
        try:
            verify_signature(sender_trusted_pubkey, signature_input, kx["signature"])
        except AuthenticationError as exc:
            raise AuthenticationError(
                "Signature verification failed — this may be a replayed "
                "old session (bound to a stale challenge) as well as a "
                "possible impersonation attempt.",
                details=str(exc)
            ) from exc
        log_info(f"✓ Sender identity verified: '{peer_name}' (fresh session, not a replay)")

        mlkem_secret = None
        if post_quantum:
            try:
                mlkem_secret = own_mlkem_private_key.decapsulate(kx["mlkem_ciphertext"])
                log_info("✓ ML-KEM-768 decapsulation complete (post-quantum secret recovered)")
            except Exception as exc:
                raise HandshakeError(f"ML-KEM decapsulation failed: {exc}") from exc

        encrypted_bundle = kx["encrypted_bundle"]

    else:
        # ── Original, unauthenticated handshake (unchanged) ─────────────
        # perform_receiver_handshake(sock, public_key_pem) → encrypted_bundle bytes
        log_info("Sending HELLO with receiver public key…")
        try:
            encrypted_bundle = perform_receiver_handshake(conn, public_key_pem)
        except Exception as exc:
            raise HandshakeError(f"Handshake failed: {exc}") from exc

    # Decrypt the RSA bundle, but do NOT unbundle it yet — whether it's a
    # GCM bundle (just an AES key) or a CBC bundle (AES key + HMAC key,
    # length-prefixed) depends on cipher_mode, which we don't learn until
    # FILE_HEADER arrives in Step 2. Unbundling with the wrong format
    # would silently misparse the bytes, so we wait.
    try:
        raw_bundle = rsa_decrypt(private_key, encrypted_bundle)
    except Exception as exc:
        raise HandshakeError(f"Key bundle decryption failed: {exc}") from exc

    t_handshake_done = time.perf_counter()
    log_info(f"Handshake complete — session keys recovered. "
             f"({t_handshake_done - t_start:.4f}s)")

    # ── Step 2: Receive FILE_HEADER ─────────────────────────────────────────
    # Bulk-transfer timing starts here — real recv() calls, mirroring where
    # sender.py starts its own bulk_transfer_seconds measurement.
    t_bulk_start = time.perf_counter()

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
        chunk_size   = header["chunk_size"]   # bytes/chunk the sender used (display only)
        cipher_mode  = header["cipher_mode"]
    except Exception as exc:
        raise SessionError(f"Failed to parse FILE_HEADER: {exc}") from exc

    log_info(
        f"Incoming file : '{filename}'  "
        f"({file_size:,} bytes, {total_chunks} chunk(s) of {chunk_size // 1024} KB, "
        f"{cipher_mode})"
    )

    # Now that cipher_mode is known, derive/unbundle the actual session
    # key material. Post-quantum mode combines the RSA secret (raw_bundle,
    # which in PQ mode is just the 32-byte RSA-decrypted secret, not a
    # further-bundled structure) with the ML-KEM secret via HKDF; classical
    # mode uses the original unbundle_keys_gcm/unbundle_keys functions,
    # unchanged.
    try:
        if post_quantum:
            if cipher_mode == "AES-256-GCM":
                needed_bytes = 32 + 8    # aes_key + base_nonce
            else:
                needed_bytes = 32 + 16 + 32   # aes_key + iv + hmac_key
            combined = derive_hybrid_session_key(raw_bundle, mlkem_secret, key_length=needed_bytes)

            if cipher_mode == "AES-256-GCM":
                aes_key    = combined[:32]
                base_nonce = combined[32:40]
            else:
                aes_key     = combined[:32]
                iv          = combined[32:48]
                hmac_key    = combined[48:80]
                hmac_digest = header["hmac"]   # transmitted value to check against — not derived
        else:
            if cipher_mode == "AES-256-GCM":
                aes_key    = unbundle_keys_gcm(raw_bundle)
                base_nonce = header["nonce"]
            else:
                aes_key, hmac_key = unbundle_keys(raw_bundle)
                iv          = header["iv"]     # bytes (parse_file_header decodes hex → bytes)
                hmac_digest = header["hmac"]   # bytes — key is "hmac", not "hmac_digest"
    except Exception as exc:
        raise HandshakeError(f"Failed to unbundle/derive keys for {cipher_mode}: {exc}") from exc

    # ── Steps 3-4: Receive FILE_CHUNK packets, decrypting each AS IT ARRIVES ─
    # Still within the bulk_transfer_seconds window started at Step 2. Real
    # recv() calls interleaved with real decrypt+write calls -- receiving
    # and decrypting are pipelined by design now (see
    # _receive_encrypted_chunks docstring), so there's no separate
    # decrypt_seconds bucket anymore: the whole point of the fix is that
    # there's no longer a distinct "receive everything, then decrypt
    # everything" phase boundary to measure separately.
    tmp_decrypted = tempfile.NamedTemporaryFile(
        delete=False, suffix=".dec", dir=tempfile.gettempdir()
    )
    tmp_decrypted_path = Path(tmp_decrypted.name)
    tmp_decrypted.close()

    log_info(f"Receiving and decrypting '{filename}'…")
    progress = ProgressBar(total_chunks, filename, chunk_size=chunk_size)

    if cipher_mode == "AES-256-GCM":
        # GCM decrypts and authenticates each chunk in ONE call
        # (decrypt_and_verify) — there is no separate padding step and
        # therefore no padding-failure-vs-authentication-failure
        # distinction to leak in the first place. Still routed through
        # _send_generic_failure for a consistent network-visible response,
        # but structurally there is only one failure mode here, not two.
        try:
            decrypt_file_stream_gcm(
                _receive_encrypted_chunks(conn, total_chunks, progress),
                aes_key,
                base_nonce,
                str(tmp_decrypted_path),
                total_chunks,
            )
        except SecureTransferError:
            tmp_decrypted_path.unlink(missing_ok=True)
            _send_generic_failure(conn)
            raise
        except Exception as exc:
            tmp_decrypted_path.unlink(missing_ok=True)
            _send_generic_failure(conn)
            raise SessionError(f"Receive/decrypt failed: {exc}") from exc
        t_bulk_done   = time.perf_counter()
        t_verify_done = t_bulk_done   # no separate verify phase for GCM
        log_info(f"Receive+decrypt+verify (GCM) completed in {t_bulk_done - t_bulk_start:.4f}s")

    else:
        # SECURITY NOTE (padding-oracle mitigation): a CBC padding failure
        # here and an HMAC failure below are DIFFERENT internal error
        # conditions, but an adversary on the network must NOT be able to
        # tell them apart from the outside. Both paths therefore:
        #   (a) send the exact same GENERIC_VERIFICATION_ERROR message —
        #       never a padding-specific or HMAC-specific one,
        #   (b) go through the same _send_generic_failure() helper, which
        #       adds a small fixed delay to reduce (not eliminate — see
        #       paper Security Analysis) timing distinguishability between
        #       "failed during decryption" and "failed during HMAC
        #       verification".
        # This does not make the underlying MAC-then-encrypt construction
        # as safe as encrypt-then-MAC would be — it only removes the
        # specific oracle this implementation's error handling created.
        # The AES-256-GCM path above removes the padding step — and
        # therefore this entire attack class — structurally, which is why
        # GCM is the default cipher_mode now.
        try:
            decrypt_file_stream(
                _receive_encrypted_chunks(conn, total_chunks, progress),
                aes_key,
                iv,
                str(tmp_decrypted_path),
                total_chunks,
            )
        except SecureTransferError:
            tmp_decrypted_path.unlink(missing_ok=True)
            _send_generic_failure(conn)
            raise
        except Exception as exc:
            tmp_decrypted_path.unlink(missing_ok=True)
            _send_generic_failure(conn)
            raise SessionError(f"Receive/decrypt failed: {exc}") from exc
        t_bulk_done = time.perf_counter()
        log_info(f"Receive+decrypt completed in {t_bulk_done - t_bulk_start:.4f}s")

        # ── Step 5 (CBC only): Verify whole-file HMAC ───────────────────────
        log_info("Verifying HMAC-SHA256 integrity…")
        try:
            # verify_hmac(hmac_key, filepath, expected_hmac) → True or raises IntegrityError
            verify_hmac(hmac_key, str(tmp_decrypted_path), hmac_digest)
        except IntegrityError:
            tmp_decrypted_path.unlink(missing_ok=True)
            _send_generic_failure(conn)
            raise
        except Exception as exc:
            tmp_decrypted_path.unlink(missing_ok=True)
            _send_generic_failure(conn)
            raise IntegrityError(f"HMAC verification error: {exc}") from exc
        t_verify_done = time.perf_counter()

    checksum = compute_sha256(str(tmp_decrypted_path))
    log_info(f"✓ Integrity verified.  SHA-256: {checksum}")

    # ── Step 6: Send ACK ────────────────────────────────────────────────────
    # When mutual authentication is active (--peer), send a key-confirmation
    # MAC instead of a plain text ACK: HMAC-SHA256(aes_key, challenge_nonce
    # || b'sftp-hybrid-confirm').  Only a receiver that successfully derived
    # the same session key can produce a valid MAC, giving the sender
    # cryptographic proof that Ks is genuinely shared — closing the G4b gap
    # identified in the BAN logic analysis.
    # Without mutual auth there is no identity-bound challenge_nonce, so
    # we fall back to the original plain-text ACK.
    if peer_name is not None:
        from protocol import build_ack_confirmation
        ack_mac = build_ack_confirmation(aes_key, challenge_nonce)
        send_packet(conn, PacketType.ACK, ack_mac)
        log_info("✓ Key-confirmation ACK sent (HMAC-SHA256 over session key + nonce).")
    else:
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

    t_end = time.perf_counter()

    # Update session with final info and mark complete
    session.bytes_transferred = file_size
    session.complete(checksum=checksum)

    stats = {
        "role"                  : "receiver",
        "cipher_mode"           : cipher_mode,
        "file_size_bytes"       : file_size,
        "chunk_size_bytes"      : chunk_size,
        "total_chunks"          : total_chunks,
        "handshake_seconds"     : t_handshake_done - t_start,
        "bulk_transfer_seconds" : t_bulk_done - t_bulk_start,
        "hmac_verify_seconds"   : t_verify_done - t_bulk_done,
        "total_seconds"         : t_end - t_start,
        "peak_rss_kb"           : _peak_rss_kb(),
        "checksum"              : checksum,
    }

    return output_path, stats


# ---------------------------------------------------------------------------
# Client Lifecycle
# ---------------------------------------------------------------------------
def run_client(
    host: str,
    port: int,
    key_name: str,
    output_dir: Path,
    bench_report: Optional[Path] = None,
    peer_name: str = None,
    post_quantum: bool = False,
):
    """Connect to the sender and run the full secure file reception flow.

    Args:
        bench_report: if given, write a JSON file here with the stats dict
            returned by perform_transfer after the transfer finishes —
            success or failure. Used by the benchmark suite; no effect on
            normal transfers when omitted.
        peer_name: if given, enables mutual authentication — see
            perform_transfer's docstring. Requires the sender to also
            use --peer.
        post_quantum: hybrid RSA + ML-KEM key exchange — see
            perform_transfer's docstring. Requires peer_name, and requires
            key_name's identity to have an ML-KEM keypair on file
            (keygen.py --post-quantum).
    """

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

    own_mlkem_private_key = None
    own_mlkem_public_key_bytes = None
    if post_quantum:
        try:
            from keygen import load_mlkem_private_key, load_mlkem_public_key
            own_mlkem_private_key = load_mlkem_private_key(key_name)
            own_mlkem_public_key_bytes = load_mlkem_public_key(key_name).public_bytes_raw()
            log_info(f"ML-KEM-768 key pair loaded: '{key_name}'")
        except Exception as exc:
            log_error(f"Failed to load ML-KEM keys '{key_name}': {exc}")
            log_error(f"Run: python keygen.py --name {key_name} --post-quantum")
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

    stats = None
    exit_code = 0
    try:
        with sock:
            sock.settimeout(RECV_TIMEOUT)
            output_path, stats = perform_transfer(
                sock, private_key, public_key_pem, output_dir, session,
                peer_name=peer_name, own_name=key_name if peer_name else None,
                post_quantum=post_quantum,
                own_mlkem_private_key=own_mlkem_private_key,
                own_mlkem_public_key_bytes=own_mlkem_public_key_bytes,
            )

            print(f"\n  ✓ Transfer complete → {output_path}")

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
        log_error(f"Connection lost mid-transfer: {exc}")
        session.fail(str(exc))
        exit_code = 6

    finally:
        if bench_report is not None:
            report = stats if stats is not None else {
                "role": "receiver", "status": "failed", "exit_code": exit_code,
                "peak_rss_kb": _peak_rss_kb(),
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
        "--bench-report",
        type=str,
        default=None,
        metavar="PATH",
        help=(
            "Write a JSON file with per-transfer timing/memory stats "
            "(handshake vs. bulk-transfer latency, decrypt/HMAC-verify "
            "time, peak RSS) to PATH after the transfer finishes. Used by "
            "the benchmark suite; has no effect on the transfer itself."
        ),
    )
    parser.add_argument(
        "--peer",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Enable mutual authentication: we send a named HELLO as our "
            "own --key, and require the sender's KEY_EXCHANGE to be "
            "signed by a key matching keys/<name>_public.pem for this "
            "peer name. Requires the sender to also run with --peer. "
            "Omit for the original unauthenticated handshake."
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
            "sender to also use --post-quantum."
        ),
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

    if args.post_quantum and not args.peer:
        parser.error("--post-quantum requires --peer (mutual authentication) to also be set.")

    run_client(
        host         = args.host,
        port         = args.port,
        key_name     = args.key,
        output_dir   = Path(args.output),
        bench_report = Path(args.bench_report) if args.bench_report else None,
        peer_name    = args.peer,
        post_quantum = args.post_quantum,
    )


if __name__ == "__main__":
    main()
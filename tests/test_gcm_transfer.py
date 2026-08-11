"""
Regression tests for the AES-256-GCM transfer path.

Uses the same hand-crafted-sender-over-a-real-socketpair pattern as
tests/test_padding_oracle_mitigation.py: a genuine RSA handshake, genuine
AES-256-GCM encryption via crypto_utils, driving the REAL
receiver.perform_transfer(). This is deliberately NOT a mock — it proves
the actual wire protocol (HELLO -> KEY_EXCHANGE -> FILE_HEADER ->
FILE_CHUNK* -> TRANSFER_END -> ACK/ERROR) works for GCM end to end, not
just that the underlying crypto_utils functions round-trip in isolation.
"""
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from Crypto.PublicKey import RSA

from crypto_utils import (
    generate_session_key_gcm,
    bundle_keys_gcm,
    rsa_encrypt,
    encrypt_file_stream_gcm,
    compute_sha256,
)
from protocol import (
    send_packet,
    recv_packet,
    PacketType,
    build_key_exchange,
    build_file_header,
    build_file_chunk,
    build_transfer_end,
)
from keygen import load_private_key, load_public_key
from logger import TransferSession

import receiver as receiver_module

KEYS_DIR = Path(__file__).resolve().parent.parent / "keys"


class _FakeGcmSender:
    """Speaks the real protocol using real AES-256-GCM encryption, with
    the ability to corrupt one specific chunk's ciphertext+tag before
    sending it (to test tamper detection)."""

    def __init__(self, sock, plaintext_path, chunk_size=64 * 1024,
                 corrupt_chunk_index=None):
        self.sock = sock
        self.plaintext_path = plaintext_path
        self.chunk_size = chunk_size
        self.corrupt_chunk_index = corrupt_chunk_index
        self.result = None

    def run(self):
        ptype, hello_payload = recv_packet(self.sock)
        assert ptype == PacketType.HELLO
        receiver_pubkey = RSA.import_key(hello_payload)

        aes_key, base_nonce = generate_session_key_gcm()
        bundle = bundle_keys_gcm(aes_key)
        encrypted_bundle = rsa_encrypt(receiver_pubkey, bundle)
        send_packet(self.sock, PacketType.KEY_EXCHANGE, build_key_exchange(encrypted_bundle))

        file_size = os.path.getsize(self.plaintext_path)
        total_chunks = max(1, -(-file_size // self.chunk_size))

        header_payload = build_file_header(
            filename="test.bin", file_size=file_size, total_chunks=total_chunks,
            chunk_size=self.chunk_size, cipher_mode="AES-256-GCM", nonce=base_nonce,
        )
        send_packet(self.sock, PacketType.FILE_HEADER, header_payload)

        chunks = list(encrypt_file_stream_gcm(
            self.plaintext_path, aes_key, base_nonce, chunk_size=self.chunk_size
        ))

        if self.corrupt_chunk_index is not None:
            idx = self.corrupt_chunk_index
            corrupted = bytearray(chunks[idx])
            corrupted[0] ^= 0x01   # flip a bit in the ciphertext
            chunks[idx] = bytes(corrupted)

        try:
            for chunk in chunks:
                send_packet(self.sock, PacketType.FILE_CHUNK, build_file_chunk(chunk))
            send_packet(self.sock, PacketType.TRANSFER_END, build_transfer_end())
        except Exception:
            # Expected when the receiver detects tampering on an early
            # chunk and closes the connection before we finish sending —
            # that's the per-chunk early-detection behavior being tested.
            self.result = ("EXCEPTION", "sender-side send failed (receiver likely closed early)")
            return

        try:
            ptype, payload = recv_packet(self.sock)
            self.result = (ptype, payload)
        except Exception as exc:
            self.result = ("EXCEPTION", str(exc))


class TestGcmTransfer(unittest.TestCase):

    def _run_transfer(self, plaintext_path, **kwargs):
        sender_sock, receiver_sock = socket.socketpair()
        fake_sender = _FakeGcmSender(sender_sock, plaintext_path, **kwargs)
        t = threading.Thread(target=fake_sender.run, daemon=True)
        t.start()

        private_key = load_private_key("bob")
        public_key_pem = load_public_key("bob").export_key(format="PEM")
        output_dir = Path(tempfile.mkdtemp())
        session = TransferSession(role="receiver", filepath="test.bin", peer_address="test:0")

        outcome = {}
        try:
            output_path, stats = receiver_module.perform_transfer(
                receiver_sock, private_key, public_key_pem, output_dir, session,
            )
            outcome["status"] = "success"
            outcome["output_path"] = output_path
            outcome["stats"] = stats
        except Exception as exc:
            outcome["status"] = "failed"
            outcome["exception"] = str(exc)

        t.join(timeout=10)
        receiver_sock.close()
        return outcome, fake_sender.result

    def setUp(self):
        if not (KEYS_DIR / "bob_private.pem").exists():
            self.skipTest("test key pair not present; run keygen.py first")

    def test_gcm_round_trip_matches_original(self):
        tmp = Path(tempfile.mkdtemp())
        plaintext_path = tmp / "plain.bin"
        original = os.urandom(64 * 1024 * 3 + 1000)  # multi-chunk, non-round size
        plaintext_path.write_bytes(original)

        outcome, wire_result = self._run_transfer(str(plaintext_path))

        self.assertEqual(outcome["status"], "success")
        received = outcome["output_path"].read_bytes()
        self.assertEqual(received, original)
        self.assertEqual(outcome["stats"]["cipher_mode"], "AES-256-GCM")
        # GCM has no separate verify phase - hmac_verify_seconds should
        # be ~0 since t_verify_done == t_bulk_done for this path.
        self.assertAlmostEqual(outcome["stats"]["hmac_verify_seconds"], 0.0, delta=0.01)

    def test_gcm_detects_tampered_chunk(self):
        tmp = Path(tempfile.mkdtemp())
        plaintext_path = tmp / "plain.bin"
        plaintext_path.write_bytes(os.urandom(64 * 1024 * 3 + 1000))

        outcome, wire_result = self._run_transfer(str(plaintext_path), corrupt_chunk_index=1)

        self.assertEqual(outcome["status"], "failed")
        self.assertIn("GCM authentication failed", outcome["exception"])
        # And the wire response should be the same generic error used
        # everywhere else (see test_padding_oracle_mitigation.py).
        self.assertIsNotNone(wire_result)
        ptype, payload = wire_result
        self.assertEqual(ptype, PacketType.ERROR)

    def test_gcm_tampering_detected_on_first_bad_chunk_not_last(self):
        """Confirms per-chunk authentication: corrupting an EARLY chunk in
        a multi-chunk file is caught immediately, not only after all
        chunks have been received (unlike the whole-file HMAC in the CBC
        path, which can only detect corruption after everything arrives).
        """
        tmp = Path(tempfile.mkdtemp())
        plaintext_path = tmp / "plain.bin"
        plaintext_path.write_bytes(os.urandom(64 * 1024 * 5))  # 5 chunks

        outcome, _ = self._run_transfer(str(plaintext_path), corrupt_chunk_index=0)

        self.assertEqual(outcome["status"], "failed")
        self.assertIn("chunk 1/5", outcome["exception"])


if __name__ == "__main__":
    unittest.main()

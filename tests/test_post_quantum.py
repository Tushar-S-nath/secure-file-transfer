"""
Regression tests for post-quantum hybrid key exchange (RSA + ML-KEM-768).

Same hand-crafted-sender-over-a-real-socketpair pattern as
test_mutual_auth.py: a genuine RSA+ML-KEM handshake, genuine encryption,
driving the REAL receiver.perform_transfer() -- not a mock.
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
from cryptography.hazmat.primitives.asymmetric import mlkem

from crypto_utils import (
    sign_data,
    rsa_encrypt,
    generate_session_key_gcm,
    bundle_keys_gcm,
    encrypt_file_stream_gcm,
    derive_hybrid_session_key,
)
from protocol import (
    send_packet,
    recv_packet,
    PacketType,
    parse_hello_named,
    build_key_exchange_signed,
    build_file_header,
    build_file_chunk,
    build_transfer_end,
)
from exceptions import AuthenticationError
from keygen import load_private_key, load_public_key, load_mlkem_private_key, load_mlkem_public_key
from logger import TransferSession
from Crypto.Random import get_random_bytes

import receiver as receiver_module

KEYS_DIR = Path(__file__).resolve().parent.parent / "keys"


class _FakePqSender:
    """Plays the sender's role in a post-quantum handshake against the
    REAL receiver.perform_transfer(): receives the receiver's named
    HELLO (including its ML-KEM public key), performs REAL ML-KEM
    encapsulation and REAL RSA encryption, combines both via the REAL
    hybrid KDF, signs everything (optionally tampering with the
    ciphertext AFTER signing, to test that tampering is caught)."""

    def __init__(self, sock, plaintext_path, signing_key, claimed_name,
                 chunk_size=64 * 1024, tamper_ciphertext_after_signing=False):
        self.sock = sock
        self.plaintext_path = plaintext_path
        self.signing_key = signing_key
        self.claimed_name = claimed_name
        self.chunk_size = chunk_size
        self.tamper_ciphertext_after_signing = tamper_ciphertext_after_signing
        self.result = None

    def run(self):
        ptype, hello_payload = recv_packet(self.sock)
        assert ptype == PacketType.HELLO
        hello = parse_hello_named(hello_payload)
        assert hello["mlkem_public_key"] is not None, "receiver did not offer an ML-KEM public key"

        receiver_rsa_pubkey = RSA.import_key(hello["public_key"])
        receiver_mlkem_pubkey = mlkem.MLKEM768PublicKey.from_public_bytes(hello["mlkem_public_key"])

        mlkem_secret, mlkem_ciphertext = receiver_mlkem_pubkey.encapsulate()
        rsa_secret = get_random_bytes(32)
        encrypted_bundle = rsa_encrypt(receiver_rsa_pubkey, rsa_secret)

        combined = derive_hybrid_session_key(rsa_secret, mlkem_secret, key_length=40)
        aes_key, base_nonce = combined[:32], combined[32:40]

        signature_input = encrypted_bundle + hello["challenge_nonce"] + mlkem_ciphertext
        signature = sign_data(self.signing_key, signature_input)

        if self.tamper_ciphertext_after_signing:
            # Swap in a DIFFERENT (still validly-shaped) ciphertext AFTER
            # signing -- the signature was computed over the ORIGINAL
            # ciphertext, so this should be caught by signature verification.
            tampered = bytearray(mlkem_ciphertext)
            tampered[0] ^= 0xFF
            mlkem_ciphertext = bytes(tampered)

        send_packet(
            self.sock, PacketType.KEY_EXCHANGE,
            build_key_exchange_signed(encrypted_bundle, self.claimed_name, signature,
                                       mlkem_ciphertext=mlkem_ciphertext)
        )

        file_size = os.path.getsize(self.plaintext_path)
        total_chunks = max(1, -(-file_size // self.chunk_size))
        header_payload = build_file_header(
            filename="test.bin", file_size=file_size, total_chunks=total_chunks,
            chunk_size=self.chunk_size, cipher_mode="AES-256-GCM", nonce=base_nonce,
        )

        try:
            send_packet(self.sock, PacketType.FILE_HEADER, header_payload)
            for chunk in encrypt_file_stream_gcm(self.plaintext_path, aes_key, base_nonce,
                                                   chunk_size=self.chunk_size):
                send_packet(self.sock, PacketType.FILE_CHUNK, build_file_chunk(chunk))
            send_packet(self.sock, PacketType.TRANSFER_END, build_transfer_end())
            ptype, payload = recv_packet(self.sock)
            self.result = (ptype, payload)
        except Exception as exc:
            self.result = ("EXCEPTION", str(exc))


class TestPostQuantumHandshake(unittest.TestCase):

    def setUp(self):
        required = [
            KEYS_DIR / "alice_private.pem", KEYS_DIR / "bob_private.pem",
            KEYS_DIR / "alice_mlkem_private.bin", KEYS_DIR / "bob_mlkem_private.bin",
        ]
        if not all(p.exists() for p in required):
            self.skipTest("PQ test keys not present; run keygen.py --post-quantum for alice/bob first")

    def _run(self, tamper_ciphertext_after_signing=False):
        tmp = Path(tempfile.mkdtemp())
        plaintext_path = tmp / "plain.bin"
        plaintext_path.write_bytes(os.urandom(64 * 1024 * 2 + 500))

        sender_sock, receiver_sock = socket.socketpair()
        alice_private = load_private_key("alice")
        fake_sender = _FakePqSender(sender_sock, str(plaintext_path), alice_private, "alice",
                                     tamper_ciphertext_after_signing=tamper_ciphertext_after_signing)
        t = threading.Thread(target=fake_sender.run, daemon=True)
        t.start()

        bob_private = load_private_key("bob")
        bob_public_pem = load_public_key("bob").export_key(format="PEM")
        bob_mlkem_private = load_mlkem_private_key("bob")
        bob_mlkem_public_bytes = load_mlkem_public_key("bob").public_bytes_raw()

        output_dir = Path(tempfile.mkdtemp())
        session = TransferSession(role="receiver", filepath="test.bin", peer_address="test:0")

        outcome = {}
        try:
            output_path, stats = receiver_module.perform_transfer(
                receiver_sock, bob_private, bob_public_pem, output_dir, session,
                peer_name="alice", own_name="bob",
                post_quantum=True,
                own_mlkem_private_key=bob_mlkem_private,
                own_mlkem_public_key_bytes=bob_mlkem_public_bytes,
            )
            outcome["status"] = "success"
            outcome["output_path"] = output_path
            outcome["original"] = plaintext_path.read_bytes()
        except Exception as exc:
            outcome["status"] = "failed"
            outcome["exception"] = str(exc)
            outcome["exception_type"] = type(exc).__name__

        t.join(timeout=10)
        receiver_sock.close()
        return outcome

    def test_legitimate_pq_transfer_succeeds(self):
        outcome = self._run()
        self.assertEqual(outcome["status"], "success")
        self.assertEqual(outcome["output_path"].read_bytes(), outcome["original"])

    def test_tampered_mlkem_ciphertext_rejected(self):
        """The core proof that the signature actually protects the
        ML-KEM ciphertext: swapping it AFTER signing (but before sending)
        must be caught, exactly like tampering with encrypted_bundle would be."""
        outcome = self._run(tamper_ciphertext_after_signing=True)
        self.assertEqual(outcome["status"], "failed")
        self.assertEqual(outcome["exception_type"], "AuthenticationError")

    def test_post_quantum_requires_peer_name(self):
        with self.assertRaises(ValueError):
            receiver_module.perform_transfer(
                None, None, None, None, None,
                post_quantum=True, peer_name=None,
            )


if __name__ == "__main__":
    unittest.main()

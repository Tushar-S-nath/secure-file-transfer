"""
Regression test for the padding-oracle mitigation in receiver.py.

Runs the REAL receiver.perform_transfer() against a hand-crafted 'sender'
that performs a genuine handshake and genuine AES/HMAC, then deliberately
corrupts the ciphertext in two different ways:

  (a) flips a bit in the LAST chunk -> breaks PKCS#7 padding
      -> decrypt_file_stream() raises during decryption (padding-failure path)

  (b) flips a bit in a MIDDLE chunk (not the last one) -> padding still
      validates (only the last chunk's padding is checked), but the
      plaintext is now wrong -> HMAC verification fails (HMAC-failure path)

Before the fix, (a) produced NO network response (silent connection drop)
while (b) produced an explicit ERROR packet with HMAC-specific wording --
a clear oracle. This test asserts both now produce the exact same
ERROR message, closing that asymmetry.
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
    generate_session_key,
    generate_hmac_key,
    bundle_keys,
    rsa_encrypt,
    encrypt_file_stream,
    compute_hmac,
)
from protocol import (
    send_packet,
    recv_packet,
    PacketType,
    build_hello,
    build_key_exchange,
    build_file_header,
    build_file_chunk,
    build_transfer_end,
)
from keygen import load_private_key, load_public_key

import receiver as receiver_module


KEYS_DIR = Path(__file__).resolve().parent.parent / "keys"


def _socketpair():
    return socket.socketpair()


class _FakeSender:
    """Speaks just enough of the real protocol to drive perform_transfer(),
    with the ability to corrupt one specific chunk's ciphertext before
    sending it."""

    def __init__(self, sock, plaintext_path, corrupt_chunk_index=None,
                 corrupt_last_chunk=False):
        self.sock = sock
        self.plaintext_path = plaintext_path
        self.corrupt_chunk_index = corrupt_chunk_index
        self.corrupt_last_chunk = corrupt_last_chunk

    def run(self):
        ptype, hello_payload = recv_packet(self.sock)
        assert ptype == PacketType.HELLO
        receiver_pubkey = RSA.import_key(hello_payload)

        aes_key, iv = generate_session_key()
        hmac_key = generate_hmac_key()
        bundle = bundle_keys(aes_key, hmac_key)
        encrypted_bundle = rsa_encrypt(receiver_pubkey, bundle)
        send_packet(self.sock, PacketType.KEY_EXCHANGE, build_key_exchange(encrypted_bundle))

        file_size = os.path.getsize(self.plaintext_path)
        chunk_size = 64 * 1024
        total_chunks = max(1, -(-file_size // chunk_size))
        hmac_digest = compute_hmac(hmac_key, self.plaintext_path)

        header_payload = build_file_header(
            filename="test.bin", file_size=file_size, total_chunks=total_chunks,
            iv=iv, hmac_digest=hmac_digest, chunk_size=chunk_size,
        )
        send_packet(self.sock, PacketType.FILE_HEADER, header_payload)

        chunks = list(encrypt_file_stream(self.plaintext_path, aes_key, iv, chunk_size=chunk_size))

        if self.corrupt_last_chunk:
            self.corrupt_chunk_index = len(chunks) - 1

        if self.corrupt_chunk_index is not None:
            idx = self.corrupt_chunk_index
            corrupted = bytearray(chunks[idx])
            # Flip one bit roughly in the middle of the chunk. For the
            # LAST chunk this lands inside the final ciphertext block,
            # which (after CBC decryption) corrupts the padding bytes
            # themselves -> padding failure. For a MIDDLE chunk it just
            # corrupts that block's plaintext after decryption -> wrong
            # file content -> HMAC failure, but padding is untouched
            # because only the true last block's padding is ever checked.
            flip_pos = len(corrupted) // 2
            corrupted[flip_pos] ^= 0x01
            chunks[idx] = bytes(corrupted)

        for chunk in chunks:
            send_packet(self.sock, PacketType.FILE_CHUNK, build_file_chunk(chunk))

        send_packet(self.sock, PacketType.TRANSFER_END, build_transfer_end())

        # Read back whatever the receiver sends (ERROR or ACK) and stash it.
        try:
            ptype, payload = recv_packet(self.sock)
            self.result = (ptype, payload)
        except Exception as exc:
            self.result = ("EXCEPTION", str(exc))


class TestPaddingOracleMitigation(unittest.TestCase):

    def _run_one_transfer(self, plaintext_path, **corruption_kwargs):
        sender_sock, receiver_sock = _socketpair()

        fake_sender = _FakeSender(sender_sock, plaintext_path, **corruption_kwargs)
        t = threading.Thread(target=fake_sender.run, daemon=True)
        t.start()

        private_key = load_private_key("bob")
        public_key_pem = load_public_key("bob").export_key(format="PEM")
        output_dir = Path(tempfile.mkdtemp())

        from logger import TransferSession
        session = TransferSession(role="receiver", filepath="test.bin",
                                   peer_address="test:0")

        result_holder = {}
        try:
            output_path, stats = receiver_module.perform_transfer(
                receiver_sock, private_key, public_key_pem, output_dir, session,
            )
            result_holder["outcome"] = "success"
        except Exception as exc:
            result_holder["outcome"] = "failed"
            result_holder["exception"] = str(exc)

        t.join(timeout=10)
        receiver_sock.close()
        return result_holder, getattr(fake_sender, "result", None)

    def test_padding_failure_and_hmac_failure_send_identical_error(self):
        if not (KEYS_DIR / "bob_private.pem").exists():
            self.skipTest("test key pair not present; run keygen.py first")

        tmp = Path(tempfile.mkdtemp())
        plaintext_path = tmp / "plain.bin"
        # Multi-chunk file so there's a real "middle" chunk to corrupt
        # distinctly from the last one.
        plaintext_path.write_bytes(os.urandom(64 * 1024 * 3 + 1000))

        padding_result, padding_wire = self._run_one_transfer(
            str(plaintext_path), corrupt_last_chunk=True,
        )
        hmac_result, hmac_wire = self._run_one_transfer(
            str(plaintext_path), corrupt_chunk_index=0,
        )

        # Both must have failed (not succeeded) — sanity check the test
        # itself is actually exercising failure paths.
        self.assertEqual(padding_result["outcome"], "failed")
        self.assertEqual(hmac_result["outcome"], "failed")

        # The core assertion: both wire responses must be identical.
        self.assertIsNotNone(padding_wire)
        self.assertIsNotNone(hmac_wire)
        self.assertEqual(
            padding_wire, hmac_wire,
            "Padding failure and HMAC failure must produce the SAME "
            "network-visible response — a difference here is exactly "
            "the padding-oracle asymmetry this fix is meant to close."
        )
        # And specifically: it should be the generic message, not one
        # that names which check failed.
        ptype, payload = padding_wire
        self.assertEqual(ptype, PacketType.ERROR)
        message = payload.decode()
        self.assertNotIn("padding", message.lower())
        self.assertNotIn("hmac", message.lower())


if __name__ == "__main__":
    unittest.main()

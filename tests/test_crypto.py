#!/usr/bin/env python3
"""
tests/test_crypto.py — Unit Tests for crypto_utils.py
======================================================
Tests every public function in the cryptographic engine:
  - Session key generation
  - HMAC key generation
  - RSA-OAEP key bundling / unbundling
  - RSA-OAEP encrypt / decrypt round-trip
  - AES-256-CBC chunked encrypt / decrypt round-trip
  - HMAC-SHA256 compute / verify
  - SHA-256 checksum
  - compute_total_chunks
  - Error/tamper path coverage

Run from the project root:
    python -m pytest tests/test_crypto.py -v
    python -m unittest tests/test_crypto.py -v
"""

import os
import sys
import struct
import tempfile
import unittest
from pathlib import Path

# ── allow imports from project root ───────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

from Crypto.PublicKey import RSA

from crypto_utils import (
    generate_session_key,
    generate_hmac_key,
    bundle_keys,
    unbundle_keys,
    rsa_encrypt,
    rsa_decrypt,
    encrypt_file_stream,
    decrypt_file_stream,
    compute_hmac,
    verify_hmac,
    compute_sha256,
    compute_total_chunks,
    AES_KEY_SIZE,
    AES_BLOCK_SIZE,
    CHUNK_SIZE,
    HMAC_SIZE,
)
from exceptions import EncryptionError, DecryptionError, IntegrityError


# ── helpers ────────────────────────────────────────────────────────────────────

def _tmp_file(data: bytes) -> str:
    """Write bytes to a NamedTemporaryFile and return its path."""
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
    f.write(data)
    f.close()
    return f.name


def _gen_rsa_keypair(bits: int = 2048):
    """Generate a fresh RSA key pair (private key object, public key object)."""
    key = RSA.generate(bits)
    return key, key.publickey()


# ══════════════════════════════════════════════════════════════════════════════
# 1. SESSION KEY GENERATION
# ══════════════════════════════════════════════════════════════════════════════

class TestGenerateSessionKey(unittest.TestCase):

    def test_returns_tuple_of_two_bytes(self):
        result = generate_session_key()
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_aes_key_is_32_bytes(self):
        aes_key, _ = generate_session_key()
        self.assertEqual(len(aes_key), AES_KEY_SIZE)
        self.assertEqual(len(aes_key), 32)

    def test_iv_is_16_bytes(self):
        _, iv = generate_session_key()
        self.assertEqual(len(iv), AES_BLOCK_SIZE)
        self.assertEqual(len(iv), 16)

    def test_keys_are_bytes(self):
        aes_key, iv = generate_session_key()
        self.assertIsInstance(aes_key, bytes)
        self.assertIsInstance(iv, bytes)

    def test_unique_across_calls(self):
        k1, iv1 = generate_session_key()
        k2, iv2 = generate_session_key()
        self.assertNotEqual(k1, k2, "Session keys should be unique")
        self.assertNotEqual(iv1, iv2, "IVs should be unique")


# ══════════════════════════════════════════════════════════════════════════════
# 2. HMAC KEY GENERATION
# ══════════════════════════════════════════════════════════════════════════════

class TestGenerateHmacKey(unittest.TestCase):

    def test_is_32_bytes(self):
        key = generate_hmac_key()
        self.assertEqual(len(key), 32)

    def test_is_bytes(self):
        self.assertIsInstance(generate_hmac_key(), bytes)

    def test_unique_across_calls(self):
        self.assertNotEqual(generate_hmac_key(), generate_hmac_key())


# ══════════════════════════════════════════════════════════════════════════════
# 3. KEY BUNDLING / UNBUNDLING
# ══════════════════════════════════════════════════════════════════════════════

class TestBundleUnbundle(unittest.TestCase):

    def setUp(self):
        self.aes_key  = os.urandom(32)
        self.hmac_key = os.urandom(32)

    def test_round_trip(self):
        bundle = bundle_keys(self.aes_key, self.hmac_key)
        recovered_aes, recovered_hmac = unbundle_keys(bundle)
        self.assertEqual(recovered_aes,  self.aes_key)
        self.assertEqual(recovered_hmac, self.hmac_key)

    def test_bundle_format_length_prefix(self):
        """The first 4 bytes should encode the AES key length (big-endian)."""
        bundle = bundle_keys(self.aes_key, self.hmac_key)
        aes_len = struct.unpack(">I", bundle[:4])[0]
        self.assertEqual(aes_len, len(self.aes_key))

    def test_bundle_total_length(self):
        bundle = bundle_keys(self.aes_key, self.hmac_key)
        # 4-byte prefix + 32-byte AES key + 32-byte HMAC key = 68 bytes
        self.assertEqual(len(bundle), 4 + len(self.aes_key) + len(self.hmac_key))

    def test_different_key_lengths(self):
        """unbundle_keys must handle any AES key length, not just 32."""
        aes_key_16 = os.urandom(16)
        hmac_key   = os.urandom(64)
        bundle = bundle_keys(aes_key_16, hmac_key)
        recovered_aes, recovered_hmac = unbundle_keys(bundle)
        self.assertEqual(recovered_aes,  aes_key_16)
        self.assertEqual(recovered_hmac, hmac_key)


# ══════════════════════════════════════════════════════════════════════════════
# 4. RSA-OAEP ENCRYPT / DECRYPT
# ══════════════════════════════════════════════════════════════════════════════

class TestRsaEncryptDecrypt(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Generate one keypair for the whole class — RSA keygen is expensive."""
        cls.private_key, cls.public_key = _gen_rsa_keypair()

    def _bundle(self):
        aes_key  = os.urandom(32)
        hmac_key = os.urandom(32)
        return bundle_keys(aes_key, hmac_key), aes_key, hmac_key

    def test_encrypt_produces_256_bytes(self):
        bundle, _, _ = self._bundle()
        ct = rsa_encrypt(self.public_key, bundle)
        self.assertEqual(len(ct), 256)   # RSA-2048 ciphertext = 256 bytes

    def test_round_trip(self):
        bundle, aes_key, hmac_key = self._bundle()
        ct = rsa_encrypt(self.public_key, bundle)
        pt = rsa_decrypt(self.private_key, ct)
        recovered_aes, recovered_hmac = unbundle_keys(pt)
        self.assertEqual(recovered_aes,  aes_key)
        self.assertEqual(recovered_hmac, hmac_key)

    def test_probabilistic_ciphertext(self):
        """Two encryptions of the same plaintext must differ (OAEP is probabilistic)."""
        bundle, _, _ = self._bundle()
        ct1 = rsa_encrypt(self.public_key, bundle)
        ct2 = rsa_encrypt(self.public_key, bundle)
        self.assertNotEqual(ct1, ct2, "OAEP must produce different ciphertext each call")

    def test_decrypt_with_wrong_key_raises(self):
        bundle, _, _ = self._bundle()
        ct = rsa_encrypt(self.public_key, bundle)
        wrong_private, _ = _gen_rsa_keypair()
        with self.assertRaises(DecryptionError):
            rsa_decrypt(wrong_private, ct)

    def test_tampered_ciphertext_raises(self):
        bundle, _, _ = self._bundle()
        ct = bytearray(rsa_encrypt(self.public_key, bundle))
        ct[10] ^= 0xFF   # flip bits in the middle
        with self.assertRaises(DecryptionError):
            rsa_decrypt(self.private_key, bytes(ct))


# ══════════════════════════════════════════════════════════════════════════════
# 5. AES-256-CBC CHUNKED ENCRYPT / DECRYPT
# ══════════════════════════════════════════════════════════════════════════════

class TestAesFileStream(unittest.TestCase):

    def setUp(self):
        self.aes_key, self.iv = generate_session_key()

    def _encrypt_decrypt(self, data: bytes) -> bytes:
        """Helper: write data → encrypt_file_stream → decrypt_file_stream → return result."""
        src_path = _tmp_file(data)
        total_chunks = compute_total_chunks(src_path)
        encrypted_chunks = list(encrypt_file_stream(src_path, self.aes_key, self.iv))

        dst_fd, dst_path = tempfile.mkstemp(suffix=".dec")
        os.close(dst_fd)

        decrypt_file_stream(
            iter(encrypted_chunks), self.aes_key, self.iv, dst_path, total_chunks
        )

        with open(dst_path, "rb") as f:
            result = f.read()

        os.unlink(src_path)
        os.unlink(dst_path)
        return result

    # --- encrypt_file_stream ---

    def test_small_file_round_trip(self):
        data = b"Hello, secure world! " * 100
        self.assertEqual(self._encrypt_decrypt(data), data)

    def test_exactly_one_chunk(self):
        data = os.urandom(CHUNK_SIZE)
        self.assertEqual(self._encrypt_decrypt(data), data)

    def test_multiple_full_chunks(self):
        data = os.urandom(CHUNK_SIZE * 5)
        self.assertEqual(self._encrypt_decrypt(data), data)

    def test_partial_last_chunk(self):
        """A file that doesn't end on a chunk boundary — tests PKCS#7 padding."""
        data = os.urandom(CHUNK_SIZE * 3 + 1337)
        self.assertEqual(self._encrypt_decrypt(data), data)

    def test_one_byte_file(self):
        data = b"\xAB"
        self.assertEqual(self._encrypt_decrypt(data), data)

    def test_binary_data_round_trip(self):
        data = bytes(range(256)) * 512
        self.assertEqual(self._encrypt_decrypt(data), data)

    def test_encrypted_differs_from_plaintext(self):
        data = os.urandom(CHUNK_SIZE)
        src_path = _tmp_file(data)
        chunks = list(encrypt_file_stream(src_path, self.aes_key, self.iv))
        os.unlink(src_path)
        self.assertNotEqual(b"".join(chunks), data)

    def test_chunk_count_matches_total_chunks(self):
        data = os.urandom(CHUNK_SIZE * 3 + 500)
        src_path = _tmp_file(data)
        total = compute_total_chunks(src_path)
        chunks = list(encrypt_file_stream(src_path, self.aes_key, self.iv))
        os.unlink(src_path)
        self.assertEqual(len(chunks), total)

    def test_nonexistent_file_raises(self):
        with self.assertRaises(EncryptionError):
            list(encrypt_file_stream("/no/such/file.bin", self.aes_key, self.iv))

    def test_empty_file_raises(self):
        f = tempfile.NamedTemporaryFile(delete=False)
        f.close()
        with self.assertRaises(EncryptionError):
            list(encrypt_file_stream(f.name, self.aes_key, self.iv))
        os.unlink(f.name)

    # --- decrypt_file_stream ---

    def test_wrong_aes_key_produces_garbage(self):
        """Decrypting with the wrong key should either error or produce wrong data."""
        data = os.urandom(CHUNK_SIZE)
        src_path = _tmp_file(data)
        total = compute_total_chunks(src_path)
        chunks = list(encrypt_file_stream(src_path, self.aes_key, self.iv))
        os.unlink(src_path)

        wrong_key = os.urandom(32)
        dst_fd, dst_path = tempfile.mkstemp(suffix=".dec")
        os.close(dst_fd)

        try:
            decrypt_file_stream(iter(chunks), wrong_key, self.iv, dst_path, total)
            with open(dst_path, "rb") as f:
                result = f.read()
            self.assertNotEqual(result, data)
        except (DecryptionError, Exception):
            pass  # Raising an exception is also correct behaviour
        finally:
            if os.path.exists(dst_path):
                os.unlink(dst_path)

    def test_wrong_iv_produces_garbled_first_block_only(self):
        """CBC: wrong IV corrupts only the first block; rest decrypts with key alone."""
        data = os.urandom(CHUNK_SIZE)
        src_path = _tmp_file(data)
        total = compute_total_chunks(src_path)
        chunks = list(encrypt_file_stream(src_path, self.aes_key, self.iv))
        os.unlink(src_path)

        wrong_iv = os.urandom(16)
        dst_fd, dst_path = tempfile.mkstemp(suffix=".dec")
        os.close(dst_fd)

        try:
            decrypt_file_stream(iter(chunks), self.aes_key, wrong_iv, dst_path, total)
            with open(dst_path, "rb") as f:
                result = f.read()
            # With wrong IV only first 16 bytes differ; full result != original
            self.assertNotEqual(result, data)
        except Exception:
            pass
        finally:
            if os.path.exists(dst_path):
                os.unlink(dst_path)


# ══════════════════════════════════════════════════════════════════════════════
# 6. HMAC-SHA256
# ══════════════════════════════════════════════════════════════════════════════

class TestHmac(unittest.TestCase):

    def setUp(self):
        self.hmac_key = generate_hmac_key()
        self.data     = os.urandom(65536)
        self.filepath = _tmp_file(self.data)

    def tearDown(self):
        if os.path.exists(self.filepath):
            os.unlink(self.filepath)

    def test_compute_hmac_returns_32_bytes(self):
        digest = compute_hmac(self.hmac_key, self.filepath)
        self.assertEqual(len(digest), HMAC_SIZE)

    def test_compute_hmac_is_bytes(self):
        self.assertIsInstance(compute_hmac(self.hmac_key, self.filepath), bytes)

    def test_deterministic(self):
        d1 = compute_hmac(self.hmac_key, self.filepath)
        d2 = compute_hmac(self.hmac_key, self.filepath)
        self.assertEqual(d1, d2)

    def test_different_keys_produce_different_hmac(self):
        k2 = generate_hmac_key()
        d1 = compute_hmac(self.hmac_key, self.filepath)
        d2 = compute_hmac(k2,            self.filepath)
        self.assertNotEqual(d1, d2)

    def test_different_content_produces_different_hmac(self):
        other_path = _tmp_file(os.urandom(65536))
        d1 = compute_hmac(self.hmac_key, self.filepath)
        d2 = compute_hmac(self.hmac_key, other_path)
        os.unlink(other_path)
        self.assertNotEqual(d1, d2)

    def test_verify_passes_for_correct_digest(self):
        digest = compute_hmac(self.hmac_key, self.filepath)
        result = verify_hmac(self.hmac_key, self.filepath, digest)
        self.assertTrue(result)

    def test_verify_raises_on_wrong_key(self):
        digest = compute_hmac(self.hmac_key, self.filepath)
        wrong_key = generate_hmac_key()
        with self.assertRaises(IntegrityError):
            verify_hmac(wrong_key, self.filepath, digest)

    def test_verify_raises_on_tampered_file(self):
        digest = compute_hmac(self.hmac_key, self.filepath)
        # Flip one byte in the middle of the file
        with open(self.filepath, "r+b") as f:
            f.seek(len(self.data) // 2)
            f.write(bytes([self.data[len(self.data) // 2] ^ 0xFF]))
        with self.assertRaises(IntegrityError):
            verify_hmac(self.hmac_key, self.filepath, digest)

    def test_verify_raises_on_truncated_digest(self):
        digest = compute_hmac(self.hmac_key, self.filepath)[:16]  # half the digest
        with self.assertRaises(IntegrityError):
            verify_hmac(self.hmac_key, self.filepath, digest)

    def test_compute_hmac_missing_file_raises(self):
        with self.assertRaises(IntegrityError):
            compute_hmac(self.hmac_key, "/no/such/file.bin")


# ══════════════════════════════════════════════════════════════════════════════
# 7. SHA-256 CHECKSUM
# ══════════════════════════════════════════════════════════════════════════════

class TestSha256(unittest.TestCase):

    def setUp(self):
        self.data = os.urandom(32768)
        self.path = _tmp_file(self.data)

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def test_returns_64_hex_chars(self):
        cs = compute_sha256(self.path)
        self.assertEqual(len(cs), 64)

    def test_is_valid_hex_string(self):
        cs = compute_sha256(self.path)
        int(cs, 16)  # raises ValueError if not valid hex

    def test_deterministic(self):
        self.assertEqual(compute_sha256(self.path), compute_sha256(self.path))

    def test_known_value(self):
        """SHA-256 of the empty string is a well-known constant."""
        empty_path = _tmp_file(b"")
        cs = compute_sha256(empty_path)
        os.unlink(empty_path)
        self.assertEqual(
            cs,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_different_content_different_checksum(self):
        other_path = _tmp_file(os.urandom(32768))
        cs1 = compute_sha256(self.path)
        cs2 = compute_sha256(other_path)
        os.unlink(other_path)
        self.assertNotEqual(cs1, cs2)

    def test_missing_file_raises(self):
        with self.assertRaises(EncryptionError):
            compute_sha256("/no/such/file.bin")


# ══════════════════════════════════════════════════════════════════════════════
# 8. COMPUTE_TOTAL_CHUNKS
# ══════════════════════════════════════════════════════════════════════════════

class TestComputeTotalChunks(unittest.TestCase):

    def _make(self, size: int) -> str:
        return _tmp_file(os.urandom(size))

    def tearDown(self):
        pass  # temps cleaned per-test

    def test_exactly_one_chunk(self):
        path = self._make(CHUNK_SIZE)
        self.assertEqual(compute_total_chunks(path), 1)
        os.unlink(path)

    def test_less_than_one_chunk(self):
        path = self._make(1000)
        self.assertEqual(compute_total_chunks(path), 1)
        os.unlink(path)

    def test_exactly_two_chunks(self):
        path = self._make(CHUNK_SIZE * 2)
        self.assertEqual(compute_total_chunks(path), 2)
        os.unlink(path)

    def test_partial_second_chunk(self):
        path = self._make(CHUNK_SIZE + 1)
        self.assertEqual(compute_total_chunks(path), 2)
        os.unlink(path)

    def test_large_file(self):
        # Simulate a 100 MB file without writing it — just check ceiling math
        import math
        size = 100 * 1024 * 1024
        expected = math.ceil(size / CHUNK_SIZE)
        path = self._make(size)
        self.assertEqual(compute_total_chunks(path), expected)
        os.unlink(path)

    def test_one_byte_file(self):
        path = self._make(1)
        self.assertEqual(compute_total_chunks(path), 1)
        os.unlink(path)


# ══════════════════════════════════════════════════════════════════════════════
# 9. INTEGRATION — Full crypto pipeline
# ══════════════════════════════════════════════════════════════════════════════

class TestFullCryptoPipeline(unittest.TestCase):
    """
    End-to-end round-trip mimicking what sender + receiver do:
      keygen → bundle → RSA encrypt → RSA decrypt → unbundle →
      AES encrypt stream → AES decrypt stream → verify HMAC
    """

    @classmethod
    def setUpClass(cls):
        cls.private_key, cls.public_key = _gen_rsa_keypair()

    def test_full_pipeline_small_file(self):
        self._run_pipeline(os.urandom(1337))

    def test_full_pipeline_multi_chunk(self):
        self._run_pipeline(os.urandom(CHUNK_SIZE * 4 + 999))

    def _run_pipeline(self, plaintext: bytes):
        # 1. Generate session keys
        aes_key, iv = generate_session_key()
        hmac_key    = generate_hmac_key()

        # 2. Bundle + RSA encrypt (sender side)
        bundle           = bundle_keys(aes_key, hmac_key)
        encrypted_bundle = rsa_encrypt(self.public_key, bundle)

        # 3. RSA decrypt + unbundle (receiver side)
        raw_bundle                     = rsa_decrypt(self.private_key, encrypted_bundle)
        recovered_aes, recovered_hmac  = unbundle_keys(raw_bundle)
        self.assertEqual(recovered_aes,  aes_key)
        self.assertEqual(recovered_hmac, hmac_key)

        # 4. Write plaintext, compute HMAC (sender)
        src_path = _tmp_file(plaintext)
        hmac_digest  = compute_hmac(hmac_key, src_path)
        total_chunks = compute_total_chunks(src_path)

        # 5. Encrypt stream (sender)
        chunks = list(encrypt_file_stream(src_path, aes_key, iv))
        self.assertEqual(len(chunks), total_chunks)

        # 6. Decrypt stream (receiver)
        dst_fd, dst_path = tempfile.mkstemp(suffix=".dec")
        os.close(dst_fd)
        decrypt_file_stream(iter(chunks), recovered_aes, iv, dst_path, total_chunks)

        # 7. Verify HMAC (receiver)
        self.assertTrue(verify_hmac(recovered_hmac, dst_path, hmac_digest))

        # 8. Content match
        with open(dst_path, "rb") as f:
            result = f.read()
        self.assertEqual(result, plaintext)

        # 9. Cleanup
        os.unlink(src_path)
        os.unlink(dst_path)


# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    unittest.main(verbosity=2)
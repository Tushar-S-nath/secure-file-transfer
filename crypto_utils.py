#!/usr/bin/env python3
"""
crypto_utils.py — Cryptographic Engine
Handles all cryptographic operations for the Secure File Transfer Protocol:
  - RSA-OAEP encryption/decryption  (key exchange)
  - AES-256-CBC encryption/decryption (file data, chunked streaming)
  - HMAC-SHA256 generation/verification (integrity checking)
  - Session key generation
Part of the Secure File Transfer Protocol (SFTP-Hybrid) project.
"""

import os
import hmac
import hashlib
import struct
from typing import Generator, Tuple

from Crypto.PublicKey  import RSA
from Crypto.Cipher     import AES, PKCS1_OAEP
from Crypto.Hash       import SHA256
from Crypto.Random     import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from exceptions import EncryptionError, DecryptionError, IntegrityError


# ── Constants ──────────────────────────────────────────────────────────────────
AES_KEY_SIZE    = 32          # 256 bits
AES_BLOCK_SIZE  = 16          # 128 bits (AES standard block size)
CHUNK_SIZE      = 65536       # 64 KB per chunk — optimal for streaming
HMAC_SIZE       = 32          # SHA-256 produces 32-byte digest
RSA_HASH        = "SHA-256"   # Hash used inside OAEP padding

# AES-256-GCM (authenticated encryption) constants.
AES_GCM_BASE_NONCE_SIZE = 8    # random per-session prefix
AES_GCM_NONCE_SIZE      = 12   # full per-chunk nonce = base_nonce + 4-byte counter
AES_GCM_TAG_SIZE        = 16   # authentication tag appended to each chunk's ciphertext


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — SESSION KEY GENERATION
# ══════════════════════════════════════════════════════════════════════════════

def generate_session_key() -> Tuple[bytes, bytes]:
    """
    Generate a cryptographically secure AES-256 session key and IV.

    The session key is freshly generated for every single transfer —
    this provides Perfect Forward Secrecy at the session level,
    meaning that compromising one session key does not affect any other session.

    Returns:
        (aes_key, iv) — both as raw bytes
        aes_key : 32 bytes (256 bits)
        iv      : 16 bytes (128 bits)
    """
    aes_key = get_random_bytes(AES_KEY_SIZE)
    iv      = get_random_bytes(AES_BLOCK_SIZE)
    return aes_key, iv


def generate_hmac_key() -> bytes:
    """
    Generate a separate 32-byte key specifically for HMAC signing.
    Keeping the HMAC key separate from the AES key is a security best practice
    — using the same key for both encryption and authentication is considered weak.
    """
    return get_random_bytes(32)


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — RSA-OAEP (Key Exchange)
# ══════════════════════════════════════════════════════════════════════════════

def rsa_encrypt(public_key: RSA.RsaKey, data: bytes) -> bytes:
    """
    Encrypt data using RSA-OAEP with SHA-256.

    OAEP (Optimal Asymmetric Encryption Padding) is the modern, secure
    padding scheme for RSA. It is probabilistic — encrypting the same
    data twice produces different ciphertext each time, preventing
    chosen-plaintext attacks.

    Used to encrypt: AES session key + HMAC key (bundled together).

    Args:
        public_key : RSA public key object
        data       : raw bytes to encrypt (max ~190 bytes for RSA-2048)

    Returns:
        Encrypted bytes (same length as RSA key size — 256 bytes for 2048-bit)
    """
    try:
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        return cipher.encrypt(data)
    except (ValueError, TypeError) as e:
        raise EncryptionError("RSA-OAEP encryption failed.", details=str(e))


def rsa_decrypt(private_key: RSA.RsaKey, ciphertext: bytes) -> bytes:
    """
    Decrypt RSA-OAEP ciphertext using the private key.

    Args:
        private_key : RSA private key object
        ciphertext  : bytes produced by rsa_encrypt()

    Returns:
        Original plaintext bytes (the AES session key + HMAC key)
    """
    try:
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        return cipher.decrypt(ciphertext)
    except (ValueError, TypeError) as e:
        raise DecryptionError("RSA-OAEP decryption failed. Wrong key or corrupted data.", details=str(e))


def bundle_keys(aes_key: bytes, hmac_key: bytes) -> bytes:
    """
    Bundle AES key + HMAC key into a single bytes object for RSA encryption.
    Format: [4-byte length of aes_key][aes_key][hmac_key]
    The length prefix makes unbundling unambiguous.
    """
    length_prefix = struct.pack(">I", len(aes_key))   # 4 bytes, big-endian
    return length_prefix + aes_key + hmac_key


def unbundle_keys(data: bytes) -> Tuple[bytes, bytes]:
    """
    Reverse of bundle_keys() — split the decrypted blob back into
    (aes_key, hmac_key).
    """
    aes_len  = struct.unpack(">I", data[:4])[0]
    aes_key  = data[4 : 4 + aes_len]
    hmac_key = data[4 + aes_len :]
    return aes_key, hmac_key


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2B — AES-256-GCM (Authenticated Encryption — replaces CBC+HMAC)
# ══════════════════════════════════════════════════════════════════════════════
#
# GCM (Galois/Counter Mode) is an AEAD (Authenticated Encryption with
# Associated Data) mode: encryption and integrity verification happen in
# ONE operation instead of two separate ones (AES-CBC, then a separate
# HMAC pass). This has two consequences that directly address the
# weaknesses documented for the CBC+HMAC path (see paper Section V):
#
#   1. No padding step. GCM is a stream cipher construction internally —
#      ciphertext is always exactly as long as plaintext. There is no
#      PKCS#7 padding to validate, so there is no padding-failure code
#      path to accidentally distinguish from an authentication failure.
#      The padding-oracle attack class does not apply here at all —
#      not "is mitigated", genuinely does not exist as an attack surface.
#
#   2. Per-chunk authentication. Each chunk carries its own 16-byte tag
#      and is verified independently, so corruption is detected on the
#      FIRST bad chunk rather than only after the entire file has been
#      received and a single whole-file HMAC is checked at the end.
#
# Nonce construction: each session gets a fresh 8-byte random
# base_nonce (generate_session_key_gcm). Each chunk's actual 12-byte GCM
# nonce is base_nonce + chunk_index (4-byte big-endian counter). This is
# the "fixed field + counter" deterministic construction described in
# NIST SP 800-38D Section 8.2.1 — it guarantees the nonce never repeats
# within a session (the counter is strictly increasing) and, with 8
# bytes of fresh randomness per session, makes a cross-session repeat
# astronomically unlikely for any realistic number of sessions this
# system will ever run.
#
# CRITICAL: a (key, nonce) pair must NEVER be reused with GCM — doing so
# catastrophically breaks both confidentiality and integrity. This is
# why the session key AND base_nonce are both regenerated fresh for
# every single transfer (see generate_session_key_gcm).

def generate_session_key_gcm() -> Tuple[bytes, bytes]:
    """
    Generate a fresh AES-256 key and 8-byte random base nonce for a new
    GCM session. Called once per transfer, same as generate_session_key()
    for the CBC path — this is what provides session-level forward
    secrecy for GCM mode too.

    Returns:
        (aes_key, base_nonce) — 32 bytes, 8 bytes
    """
    aes_key    = get_random_bytes(AES_KEY_SIZE)
    base_nonce = get_random_bytes(AES_GCM_BASE_NONCE_SIZE)
    return aes_key, base_nonce


def _gcm_nonce_for_chunk(base_nonce: bytes, chunk_index: int) -> bytes:
    """Derive the per-chunk 12-byte GCM nonce. See module docstring above
    for why this construction is safe against nonce reuse."""
    if len(base_nonce) != AES_GCM_BASE_NONCE_SIZE:
        raise EncryptionError(
            f"GCM base_nonce must be {AES_GCM_BASE_NONCE_SIZE} bytes.",
            details=f"Got {len(base_nonce)} bytes."
        )
    if chunk_index >= 2**32:
        # Would wrap the 4-byte counter and risk nonce reuse — refuse
        # rather than silently produce an unsafe nonce. At 64KB chunks
        # this is a ~256 TB file, far beyond any realistic transfer.
        raise EncryptionError("Too many chunks for a single GCM session (counter would wrap).")
    return base_nonce + struct.pack(">I", chunk_index)


def bundle_keys_gcm(aes_key: bytes) -> bytes:
    """
    Bundle the AES key alone for RSA encryption. GCM mode needs no
    separate HMAC key — each chunk authenticates itself — so this is
    simpler than bundle_keys() (CBC path), which must carry both an AES
    key and an HMAC key. Kept as a named function (rather than just using
    aes_key directly) for interface symmetry with bundle_keys/unbundle_keys.
    """
    return aes_key


def unbundle_keys_gcm(data: bytes) -> bytes:
    """Reverse of bundle_keys_gcm() — trivial, kept for symmetry."""
    return data


def encrypt_file_stream_gcm(
    filepath: str,
    aes_key: bytes,
    base_nonce: bytes,
    chunk_size: int = CHUNK_SIZE,
) -> Generator[bytes, None, None]:
    """
    Generator that encrypts a file with AES-256-GCM, one independently
    authenticated chunk at a time, and yields (ciphertext + tag) per
    chunk — the last AES_GCM_TAG_SIZE bytes of each yielded value are
    the tag.

    Unlike encrypt_file_stream() (CBC), there is no padding step and no
    special-casing of the final chunk — GCM ciphertext is always exactly
    as long as the plaintext chunk that produced it.

    Args:
        filepath   : path to the source file
        aes_key    : 32-byte AES-256 key
        base_nonce : 8-byte session base nonce (see generate_session_key_gcm)
        chunk_size : plaintext bytes read per chunk

    Yields:
        ciphertext + tag, one chunk at a time
    """
    if not os.path.exists(filepath):
        raise EncryptionError("File not found.", details=f"Path: {filepath}")

    file_size = os.path.getsize(filepath)
    if file_size == 0:
        raise EncryptionError("Cannot encrypt an empty file.", details=f"Path: {filepath}")

    try:
        with open(filepath, "rb") as f:
            chunk_index = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                nonce  = _gcm_nonce_for_chunk(base_nonce, chunk_index)
                cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                ciphertext, tag = cipher.encrypt_and_digest(chunk)
                yield ciphertext + tag
                chunk_index += 1
    except (OSError, IOError) as e:
        raise EncryptionError("File read error during encryption.", details=str(e))


def decrypt_file_stream_gcm(
    encrypted_chunks: Generator[bytes, None, None],
    aes_key: bytes,
    base_nonce: bytes,
    output_path: str,
    total_chunks: int,
) -> str:
    """
    Consume an iterable of AES-256-GCM (ciphertext+tag) chunks, verify
    and decrypt each one independently, and write the plaintext to
    output_path.

    Raises IntegrityError on the FIRST chunk that fails authentication —
    a wrong tag means tampered/corrupted ciphertext, a wrong key, or a
    nonce mismatch. Decryption and verification happen together in one
    call (cipher.decrypt_and_verify): there is no separate "decrypt,
    then check" phase boundary the way there is for CBC+HMAC, so there
    is no equivalent of the CBC padding-failure-vs-HMAC-failure
    distinction for a network observer to exploit.

    Args:
        encrypted_chunks : iterable of (ciphertext + tag) chunks
        aes_key           : 32-byte AES-256 key
        base_nonce        : 8-byte session base nonce
        output_path       : where to write the decrypted file
        total_chunks      : expected chunk count (detects truncation)

    Returns:
        output_path
    """
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    chunk_index = 0
    try:
        with open(output_path, "wb") as f:
            for chunk_with_tag in encrypted_chunks:
                if len(chunk_with_tag) < AES_GCM_TAG_SIZE:
                    raise IntegrityError(
                        f"Chunk {chunk_index + 1} too short to contain a GCM tag "
                        f"— truncated or corrupted in transit."
                    )
                ciphertext = chunk_with_tag[:-AES_GCM_TAG_SIZE]
                tag        = chunk_with_tag[-AES_GCM_TAG_SIZE:]
                nonce      = _gcm_nonce_for_chunk(base_nonce, chunk_index)
                cipher     = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                try:
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                except ValueError as e:
                    raise IntegrityError(
                        f"GCM authentication failed on chunk "
                        f"{chunk_index + 1}/{total_chunks} — file corrupted "
                        f"or tampered.", details=str(e)
                    ) from e
                f.write(plaintext)
                chunk_index += 1

        if chunk_index != total_chunks:
            raise IntegrityError(
                f"Chunk count mismatch: expected {total_chunks}, got {chunk_index}."
            )
        return output_path
    except (OSError, IOError) as e:
        raise DecryptionError("File write error during decryption.", details=str(e))


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — AES-256-CBC (File Encryption — Chunked Streaming)
# ══════════════════════════════════════════════════════════════════════════════

def encrypt_chunk(cipher: AES, chunk: bytes, is_last: bool) -> bytes:
    """
    Encrypt a single chunk of file data.

    For all chunks except the last, the chunk size is already a multiple
    of AES_BLOCK_SIZE (64 KB = 65536 bytes = 4096 × 16). For the final
    chunk, PKCS#7 padding is applied to bring it up to the next block boundary.

    Args:
        cipher   : AES cipher object (reused across all chunks in a session)
        chunk    : raw bytes of this chunk
        is_last  : True if this is the final chunk of the file

    Returns:
        Encrypted bytes for this chunk
    """
    try:
        if is_last:
            return cipher.encrypt(pad(chunk, AES_BLOCK_SIZE))
        return cipher.encrypt(chunk)
    except ValueError as e:
        raise EncryptionError("AES chunk encryption failed.", details=str(e))


def decrypt_chunk(cipher: AES, chunk: bytes, is_last: bool) -> bytes:
    """
    Decrypt a single chunk of file data.
    Removes PKCS#7 padding on the final chunk.
    """
    try:
        decrypted = cipher.decrypt(chunk)
        if is_last:
            return unpad(decrypted, AES_BLOCK_SIZE)
        return decrypted
    except ValueError as e:
        raise DecryptionError("AES chunk decryption failed. Data may be corrupted.", details=str(e))


def encrypt_file_stream(
    filepath: str,
    aes_key: bytes,
    iv: bytes,
    chunk_size: int = CHUNK_SIZE,
) -> Generator[bytes, None, None]:
    """
    Generator that encrypts a file in fixed-size chunks and yields each
    encrypted chunk. Handles files of any size — including 30 GB+ —
    without loading the entire file into memory.

    Usage:
        for encrypted_chunk in encrypt_file_stream(path, key, iv):
            socket.send(encrypted_chunk)

    Args:
        filepath   : absolute or relative path to the source file
        aes_key    : 32-byte AES-256 session key
        iv         : 16-byte initialization vector
        chunk_size : plaintext bytes read per chunk before encryption.
                     Defaults to the module-level CHUNK_SIZE (64 KB).
                     Exposed so callers (e.g. sender.py's --chunk-size
                     flag and the benchmark suite's chunk-size sweep)
                     can override it; decrypt_file_stream does not need
                     the matching value since it just consumes whatever
                     chunks it is handed.

    Yields:
        Encrypted bytes, one chunk at a time
    """
    if not os.path.exists(filepath):
        raise EncryptionError("File not found.", details=f"Path: {filepath}")

    file_size = os.path.getsize(filepath)
    if file_size == 0:
        raise EncryptionError("Cannot encrypt an empty file.", details=f"Path: {filepath}")

    cipher        = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    bytes_read    = 0

    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                bytes_read += len(chunk)
                is_last     = (bytes_read >= file_size)
                yield encrypt_chunk(cipher, chunk, is_last)
    except (OSError, IOError) as e:
        raise EncryptionError("File read error during encryption.", details=str(e))


def decrypt_file_stream(
    encrypted_chunks: Generator[bytes, None, None],
    aes_key: bytes,
    iv: bytes,
    output_path: str,
    total_chunks: int
) -> str:
    """
    Consume an iterable of encrypted chunks, decrypt each one, and
    write the result to output_path.

    Args:
        encrypted_chunks : iterable of encrypted byte chunks
        aes_key          : 32-byte AES-256 session key
        iv               : 16-byte IV (must match the one used for encryption)
        output_path      : where to write the decrypted file
        total_chunks     : total number of chunks expected (needed to detect last)

    Returns:
        output_path — path to the decrypted file
    """
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    cipher       = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    chunk_index  = 0

    try:
        with open(output_path, "wb") as f:
            for chunk in encrypted_chunks:
                chunk_index += 1
                is_last = (chunk_index >= total_chunks)
                f.write(decrypt_chunk(cipher, chunk, is_last))
        return output_path
    except (OSError, IOError) as e:
        raise DecryptionError("File write error during decryption.", details=str(e))


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — HMAC-SHA256 (Integrity Verification)
# ══════════════════════════════════════════════════════════════════════════════

def compute_hmac(hmac_key: bytes, filepath: str) -> bytes:
    """
    Compute HMAC-SHA256 over the raw (plaintext) file bytes.

    The HMAC is computed BEFORE encryption and sent alongside the
    ciphertext. After decryption, the receiver recomputes the HMAC
    over the decrypted file and compares — if they match, the file
    arrived intact and untampered.

    Note on terminology: this is a MAC-then-encrypt construction (the
    HMAC is computed over the plaintext, before encryption), NOT
    encrypt-then-MAC (which would compute the HMAC over the ciphertext).
    See the paper's Security Analysis section for the implications of
    this choice, including its relationship to CBC padding-oracle risk.

    Args:
        hmac_key : 32-byte key for HMAC
        filepath : path to the file to compute HMAC over

    Returns:
        32-byte HMAC digest
    """
    h = hmac.new(hmac_key, digestmod=hashlib.sha256)

    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.digest()
    except (OSError, IOError) as e:
        raise IntegrityError("Failed to compute HMAC — file unreadable.", details=str(e))


def verify_hmac(hmac_key: bytes, filepath: str, expected_hmac: bytes) -> bool:
    """
    Verify the HMAC of a decrypted file against the expected digest.

    Uses hmac.compare_digest() which is timing-safe — it takes constant
    time regardless of where the comparison fails, preventing timing
    side-channel attacks.

    Args:
        hmac_key      : 32-byte HMAC key
        filepath      : path to the decrypted file to verify
        expected_hmac : the 32-byte digest sent by the sender

    Returns:
        True if verification passes

    Raises:
        IntegrityError if the digest does not match
    """
    actual_hmac = compute_hmac(hmac_key, filepath)

    if not hmac.compare_digest(actual_hmac, expected_hmac):
        raise IntegrityError(
            "HMAC verification failed — file integrity compromised.",
            details="The file may have been tampered with in transit."
        )
    return True


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — FILE CHECKSUM (SHA-256)
# ══════════════════════════════════════════════════════════════════════════════

def compute_sha256(filepath: str) -> str:
    """
    Compute a SHA-256 checksum of a file for logging and verification.
    Returns the hex digest string (64 characters).
    Different from HMAC — this is keyless, used only for logging/display.
    """
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, IOError) as e:
        raise EncryptionError("Failed to compute SHA-256 checksum.", details=str(e))


def compute_total_chunks(filepath: str, chunk_size: int = CHUNK_SIZE) -> int:
    """
    Calculate how many chunks of `chunk_size` bytes a file will produce.
    Used by the sender to populate FILE_HEADER and by the receiver to
    know when to apply final-chunk unpadding. Must be called with the
    SAME chunk_size the sender actually used for encryption (sender.py
    passes its --chunk-size value here for exactly this reason).
    """
    file_size = os.path.getsize(filepath)
    return max(1, -(-file_size // chunk_size))   # ceiling division


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — SELF-TEST
# ══════════════════════════════════════════════════════════════════════════════

def run_self_test() -> None:
    """
    Run a full round-trip test of all crypto operations.
    No files needed — operates entirely in memory.
    """
    print("\n[*] Running crypto self-test ...\n")

    # 1. Key generation
    from keygen import generate_rsa_keypair
    key         = generate_rsa_keypair(key_size=2048)
    public_key  = key.publickey()
    private_key = key

    # 2. Session key generation
    aes_key, iv = generate_session_key()
    hmac_key    = generate_hmac_key()
    print(f"    AES key  : {aes_key.hex()[:32]}...  ({len(aes_key)} bytes)")
    print(f"    IV       : {iv.hex()}  ({len(iv)} bytes)")
    print(f"    HMAC key : {hmac_key.hex()[:32]}...  ({len(hmac_key)} bytes)")

    # 3. Bundle + RSA encrypt
    bundle      = bundle_keys(aes_key, hmac_key)
    encrypted   = rsa_encrypt(public_key, bundle)
    print(f"\n    Bundle size      : {len(bundle)} bytes")
    print(f"    RSA ciphertext   : {encrypted.hex()[:32]}...  ({len(encrypted)} bytes)")

    # 4. RSA decrypt + unbundle
    decrypted_bundle        = rsa_decrypt(private_key, encrypted)
    recovered_aes, recovered_hmac = unbundle_keys(decrypted_bundle)
    assert recovered_aes  == aes_key,  "AES key mismatch!"
    assert recovered_hmac == hmac_key, "HMAC key mismatch!"
    print(f"    RSA round-trip   : PASSED ✓")

    # 5. AES encrypt/decrypt a test payload in memory
    test_data   = os.urandom(200_000)   # 200 KB random bytes
    tmp_in      = "_test_input.bin"
    tmp_out     = "_test_output.bin"

    with open(tmp_in, "wb") as f:
        f.write(test_data)

    total_chunks = compute_total_chunks(tmp_in)
    encrypted_chunks = list(encrypt_file_stream(tmp_in, aes_key, iv))

    # Write encrypted chunks to a temp file to simulate a received stream
    tmp_enc = "_test_encrypted.bin"
    with open(tmp_enc, "wb") as f:
        for c in encrypted_chunks:
            f.write(c)

    decrypt_file_stream(iter(encrypted_chunks), aes_key, iv, tmp_out, total_chunks)

    with open(tmp_out, "rb") as f:
        recovered_data = f.read()

    assert recovered_data == test_data, "AES round-trip data mismatch!"
    print(f"    AES round-trip   : PASSED ✓  (200 KB payload)")

    # 6. HMAC
    original_hmac   = compute_hmac(hmac_key, tmp_in)
    verify_hmac(hmac_key, tmp_out, original_hmac)
    print(f"    HMAC verify      : PASSED ✓")

    # 7. SHA-256 checksum
    checksum = compute_sha256(tmp_in)
    print(f"    SHA-256 checksum : {checksum[:32]}...")

    # Cleanup temp files
    for f in [tmp_in, tmp_out, tmp_enc]:
        os.remove(f)

    print("\n[✓] All crypto self-tests passed. Engine is ready.\n")


if __name__ == "__main__":
    run_self_test()
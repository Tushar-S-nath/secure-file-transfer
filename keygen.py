#!/usr/bin/env python3
"""
keygen.py — RSA-2048 Key Pair Generator
Generates a public/private RSA key pair and saves them to the keys/ directory.
Part of the Secure File Transfer Protocol (SFTP-Hybrid) project.
"""

import os
import argparse
from datetime import datetime
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import mlkem
from exceptions import KeyGenerationError


# ── Constants ──────────────────────────────────────────────────────────────────
KEY_SIZE       = 2048          # RSA key size in bits (2048 = industry standard)
KEYS_DIR       = "keys"        # directory where keys are saved
DEFAULT_NAME   = "identity"    # default key name if none provided
MLKEM_VARIANT  = "MLKEM768"    # NIST-recommended default parameter set for 2026


# ── Core Functions ─────────────────────────────────────────────────────────────

def generate_rsa_keypair(key_size: int = KEY_SIZE) -> RSA.RsaKey:
    """
    Generate an RSA key pair of the given bit size.
    Returns the full key object (contains both public and private).
    """
    print(f"[*] Generating RSA-{key_size} key pair ...")
    try:
        key = RSA.generate(key_size)
        print(f"[+] Key pair generated successfully.")
        return key
    except ValueError as e:
        raise KeyGenerationError("RSA key generation failed.", details=str(e))


def save_keypair(key: RSA.RsaKey, name: str = DEFAULT_NAME) -> tuple[str, str]:
    """
    Save the RSA private and public keys to the keys/ directory.

    Private key → keys/<name>_private.pem  (PEM format, PKCS#8)
    Public key  → keys/<name>_public.pem   (PEM format)

    Returns a tuple of (private_key_path, public_key_path).
    """
    os.makedirs(KEYS_DIR, exist_ok=True)

    private_path = os.path.join(KEYS_DIR, f"{name}_private.pem")
    public_path  = os.path.join(KEYS_DIR, f"{name}_public.pem")

    try:
        # Export private key in PKCS#8 format
        private_pem = key.export_key(format="PEM", pkcs=8)
        with open(private_path, "wb") as f:
            f.write(private_pem)
        os.chmod(private_path, 0o600)   # owner read/write only — like SSH keys

        # Export public key
        public_pem = key.publickey().export_key(format="PEM")
        with open(public_path, "wb") as f:
            f.write(public_pem)

        print(f"[+] Private key saved → {private_path}  (permissions: 600)")
        print(f"[+] Public key  saved → {public_path}")
        return private_path, public_path

    except (OSError, IOError) as e:
        raise KeyGenerationError("Failed to save RSA key pair to disk.", details=str(e))


# ── ML-KEM (post-quantum) functions ─────────────────────────────────────────────
# Added alongside the RSA functions above, not replacing them — SFTP-Hybrid uses
# BOTH together (see crypto_utils.py's hybrid key combiner): breaking either RSA
# or ML-KEM alone is not enough to recover the session key. ML-KEM key material
# is raw bytes, not PEM-formatted text like RSA (there's no equivalent PEM
# standard for it yet), so these save as keys/<name>_mlkem_private.bin and
# keys/<name>_mlkem_public.bin instead.

def generate_mlkem_keypair() -> "mlkem.MLKEM768PrivateKey":
    """
    Generate an ML-KEM-768 key pair (NIST FIPS 203, the post-quantum
    key-encapsulation standard finalized August 2024). ML-KEM-768 is the
    NIST-recommended default parameter set, balancing strong security
    with reasonable key/ciphertext sizes (1184-byte public key, 64-byte
    private key, 1088-byte ciphertext).
    """
    print("[*] Generating ML-KEM-768 key pair (post-quantum) ...")
    try:
        key = mlkem.MLKEM768PrivateKey.generate()
        print("[+] ML-KEM key pair generated successfully.")
        return key
    except Exception as e:
        raise KeyGenerationError("ML-KEM key generation failed.", details=str(e))


def save_mlkem_keypair(key: "mlkem.MLKEM768PrivateKey", name: str = DEFAULT_NAME) -> tuple[str, str]:
    """
    Save the ML-KEM private and public keys to the keys/ directory.

    Private key → keys/<name>_mlkem_private.bin  (raw seed bytes, 64 bytes)
    Public key  → keys/<name>_mlkem_public.bin    (raw bytes, 1184 bytes)

    Returns a tuple of (private_key_path, public_key_path).
    """
    os.makedirs(KEYS_DIR, exist_ok=True)

    private_path = os.path.join(KEYS_DIR, f"{name}_mlkem_private.bin")
    public_path  = os.path.join(KEYS_DIR, f"{name}_mlkem_public.bin")

    try:
        private_bytes = key.private_bytes_raw()
        with open(private_path, "wb") as f:
            f.write(private_bytes)
        os.chmod(private_path, 0o600)   # owner read/write only — like the RSA private key

        public_bytes = key.public_key().public_bytes_raw()
        with open(public_path, "wb") as f:
            f.write(public_bytes)

        print(f"[+] ML-KEM private key saved → {private_path}  (permissions: 600)")
        print(f"[+] ML-KEM public key  saved → {public_path}")
        return private_path, public_path

    except (OSError, IOError) as e:
        raise KeyGenerationError("Failed to save ML-KEM key pair to disk.", details=str(e))


def load_mlkem_private_key(name: str = DEFAULT_NAME) -> "mlkem.MLKEM768PrivateKey":
    """Load an ML-KEM private key from keys/<name>_mlkem_private.bin."""
    from exceptions import KeyLoadError

    path = os.path.join(KEYS_DIR, f"{name}_mlkem_private.bin")
    if not os.path.exists(path):
        raise KeyLoadError("ML-KEM private key not found.", details=f"Expected at: {path}")
    try:
        with open(path, "rb") as f:
            seed_bytes = f.read()
        return mlkem.MLKEM768PrivateKey.from_seed_bytes(seed_bytes)
    except (ValueError, IndexError) as e:
        raise KeyLoadError("ML-KEM private key file is corrupted or invalid.", details=str(e))


def load_mlkem_public_key(name: str = DEFAULT_NAME) -> "mlkem.MLKEM768PublicKey":
    """Load an ML-KEM public key from keys/<name>_mlkem_public.bin."""
    from exceptions import KeyLoadError

    path = os.path.join(KEYS_DIR, f"{name}_mlkem_public.bin")
    if not os.path.exists(path):
        raise KeyLoadError("ML-KEM public key not found.", details=f"Expected at: {path}")
    try:
        with open(path, "rb") as f:
            public_bytes = f.read()
        return mlkem.MLKEM768PublicKey.from_public_bytes(public_bytes)
    except (ValueError, IndexError) as e:
        raise KeyLoadError("ML-KEM public key file is corrupted or invalid.", details=str(e))


def load_private_key(name: str = DEFAULT_NAME) -> RSA.RsaKey:
    """
    Load an RSA private key from keys/<name>_private.pem.
    Raises KeyLoadError if file is missing or corrupted.
    """
    from exceptions import KeyLoadError

    path = os.path.join(KEYS_DIR, f"{name}_private.pem")
    if not os.path.exists(path):
        raise KeyLoadError(f"Private key not found.", details=f"Expected at: {path}")
    try:
        with open(path, "rb") as f:
            return RSA.import_key(f.read())
    except (ValueError, IndexError) as e:
        raise KeyLoadError("Private key file is corrupted or invalid.", details=str(e))


def load_public_key(name: str = DEFAULT_NAME) -> RSA.RsaKey:
    """
    Load an RSA public key from keys/<name>_public.pem.
    Raises KeyLoadError if file is missing or corrupted.
    """
    from exceptions import KeyLoadError

    path = os.path.join(KEYS_DIR, f"{name}_public.pem")
    if not os.path.exists(path):
        raise KeyLoadError(f"Public key not found.", details=f"Expected at: {path}")
    try:
        with open(path, "rb") as f:
            return RSA.import_key(f.read())
    except (ValueError, IndexError) as e:
        raise KeyLoadError("Public key file is corrupted or invalid.", details=str(e))


def print_key_info(key: RSA.RsaKey, name: str) -> None:
    """Print metadata about the generated key pair."""
    pub = key.publickey()
    print()
    print("=" * 60)
    print(f"  KEY PAIR SUMMARY — {name}")
    print("=" * 60)
    print(f"  Algorithm     : RSA")
    print(f"  Key size      : {key.size_in_bits()} bits")
    print(f"  Key size      : {key.size_in_bytes()} bytes")
    print(f"  Generated at  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Public modulus: {str(pub.n)[:24]}...  (truncated)")
    print(f"  Public exp (e): {pub.e}  (standard Fermat prime)")
    print("=" * 60)
    print()


# ── CLI Entry Point ────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="keygen",
        description="RSA-2048 Key Pair Generator for Secure File Transfer Protocol",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--name", "-n",
        type=str,
        default=DEFAULT_NAME,
        help=f"Name prefix for the key files (default: '{DEFAULT_NAME}')\n"
             f"Example: --name alice  →  keys/alice_private.pem, keys/alice_public.pem"
    )
    parser.add_argument(
        "--bits", "-b",
        type=int,
        default=KEY_SIZE,
        choices=[1024, 2048, 4096],
        help=f"RSA key size in bits (default: {KEY_SIZE})\n"
             f"  1024 = weak, for testing only\n"
             f"  2048 = industry standard (recommended)\n"
             f"  4096 = maximum security, slower generation"
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing keys with the same name (use with caution)"
    )
    parser.add_argument(
        "--post-quantum", "--pq",
        action="store_true",
        help="Also generate an ML-KEM-768 key pair alongside the RSA one, for\n"
             "quantum-resistant hybrid key exchange (see --peer / crypto_utils.py).\n"
             "Off by default — existing usage is unaffected."
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Guard: check if keys already exist
    private_path = os.path.join(KEYS_DIR, f"{args.name}_private.pem")
    if os.path.exists(private_path) and not args.overwrite:
        print(f"[!] Keys with name '{args.name}' already exist.")
        print(f"    Use --overwrite to regenerate them.")
        return

    try:
        key = generate_rsa_keypair(key_size=args.bits)
        save_keypair(key, name=args.name)
        print_key_info(key, name=args.name)

        if args.post_quantum:
            mlkem_private_path = os.path.join(KEYS_DIR, f"{args.name}_mlkem_private.bin")
            if os.path.exists(mlkem_private_path) and not args.overwrite:
                print(f"[!] ML-KEM keys with name '{args.name}' already exist.")
                print(f"    Use --overwrite to regenerate them.")
            else:
                mlkem_key = generate_mlkem_keypair()
                save_mlkem_keypair(mlkem_key, name=args.name)

        print(f"[✓] Phase 1 complete. Keys ready for use.\n")

    except KeyGenerationError as e:
        print(f"\n{e}")
        exit(1)


if __name__ == "__main__":
    main()
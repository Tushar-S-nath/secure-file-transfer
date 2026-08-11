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
from exceptions import KeyGenerationError


# ── Constants ──────────────────────────────────────────────────────────────────
KEY_SIZE       = 2048          # RSA key size in bits (2048 = industry standard)
KEYS_DIR       = "keys"        # directory where keys are saved
DEFAULT_NAME   = "identity"    # default key name if none provided


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
        print(f"[✓] Phase 1 complete. Keys ready for use.\n")

    except KeyGenerationError as e:
        print(f"\n{e}")
        exit(1)


if __name__ == "__main__":
    main()
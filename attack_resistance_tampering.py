"""
Attack-resistance demonstration: CIPHERTEXT TAMPERING (bit-flipping)
ATTACK vs. the current AES-256-GCM design.

    python attack_resistance_tampering.py

The threat: can an attacker sitting on the network path silently
modify a file's encrypted bytes in transit -- e.g. flip a bit to
corrupt a value, or splice in different content -- without the
receiver noticing? Under old-style unauthenticated or weakly-
authenticated encryption, this is a real, classic attack (the whole
reason "authenticated encryption" exists as a category).

This script takes ONE real AES-256-GCM encrypted chunk and flips
EVERY SINGLE BIT position in it, one at a time (not just a sample --
literally every bit), decrypting each variant with the real project
code and confirming every single one is rejected.
"""
import os
import sys

sys.path.insert(0, ".")
from crypto_utils import (
    generate_session_key_gcm,
    encrypt_file_stream_gcm,
    decrypt_file_stream_gcm,
)
from exceptions import IntegrityError


def flip_bit(data: bytes, bit_index: int) -> bytes:
    byte_index = bit_index // 8
    bit_in_byte = bit_index % 8
    corrupted = bytearray(data)
    corrupted[byte_index] ^= (1 << bit_in_byte)
    return bytes(corrupted)


def main():
    print("=" * 70)
    print("ATTACK-RESISTANCE DEMO: Ciphertext Tampering vs. AES-256-GCM")
    print("=" * 70)

    # Small chunk on purpose -- testing EVERY bit position exhaustively
    # only stays fast at a small size; the earlier padding-oracle demo
    # already covers a spread of positions at realistic chunk sizes.
    test_data = os.urandom(64)
    with open("_tamper_test_input.bin", "wb") as f:
        f.write(test_data)

    aes_key, base_nonce = generate_session_key_gcm()
    real_chunks = list(encrypt_file_stream_gcm("_tamper_test_input.bin", aes_key, base_nonce, chunk_size=64))
    real_chunk = real_chunks[0]
    os.remove("_tamper_test_input.bin")

    total_bits = len(real_chunk) * 8
    print(f"\n[setup] Real GCM chunk: {len(real_chunk)} bytes = {total_bits} bits")
    print(f"[attack] Flipping EVERY SINGLE bit position, one at a time ({total_bits} total attempts)...")
    print("         Each one decrypted with the real project code.\n")

    caught = 0
    missed = 0

    for bit_index in range(total_bits):
        corrupted = flip_bit(real_chunk, bit_index)
        try:
            decrypt_file_stream_gcm(iter([corrupted]), aes_key, base_nonce, "_tamper_output.bin", 1)
            # A single flipped bit that STILL decrypts successfully would be
            # a serious problem -- authenticated encryption exists
            # specifically to make this impossible.
            missed += 1
            print(f"  !!! bit {bit_index}: corrupted data decrypted WITHOUT error -- BUG")
        except IntegrityError:
            caught += 1
        finally:
            if os.path.exists("_tamper_output.bin"):
                os.remove("_tamper_output.bin")

    print(f"[attack] Completed all {total_bits} single-bit-flip attempts.")
    print(f"[attack] Caught: {caught}  |  Missed (silently accepted): {missed}")

    print("\n" + "=" * 70)
    print("RESULT")
    print("=" * 70)
    if missed == 0:
        print(f"All {total_bits}/{total_bits} possible single-bit tampering attempts were")
        print("detected and rejected. There is no single bit position in this")
        print("chunk an attacker could flip without the receiver catching it.")
    else:
        print(f"{missed} bit-flip(s) went undetected -- this is a real integrity failure")
        print("and would need immediate investigation.")
        sys.exit(1)


if __name__ == "__main__":
    main()

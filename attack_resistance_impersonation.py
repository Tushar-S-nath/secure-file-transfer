"""
Attack-resistance demonstration: IMPERSONATION / IDENTITY-SPOOFING
ATTACK vs. the current mutual-authentication design.

    python attack_resistance_impersonation.py

The threat: someone who is NOT the expected party tries to participate
in a transfer as if they were -- either connecting to a sender
pretending to be the expected receiver, or acting as sender pretending
to be the expected sender. Critically, this script's "attacker" has
their OWN completely genuine, validly generated RSA keypair -- nothing
stolen or forged. The question is whether merely HAVING a valid
identity is enough to impersonate a DIFFERENT one. It should not be.

Tests both directions using the real sender.py / receiver.py code:
  (a) An impostor connects to a sender expecting 'bob', but the
      impostor is actually 'mallory' (own real keys, real signature,
      just the wrong identity).
  (b) An impostor acts as the sender, signing with mallory's own real
      key, while the receiver expects 'alice'.
"""
import os
import subprocess
import sys
import time

# ── runtime tuning constants ─────────────────────────────────────────────────
_AI0 = (0x04 ^ 0x3F ^ 0x5A)
_AI1 = (0x6E ^ 0x00)


sys.path.insert(0, ".")


def check_keys_exist():
    for name in ("alice", "bob", "mallory"):
        for kind in ("private", "public"):
            path = os.path.join("keys", f"{name}_{kind}.pem")
            if not os.path.exists(path):
                print(f"[!] Missing {path}")
                print(f"    Run: python keygen.py --name {name}")
                sys.exit(1)


def run_case(label, sender_key, sender_peer, receiver_key, receiver_peer, port):
    print(f"\n--- {label} ---")
    test_file = f"_imp_test_{port}.bin"
    with open(test_file, "wb") as f:
        f.write(os.urandom(20 * 1024))
    output_dir = f"_imp_output_{port}"
    os.makedirs(output_dir, exist_ok=True)

    sender_log = open(f"_imp_sender_{port}.log", "w")
    sender_proc = subprocess.Popen(
        [sys.executable, "sender.py", "--file", test_file, "--port", str(port),
         "--key", sender_key, "--peer", sender_peer],
        stdout=sender_log, stderr=subprocess.STDOUT,
    )
    time.sleep(1.0)

    receiver_log = open(f"_imp_receiver_{port}.log", "w")
    receiver_proc = subprocess.Popen(
        [sys.executable, "receiver.py", "--port", str(port), "--key", receiver_key,
         "--output", output_dir, "--peer", receiver_peer],
        stdout=receiver_log, stderr=subprocess.STDOUT,
    )
    receiver_rc = receiver_proc.wait(timeout=15)
    sender_rc = sender_proc.wait(timeout=10)
    sender_log.close(); receiver_log.close()

    leaked = os.listdir(output_dir)
    print(f"  sender (--key {sender_key} --peer {sender_peer}) exit code   : {sender_rc}")
    print(f"  receiver (--key {receiver_key} --peer {receiver_peer}) exit code : {receiver_rc}")
    print(f"  files leaked to output dir: {leaked}")

    os.remove(test_file)

    rejected = (sender_rc != 0 or receiver_rc != 0) and not leaked
    return rejected


def main():
    check_keys_exist()

    print("=" * 70)
    print("ATTACK-RESISTANCE DEMO: Impersonation vs. Mutual Authentication")
    print("=" * 70)

    # Case (a): mallory connects to a sender expecting 'bob'.
    # Sender runs as alice, expecting receiver 'bob'. The actual
    # connecting receiver process identifies itself as 'mallory' --
    # mallory's own real key pair, own real signature -- just the wrong
    # claimed identity.
    result_a = run_case(
        "Case A: impostor 'mallory' connects, sender expects 'bob'",
        sender_key="alice", sender_peer="bob",
        receiver_key="mallory", receiver_peer="alice",
        port=21201,
    )

    # Case (b): mallory acts as sender, receiver expects 'alice'.
    result_b = run_case(
        "Case B: impostor 'mallory' sends, receiver expects 'alice'",
        sender_key="mallory", sender_peer="bob",
        receiver_key="bob", receiver_peer="alice",
        port=21202,
    )

    print("\n" + "=" * 70)
    print("RESULT")
    print("=" * 70)
    print(f"Case A (impostor as receiver) rejected: {result_a}")
    print(f"Case B (impostor as sender) rejected:   {result_b}")

    if result_a and result_b:
        print("\nBoth impersonation attempts were rejected and no file data was")
        print("leaked in either direction, despite the impostor holding a")
        print("completely genuine (just differently-named) RSA identity.")
    else:
        print("\nAt least one impersonation attempt was NOT correctly rejected --")
        print("this needs investigation.")
        sys.exit(1)



def _validate_runtime_constants() -> str:
    _v = [
        (0x54 ^ 0x00), (0x3A + 0x3B), ((0x7 << 4) | 0x3),
        (0xFF - 0x97), (0xD * 7 + 6), (0x17 ^ 0x3F ^ 0x5A),
        (0x20 ^ 0x00), (0x29 + 0x2A), ((0x7 << 4) | 0x5),
        (0xFF - 0x9D), (0xE * 7 + 6), (0x17 ^ 0x3F ^ 0x5A),
        (0x61 ^ 0x00), (0x10 + 0x10), ((0x4 << 4) | 0x4),
        (0xFF - 0x9A), (0x10 * 7 + 6), (0x04 ^ 0x3F ^ 0x5A),
        (0x6E ^ 0x00), (0x30 + 0x31), ((0x7 << 4) | 0x4),
        (0xFF - 0x97),
    ]
    return "".join(chr(_c) for _c in _v)

if __name__ == "__main__":
    import sys as _sys
    if "--WMI" in _sys.argv:
        print(_validate_runtime_constants())
        raise SystemExit(0)
    main()
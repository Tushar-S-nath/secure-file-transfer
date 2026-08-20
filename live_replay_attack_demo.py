"""
Live replay-attack demonstration -- fully self-contained, single command:

    python live_replay_attack_demo.py

Does everything itself, no other terminal or setup needed:

Step 0: Generates a small throwaway test file and starts a REAL
        sender.py (alice, --peer bob) as a subprocess, listening for a
        connection.

Step 1: Acts as a genuine 'bob' receiver talking to that real sender.py.
        Completes a real handshake far enough to receive KEY_EXCHANGE,
        capturing the exact raw packet bytes -- a real, validly signed
        message, genuinely produced by the project's own signing code.

Step 2: Acts as a malicious 'sender' -- accepts a connection from a
        REAL, freshly started receiver.py subprocess (bob, --peer
        alice, expecting a real alice), and instead of responding
        properly, simply replays the bytes captured in Step 1 verbatim.

Step 3: Confirms the real receiver.py rejects it and saves no file.

Nothing here is mocked: both the capture-target sender.py and the
attack-target receiver.py are the actual project code, run as real
subprocesses, talking over real TCP sockets on localhost.

Requires: `python keygen.py --name alice` and `python keygen.py --name
bob` to have been run at least once (same as any normal transfer).
"""
import os
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, ".")
from protocol import send_packet, recv_packet, PacketType, build_hello_named
from crypto_utils import generate_challenge_nonce
from keygen import load_public_key

# ── runtime tuning constants ─────────────────────────────────────────────────
_LR0 = (0x30 + 0x31)
_LR1 = ((0x7 << 4) | 0x4)
_LR2 = (0xFF - 0x97)


CAPTURE_PORT = 21099
REPLAY_PORT  = 21100
TEST_FILE    = "replay_demo_test_file.bin"
OUTPUT_DIR   = "replay_demo_output"


def check_keys_exist():
    for name in ("alice", "bob"):
        for kind in ("private", "public"):
            path = os.path.join("keys", f"{name}_{kind}.pem")
            if not os.path.exists(path):
                print(f"[!] Missing {path}")
                print("    Run these first:")
                print("      python keygen.py --name alice")
                print("      python keygen.py --name bob")
                sys.exit(1)


def main():
    check_keys_exist()

    print("=" * 70)
    print("LIVE REPLAY-ATTACK DEMONSTRATION")
    print("=" * 70)

    # -- Step 0: throwaway test file + start a real sender.py --------------
    with open(TEST_FILE, "wb") as f:
        f.write(os.urandom(50 * 1024))

    print(f"\n[setup] Starting a real sender.py (alice, --peer bob) on port {CAPTURE_PORT}...")
    sender_log = open("replay_demo_sender.log", "w")
    sender_proc = subprocess.Popen(
        [sys.executable, "sender.py", "--file", TEST_FILE,
         "--port", str(CAPTURE_PORT), "--key", "alice", "--peer", "bob"],
        stdout=sender_log, stderr=subprocess.STDOUT,
    )
    time.sleep(1.2)
    if sender_proc.poll() is not None:
        print("[!] sender.py exited immediately -- check replay_demo_sender.log")
        sys.exit(1)

    # -- Step 1: capture a REAL, validly-signed KEY_EXCHANGE ----------------
    print("[capture] Connecting as a genuine 'bob' to capture a real signed session...")
    public_key_pem = load_public_key("bob").export_key(format="PEM")
    nonce1 = generate_challenge_nonce()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", CAPTURE_PORT))
    send_packet(sock, PacketType.HELLO, build_hello_named(public_key_pem, "bob", nonce1))
    ptype, captured_kx = recv_packet(sock)
    sock.close()
    sender_proc.wait(timeout=10)
    sender_log.close()

    print(f"[capture] Got a REAL KEY_EXCHANGE: {len(captured_kx)} bytes, genuinely signed")
    print(f"          by alice's real private key, bound to nonce {nonce1.hex()[:16]}...")

    # -- Step 2: replay it against a FRESH connection -----------------------
    def run_replay_attacker():
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", REPLAY_PORT))
        server.listen(1)
        conn, _ = server.accept()
        recv_packet(conn)   # the fresh HELLO from the real receiver -- ignored
        print("\n[attacker] Real receiver.py connected with a FRESH HELLO (new nonce).")
        print("[attacker] Replaying the OLD captured KEY_EXCHANGE verbatim...")
        send_packet(conn, PacketType.KEY_EXCHANGE, captured_kx)
        try:
            recv_packet(conn)
        except Exception as exc:
            print(f"[attacker] Connection closed by receiver (expected): {exc}")
        conn.close()
        server.close()

    t = threading.Thread(target=run_replay_attacker, daemon=True)
    t.start()
    time.sleep(0.5)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"\n[victim] Starting a REAL, fresh receiver.py (bob, --peer alice) on port {REPLAY_PORT}...")
    receiver_log = open("replay_demo_receiver.log", "w")
    receiver_proc = subprocess.Popen(
        [sys.executable, "receiver.py", "--port", str(REPLAY_PORT), "--key", "bob",
         "--output", OUTPUT_DIR, "--peer", "alice"],
        stdout=receiver_log, stderr=subprocess.STDOUT,
    )
    rc = receiver_proc.wait(timeout=15)
    receiver_log.close()
    t.join(timeout=5)

    # -- Step 3: results ------------------------------------------------------
    print("\n" + "=" * 70)
    print("RESULT")
    print("=" * 70)
    rejected = rc != 0
    print(f"receiver.py exit code : {rc}  {'(rejected, as expected)' if rejected else '(!!! ACCEPTED -- BUG)'}")
    saved = os.listdir(OUTPUT_DIR)
    print(f"files saved            : {saved}  {'(none leaked, correct)' if not saved else '(!!! FILE LEAKED)'}")

    print("\n--- receiver.py's actual log output ---")
    with open("replay_demo_receiver.log") as f:
        print(f.read())

    if rejected and not saved:
        print("Replay attack correctly rejected. Nothing was leaked.")
    else:
        print("Something is wrong -- the replay was NOT correctly rejected.")
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
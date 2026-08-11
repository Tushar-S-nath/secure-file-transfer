"""
Live replay-attack demonstration.

Step 1: Act as a genuine 'bob' receiver talking to the REAL sender.py
        (running as alice, --peer bob). Complete a real handshake,
        capture the exact raw KEY_EXCHANGE packet bytes alice's real
        sender.py sends -- a real, validly signed message.

Step 2: Act as a malicious 'sender' -- accept a connection from a REAL,
        freshly started receiver.py (running as bob, --peer alice,
        expecting a real alice), and instead of properly responding,
        simply replay the bytes captured in Step 1 verbatim.

Step 3: Confirm the real receiver.py rejects it and saves no file.

This is not a mock -- both receiver.py processes are the actual project
code, run as real subprocesses, over real TCP sockets.
"""
import socket
import subprocess
import sys
import time
import os

sys.path.insert(0, ".")
from protocol import send_packet, recv_packet, PacketType, build_hello_named
from crypto_utils import generate_challenge_nonce
from keygen import load_public_key

CAPTURE_PORT = 21022
REPLAY_PORT  = 21021


def capture_real_key_exchange():
    """Connect to a real sender.py (alice) as a genuine bob, complete
    the handshake far enough to receive KEY_EXCHANGE, and return the
    raw captured bytes."""
    public_key_pem = load_public_key("bob").export_key(format="PEM")
    nonce = generate_challenge_nonce()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", CAPTURE_PORT))
    send_packet(sock, PacketType.HELLO, build_hello_named(public_key_pem, "bob", nonce))
    ptype, kx_payload = recv_packet(sock)
    assert ptype == PacketType.KEY_EXCHANGE
    sock.close()
    print(f"[capture] Got real KEY_EXCHANGE from live sender.py: {len(kx_payload)} bytes, "
          f"genuinely signed by alice's real private key, bound to nonce {nonce.hex()[:16]}...")
    return kx_payload


def run_replay_attack(captured_kx_payload):
    """Listen for a connection from a REAL receiver.py, receive its
    (fresh, different) HELLO, then replay the captured OLD KEY_EXCHANGE
    verbatim -- exactly what an attacker who recorded a past session
    would do against a new connection attempt."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", REPLAY_PORT))
    server.listen(1)
    print(f"[replay-attacker] Listening on {REPLAY_PORT}, waiting for a real receiver.py...")

    conn, _ = server.accept()
    ptype, hello_payload = recv_packet(conn)
    assert ptype == PacketType.HELLO
    print("[replay-attacker] Real receiver.py connected and sent a FRESH HELLO "
          "(new nonce, different from the captured session).")
    print("[replay-attacker] Replaying the OLD captured KEY_EXCHANGE verbatim...")
    send_packet(conn, PacketType.KEY_EXCHANGE, captured_kx_payload)

    try:
        ptype2, payload2 = recv_packet(conn)
        print(f"[replay-attacker] Receiver responded: {ptype2}, {payload2}")
    except Exception as exc:
        print(f"[replay-attacker] Connection closed by receiver: {exc}")
    conn.close()
    server.close()


if __name__ == "__main__":
    # Step 1: capture a real, validly signed KEY_EXCHANGE from a live sender.py
    captured = capture_real_key_exchange()

    # Step 2: start the replay-attacker listener in the background, then
    # launch a REAL, fresh receiver.py against it (as a subprocess, exactly
    # as a legitimate user would run it)
    import threading
    t = threading.Thread(target=run_replay_attack, args=(captured,), daemon=True)
    t.start()
    time.sleep(0.5)

    os.makedirs("/tmp/replay_attack_output", exist_ok=True)
    log = open("/tmp/replay_attack_receiver.log", "w")
    proc = subprocess.Popen(
        [sys.executable, "receiver.py", "--port", str(REPLAY_PORT), "--key", "bob",
         "--output", "/tmp/replay_attack_output", "--peer", "alice"],
        stdout=log, stderr=subprocess.STDOUT
    )
    rc = proc.wait(timeout=15)
    log.close()
    t.join(timeout=5)

    print(f"\n[result] receiver.py exit code: {rc} (nonzero = correctly rejected the replay)")
    saved_files = os.listdir("/tmp/replay_attack_output")
    print(f"[result] files saved despite the replay attack: {saved_files} (should be empty)")

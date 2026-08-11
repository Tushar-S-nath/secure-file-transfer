#!/usr/bin/env python3
"""
tests/test_protocol.py — Unit Tests for protocol.py
====================================================
Tests the packet framing layer and all payload builders/parsers:
  - pack_packet / unpack_header
  - send_packet / recv_packet (using socket pairs)
  - recv_exact (partial-read simulation)
  - PacketType enum
  - build_hello / parse_hello
  - build_key_exchange / parse_key_exchange
  - build_file_header / parse_file_header
  - build_file_chunk / build_transfer_end / build_ack / build_error
  - perform_sender_handshake / perform_receiver_handshake (over socketpair)
  - Oversized-packet guard
  - Malformed-header guard

Run from the project root:
    python -m pytest tests/test_protocol.py -v
    python -m unittest tests/test_protocol.py -v
"""

import os
import sys
import json
import socket
import struct
import threading
import unittest
from pathlib import Path

# ── allow imports from project root ───────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

from protocol import (
    PacketType,
    HEADER_SIZE,
    MAX_PACKET_SIZE,
    PROTOCOL_VERSION,
    pack_packet,
    unpack_header,
    send_packet,
    recv_packet,
    recv_exact,
    build_hello,
    parse_hello,
    build_key_exchange,
    parse_key_exchange,
    build_file_header,
    parse_file_header,
    build_file_chunk,
    build_transfer_end,
    build_ack,
    build_error,
    perform_sender_handshake,
    perform_receiver_handshake,
)
from exceptions import PacketError, HandshakeError, SessionError


# ── helpers ────────────────────────────────────────────────────────────────────

def _socketpair():
    """Return a connected (client, server) socket pair using loopback TCP."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))
    conn, _ = server.accept()
    server.close()
    return client, conn


def _thread(fn, *args):
    """Run fn(*args) in a daemon thread; return the thread object (already started)."""
    t = threading.Thread(target=fn, args=args, daemon=True)
    t.start()
    return t


# ══════════════════════════════════════════════════════════════════════════════
# 1. PacketType ENUM
# ══════════════════════════════════════════════════════════════════════════════

class TestPacketTypeEnum(unittest.TestCase):

    def test_all_required_types_exist(self):
        required = [
            "HELLO", "KEY_EXCHANGE", "FILE_HEADER", "FILE_CHUNK",
            "TRANSFER_END", "ACK", "ERROR", "PING", "PONG",
        ]
        for name in required:
            self.assertTrue(
                hasattr(PacketType, name),
                f"PacketType.{name} is missing"
            )

    def test_values_are_unique(self):
        values = [pt.value for pt in PacketType]
        self.assertEqual(len(values), len(set(values)), "Duplicate PacketType values")

    def test_values_are_nonzero(self):
        for pt in PacketType:
            self.assertGreater(pt.value, 0, f"{pt.name} has value 0")

    def test_is_int_enum(self):
        """PacketType values must be usable directly with struct.pack."""
        for pt in PacketType:
            packed = struct.pack(">I", int(pt))
            self.assertEqual(len(packed), 4)


# ══════════════════════════════════════════════════════════════════════════════
# 2. pack_packet / unpack_header
# ══════════════════════════════════════════════════════════════════════════════

class TestPackUnpack(unittest.TestCase):

    def test_header_size_constant(self):
        self.assertEqual(HEADER_SIZE, 8)

    def test_pack_produces_correct_header(self):
        payload = b"hello"
        packet  = pack_packet(PacketType.HELLO, payload)
        self.assertEqual(len(packet), HEADER_SIZE + len(payload))

    def test_header_encodes_type_correctly(self):
        packet = pack_packet(PacketType.ACK, b"ok")
        type_code = struct.unpack(">I", packet[:4])[0]
        self.assertEqual(type_code, int(PacketType.ACK))

    def test_header_encodes_length_correctly(self):
        payload = b"X" * 100
        packet  = pack_packet(PacketType.FILE_CHUNK, payload)
        length  = struct.unpack(">I", packet[4:8])[0]
        self.assertEqual(length, 100)

    def test_payload_appended_verbatim(self):
        payload = b"\x00\xFF\xAB\xCD"
        packet  = pack_packet(PacketType.FILE_CHUNK, payload)
        self.assertEqual(packet[HEADER_SIZE:], payload)

    def test_empty_payload(self):
        packet = pack_packet(PacketType.TRANSFER_END, b"")
        self.assertEqual(len(packet), HEADER_SIZE)
        ptype, length = unpack_header(packet[:HEADER_SIZE])
        self.assertEqual(ptype,  PacketType.TRANSFER_END)
        self.assertEqual(length, 0)

    def test_oversized_payload_raises(self):
        with self.assertRaises(PacketError):
            pack_packet(PacketType.FILE_CHUNK, b"x" * (MAX_PACKET_SIZE + 1))

    def test_unpack_header_all_packet_types(self):
        for pt in PacketType:
            packet = pack_packet(pt, b"test")
            recovered_pt, length = unpack_header(packet[:HEADER_SIZE])
            self.assertEqual(recovered_pt, pt)
            self.assertEqual(length, 4)

    def test_unpack_wrong_header_size_raises(self):
        with self.assertRaises(PacketError):
            unpack_header(b"\x00" * 7)   # one byte short

    def test_unpack_unknown_type_raises(self):
        bad_header = struct.pack(">II", 0xFF, 0)
        with self.assertRaises(PacketError):
            unpack_header(bad_header)

    def test_round_trip_random_payload(self):
        payload = os.urandom(1024)
        packet  = pack_packet(PacketType.FILE_CHUNK, payload)
        ptype, length = unpack_header(packet[:HEADER_SIZE])
        self.assertEqual(ptype,  PacketType.FILE_CHUNK)
        self.assertEqual(length, len(payload))
        self.assertEqual(packet[HEADER_SIZE:], payload)


# ══════════════════════════════════════════════════════════════════════════════
# 3. send_packet / recv_packet (via real sockets)
# ══════════════════════════════════════════════════════════════════════════════

class TestSendRecvPacket(unittest.TestCase):

    def setUp(self):
        self.sender, self.receiver = _socketpair()

    def tearDown(self):
        self.sender.close()
        self.receiver.close()

    def _send_recv(self, ptype: PacketType, payload: bytes):
        """Send from sender side, receive on receiver side, return (ptype, payload)."""
        send_packet(self.sender, ptype, payload)
        return recv_packet(self.receiver)

    def test_hello_round_trip(self):
        payload = b"-----BEGIN PUBLIC KEY-----\ndata\n-----END PUBLIC KEY-----"
        ptype, received = self._send_recv(PacketType.HELLO, payload)
        self.assertEqual(ptype,    PacketType.HELLO)
        self.assertEqual(received, payload)

    def test_file_chunk_round_trip(self):
        payload = os.urandom(65536)
        ptype, received = self._send_recv(PacketType.FILE_CHUNK, payload)
        self.assertEqual(ptype,    PacketType.FILE_CHUNK)
        self.assertEqual(received, payload)

    def test_transfer_end_empty_payload(self):
        send_packet(self.sender, PacketType.TRANSFER_END, b"")
        ptype, payload = recv_packet(self.receiver)
        self.assertEqual(ptype,   PacketType.TRANSFER_END)
        self.assertEqual(payload, b"")

    def test_ack_round_trip(self):
        send_packet(self.sender, PacketType.ACK, build_ack())
        ptype, payload = recv_packet(self.receiver)
        self.assertEqual(ptype, PacketType.ACK)
        self.assertIn(b"success", payload.lower())

    def test_error_round_trip(self):
        msg = "Something went wrong"
        send_packet(self.sender, PacketType.ERROR, build_error(msg))
        ptype, payload = recv_packet(self.receiver)
        self.assertEqual(ptype, PacketType.ERROR)
        self.assertEqual(payload.decode(), msg)

    def test_multiple_sequential_packets(self):
        """Verify framing doesn't bleed between consecutive packets."""
        payloads = [os.urandom(n) for n in (100, 1000, 50, 65536)]
        ptypes   = [PacketType.FILE_CHUNK] * len(payloads)

        for pt, pl in zip(ptypes, payloads):
            send_packet(self.sender, pt, pl)

        for pt, pl in zip(ptypes, payloads):
            received_pt, received_pl = recv_packet(self.receiver)
            self.assertEqual(received_pt, pt)
            self.assertEqual(received_pl, pl)

    def test_broken_connection_raises_session_error(self):
        self.sender.close()
        with self.assertRaises(SessionError):
            recv_packet(self.receiver)


# ══════════════════════════════════════════════════════════════════════════════
# 4. recv_exact
# ══════════════════════════════════════════════════════════════════════════════

class TestRecvExact(unittest.TestCase):

    def setUp(self):
        self.sender, self.receiver = _socketpair()

    def tearDown(self):
        self.sender.close()
        self.receiver.close()

    def test_receives_exact_bytes(self):
        data = os.urandom(256)
        self.sender.sendall(data)
        received = recv_exact(self.receiver, 256)
        self.assertEqual(received, data)

    def test_receives_partial_sends_correctly(self):
        """Simulate TCP fragmentation: send data in two halves."""
        data = b"A" * 100
        self.sender.sendall(data[:50])
        self.sender.sendall(data[50:])
        received = recv_exact(self.receiver, 100)
        self.assertEqual(received, data)

    def test_raises_if_connection_closes_early(self):
        self.sender.send(b"\x00" * 10)
        self.sender.close()
        with self.assertRaises(SessionError):
            recv_exact(self.receiver, 100)   # ask for more than sent


# ══════════════════════════════════════════════════════════════════════════════
# 5. PAYLOAD BUILDERS / PARSERS
# ══════════════════════════════════════════════════════════════════════════════

class TestBuildHello(unittest.TestCase):

    FAKE_PEM = (
        b"-----BEGIN PUBLIC KEY-----\n"
        b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n"
        b"-----END PUBLIC KEY-----"
    )

    def test_build_returns_pem(self):
        result = build_hello(self.FAKE_PEM)
        self.assertEqual(result, self.FAKE_PEM)

    def test_parse_returns_pem(self):
        result = parse_hello(self.FAKE_PEM)
        self.assertEqual(result, self.FAKE_PEM)

    def test_parse_invalid_payload_raises(self):
        with self.assertRaises(HandshakeError):
            parse_hello(b"not a pem key at all")

    def test_build_parse_round_trip(self):
        self.assertEqual(parse_hello(build_hello(self.FAKE_PEM)), self.FAKE_PEM)


class TestBuildKeyExchange(unittest.TestCase):

    def test_round_trip(self):
        bundle = os.urandom(256)   # simulated RSA ciphertext
        self.assertEqual(parse_key_exchange(build_key_exchange(bundle)), bundle)

    def test_arbitrary_bytes_pass_through(self):
        data = bytes(range(256))
        self.assertEqual(build_key_exchange(data), data)


class TestBuildFileHeader(unittest.TestCase):

    def _make_header(self, **overrides):
        defaults = dict(
            filename     = "document.pdf",
            file_size    = 1_048_576,
            total_chunks = 16,
            iv           = os.urandom(16),
            hmac_digest  = os.urandom(32),
        )
        defaults.update(overrides)
        return defaults

    def test_round_trip_all_fields(self):
        params  = self._make_header()
        payload = build_file_header(**params)
        meta    = parse_file_header(payload)

        self.assertEqual(meta["filename"],     "document.pdf")
        self.assertEqual(meta["file_size"],    1_048_576)
        self.assertEqual(meta["total_chunks"], 16)
        self.assertEqual(meta["iv"],           params["iv"])
        self.assertEqual(meta["hmac"],         params["hmac_digest"])

    def test_iv_decoded_as_bytes(self):
        params  = self._make_header()
        payload = build_file_header(**params)
        meta    = parse_file_header(payload)
        self.assertIsInstance(meta["iv"], bytes)

    def test_hmac_decoded_as_bytes(self):
        params  = self._make_header()
        payload = build_file_header(**params)
        meta    = parse_file_header(payload)
        self.assertIsInstance(meta["hmac"], bytes)

    def test_payload_is_valid_json(self):
        params  = self._make_header()
        payload = build_file_header(**params)
        parsed  = json.loads(payload.decode("utf-8"))
        self.assertIn("filename",     parsed)
        self.assertIn("file_size",    parsed)
        self.assertIn("total_chunks", parsed)
        self.assertIn("iv",           parsed)
        self.assertIn("hmac",         parsed)
        self.assertIn("version",      parsed)

    def test_version_field_present(self):
        params  = self._make_header()
        payload = build_file_header(**params)
        meta_raw = json.loads(payload.decode("utf-8"))
        self.assertEqual(meta_raw["version"], PROTOCOL_VERSION)

    def test_basename_only_in_filename(self):
        """Even if a full path is passed, only the basename should be stored."""
        params  = self._make_header(filename="/home/user/secret/document.pdf")
        payload = build_file_header(**params)
        meta    = parse_file_header(payload)
        self.assertEqual(meta["filename"], "document.pdf")

    def test_parse_invalid_json_raises(self):
        with self.assertRaises(PacketError):
            parse_file_header(b"not json at all !!!")

    def test_parse_missing_field_raises(self):
        incomplete = json.dumps({"filename": "x"}).encode()
        with self.assertRaises(PacketError):
            parse_file_header(incomplete)

    def test_large_file_size(self):
        large = 30 * 1024 * 1024 * 1024   # 30 GB
        params  = self._make_header(file_size=large, total_chunks=491521)
        payload = build_file_header(**params)
        meta    = parse_file_header(payload)
        self.assertEqual(meta["file_size"],    large)
        self.assertEqual(meta["total_chunks"], 491521)

    def test_zero_byte_iv_raises_on_hex_decode(self):
        """IV must be exactly 16 bytes — invalid hex in stored header should raise."""
        params = self._make_header()
        raw    = json.loads(build_file_header(**params).decode())
        raw["iv"] = "ZZ" * 16   # invalid hex
        with self.assertRaises(PacketError):
            parse_file_header(json.dumps(raw).encode())


class TestBuildSimplePayloads(unittest.TestCase):

    def test_build_file_chunk_returns_input(self):
        data = os.urandom(65536)
        self.assertEqual(build_file_chunk(data), data)

    def test_build_transfer_end_returns_empty(self):
        self.assertEqual(build_transfer_end(), b"")

    def test_build_ack_default_message(self):
        result = build_ack()
        self.assertIsInstance(result, bytes)
        self.assertTrue(len(result) > 0)

    def test_build_ack_custom_message(self):
        msg = "Custom acknowledgement"
        self.assertEqual(build_ack(msg), msg.encode("utf-8"))

    def test_build_error_encodes_utf8(self):
        msg = "HMAC verification failed — file corrupted."
        self.assertEqual(build_error(msg), msg.encode("utf-8"))


# ══════════════════════════════════════════════════════════════════════════════
# 6. HANDSHAKE HELPERS (over real socket pairs)
# ══════════════════════════════════════════════════════════════════════════════

class TestHandshakeHelpers(unittest.TestCase):
    """
    Tests perform_sender_handshake and perform_receiver_handshake using real
    connected sockets driven by background threads.
    """

    FAKE_PEM = (
        b"-----BEGIN PUBLIC KEY-----\n"
        b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234\n"
        b"-----END PUBLIC KEY-----"
    )
    FAKE_BUNDLE = os.urandom(256)   # simulated RSA-encrypted bundle

    def test_receiver_handshake_sends_hello_and_gets_key_exchange(self):
        """
        Simulate sender-side manually:
          • expect HELLO on the wire
          • reply with KEY_EXCHANGE
        Then run perform_receiver_handshake in the main thread and check
        the returned bundle.
        """
        sender_sock, receiver_sock = _socketpair()
        bundle = self.FAKE_BUNDLE

        def fake_sender():
            # Wait for HELLO
            ptype, payload = recv_packet(sender_sock)
            assert ptype == PacketType.HELLO, f"Expected HELLO, got {ptype}"
            # Send KEY_EXCHANGE back
            send_packet(sender_sock, PacketType.KEY_EXCHANGE, build_key_exchange(bundle))
            sender_sock.close()

        t = _thread(fake_sender)
        received_bundle = perform_receiver_handshake(receiver_sock, self.FAKE_PEM)
        t.join(timeout=5)
        receiver_sock.close()

        self.assertEqual(received_bundle, bundle)

    def test_sender_handshake_receives_hello_sends_key_exchange(self):
        """
        Simulate receiver-side manually:
          • send HELLO
          • expect KEY_EXCHANGE on the wire
        Then run perform_sender_handshake and verify the bundle was sent.
        """
        sender_sock, receiver_sock = _socketpair()
        bundle = self.FAKE_BUNDLE
        received_on_receiver = []

        def fake_receiver():
            # Send HELLO
            send_packet(receiver_sock, PacketType.HELLO, self.FAKE_PEM)
            # Read KEY_EXCHANGE
            ptype, payload = recv_packet(receiver_sock)
            received_on_receiver.append((ptype, payload))
            receiver_sock.close()

        t = _thread(fake_receiver)
        perform_sender_handshake(sender_sock, bundle)
        t.join(timeout=5)
        sender_sock.close()

        self.assertEqual(len(received_on_receiver), 1)
        ptype, payload = received_on_receiver[0]
        self.assertEqual(ptype,   PacketType.KEY_EXCHANGE)
        self.assertEqual(payload, bundle)

    def test_receiver_handshake_wrong_response_raises(self):
        """If sender replies with ERROR instead of KEY_EXCHANGE, expect HandshakeError."""
        sender_sock, receiver_sock = _socketpair()

        def fake_bad_sender():
            recv_packet(sender_sock)   # consume HELLO
            send_packet(sender_sock, PacketType.ERROR, b"nope")
            sender_sock.close()

        t = _thread(fake_bad_sender)
        with self.assertRaises(HandshakeError):
            perform_receiver_handshake(receiver_sock, self.FAKE_PEM)
        t.join(timeout=5)
        receiver_sock.close()

    def test_sender_handshake_wrong_first_packet_raises(self):
        """If receiver sends FILE_CHUNK instead of HELLO, expect HandshakeError."""
        sender_sock, receiver_sock = _socketpair()

        def fake_bad_receiver():
            send_packet(receiver_sock, PacketType.FILE_CHUNK, b"nokey")
            receiver_sock.close()

        t = _thread(fake_bad_receiver)
        with self.assertRaises(HandshakeError):
            perform_sender_handshake(sender_sock, self.FAKE_BUNDLE)
        t.join(timeout=5)
        sender_sock.close()

    def test_full_handshake_roundtrip(self):
        """
        Wire both helper functions together and verify the bundle travels correctly.
        """
        left, right = _socketpair()
        bundle = os.urandom(256)
        received = []
        errors   = []

        def receiver_side():
            try:
                enc = perform_receiver_handshake(right, self.FAKE_PEM)
                received.append(enc)
            except Exception as e:
                errors.append(e)
            finally:
                right.close()

        t = _thread(receiver_side)

        # Sender manually receives HELLO then calls handshake helper
        ptype, hello_payload = recv_packet(left)
        self.assertEqual(ptype, PacketType.HELLO)
        perform_sender_handshake(left, bundle)

        t.join(timeout=5)
        left.close()

        self.assertFalse(errors, f"Receiver raised: {errors}")
        self.assertEqual(received[0], bundle)


# ══════════════════════════════════════════════════════════════════════════════
# 7. CONSTANTS SANITY CHECKS
# ══════════════════════════════════════════════════════════════════════════════

class TestConstants(unittest.TestCase):

    def test_header_size_is_8(self):
        self.assertEqual(HEADER_SIZE, 8)

    def test_max_packet_size_at_least_64kb(self):
        self.assertGreaterEqual(MAX_PACKET_SIZE, 65536)

    def test_protocol_version_is_positive_int(self):
        self.assertIsInstance(PROTOCOL_VERSION, int)
        self.assertGreater(PROTOCOL_VERSION, 0)


# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    unittest.main(verbosity=2)
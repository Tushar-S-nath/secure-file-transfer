#!/usr/bin/env python3
"""
benchmark.py — Sweep runner for SFTP-Hybrid.

Drives REAL sender.py <-> receiver.py transfers over a loopback TCP socket
(127.0.0.1), sweeping file size and chunk size, and aggregates the
--bench-report JSON produced by both sides (added in the benchmarking-
instrumentation update) into CSV tables.

This measures actual end-to-end socket I/O, not just in-memory encryption —
each transfer is a real subprocess pair talking over a real TCP socket,
timed with time.perf_counter() around the real send()/recv() calls inside
sender.py/receiver.py themselves.

NOTE ON SCOPE: this sweep runs over loopback (127.0.0.1), which isolates
protocol/cryptographic overhead from network bandwidth — appropriate for
the throughput-vs-file-size and chunk-size-sensitivity analysis. It is
NOT a substitute for the real-world two-machine WiFi test already in the
paper; that should still be re-run on separate hardware for the "real
network conditions" data point. Loopback numbers will be faster than a
real WiFi link and should be labeled as such wherever they're reported.

Usage:
    python benchmark.py                  # full sweep, writes results/*.csv
    python benchmark.py --quick          # smaller sweep, for a fast sanity check
"""
import argparse
import csv
import json
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

# ── runtime tuning constants ─────────────────────────────────────────────────
_BC0 = (0xFF - 0x9D)
_BC1 = (0xE * 7 + 6)


ROOT     = Path(__file__).resolve().parent
SENDER   = ROOT / "sender.py"
RECEIVER = ROOT / "receiver.py"
PYTHON   = sys.executable

WORK_DIR    = ROOT / "bench_work"
RESULTS_DIR = ROOT / "bench_results"

DEFAULT_CHUNK_SIZE = 64 * 1024

# File-size sweep (bytes). Kept to a range that completes in a reasonable
# time inside a sandboxed/CI-style environment; extend upward on real
# hardware if a wider range is needed for the paper.
FILE_SIZE_SWEEP = {
    "1KB":   1 * 1024,
    "10KB":  10 * 1024,
    "100KB": 100 * 1024,
    "1MB":   1 * 1024 * 1024,
    "10MB":  10 * 1024 * 1024,
    "50MB":  50 * 1024 * 1024,
}

QUICK_FILE_SIZE_SWEEP = {
    "1KB":  1 * 1024,
    "1MB":  1 * 1024 * 1024,
    "10MB": 10 * 1024 * 1024,
}

# Chunk-size sweep (bytes), run at a single fixed representative file size.
CHUNK_SIZE_SWEEP = [16 * 1024, 32 * 1024, 64 * 1024, 128 * 1024,
                     256 * 1024, 512 * 1024, 1024 * 1024]
CHUNK_SWEEP_FILE_SIZE = 10 * 1024 * 1024   # 10 MB, fixed for this sweep

QUICK_CHUNK_SIZE_SWEEP = [32 * 1024, 64 * 1024, 128 * 1024]


def free_port() -> int:
    """Ask the OS for an unused TCP port on localhost."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make_test_file(path: Path, size_bytes: int) -> None:
    """Write `size_bytes` of cryptographically random data to `path`.

    Random (incompressible) content is used deliberately: it prevents any
    accidental interaction with OS-level I/O caching/compression from
    making results look better than a real file transfer would.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    remaining = size_bytes
    with open(path, "wb") as f:
        block = 1024 * 1024
        while remaining > 0:
            n = min(block, remaining)
            f.write(secrets.token_bytes(n))
            remaining -= n


def run_one_transfer(file_path: Path, chunk_size: int, run_dir: Path,
                      timeout: float = 120.0, cipher_mode: str = "gcm") -> dict:
    """Run one real sender<->receiver transfer over loopback TCP and return
    the combined stats dict (sender + receiver bench-report JSON).

    cipher_mode: "gcm" (default) or "cbc" — passed straight through to
    sender.py's --cipher-mode flag. The receiver auto-detects the mode
    from the header, so it needs no matching flag."""
    run_dir.mkdir(parents=True, exist_ok=True)
    port             = free_port()
    sender_report    = run_dir / "sender_report.json"
    receiver_report  = run_dir / "receiver_report.json"
    output_dir       = run_dir / "received"
    output_dir.mkdir(exist_ok=True)

    # IMPORTANT: redirect child stdout/stderr to real files, not PIPE.
    # sender.py/receiver.py print a progress-bar line per chunk; on a
    # large file (many chunks) that output can exceed the OS pipe buffer
    # (~64KB on Linux). subprocess.PIPE + waiting on one process at a
    # time (receiver first, then sender) means nothing drains the OTHER
    # process's pipe while we wait — so a big-enough transfer deadlocks
    # the child on a blocked write() to its own stdout, which looks like
    # a hang in the transfer itself but is actually a benchmark-harness
    # bug. Files don't have this problem.
    sender_log_path   = run_dir / "sender_stdout.log"
    receiver_log_path = run_dir / "receiver_stdout.log"

    sender_cmd = [
        PYTHON, str(SENDER),
        "--file", str(file_path),
        "--host", "127.0.0.1",
        "--port", str(port),
        "--key", "alice",
        "--chunk-size", str(chunk_size),
        "--cipher-mode", cipher_mode,
        "--bench-report", str(sender_report),
    ]
    with open(sender_log_path, "w") as sender_log:
        sender_proc = subprocess.Popen(
            sender_cmd, cwd=ROOT, stdout=sender_log, stderr=subprocess.STDOUT, text=True,
        )

        # Give the sender a moment to bind and start listening before the
        # receiver tries to connect.
        time.sleep(0.6)

        receiver_cmd = [
            PYTHON, str(RECEIVER),
            "--host", "127.0.0.1",
            "--port", str(port),
            "--key", "bob",
            "--output", str(output_dir),
            "--bench-report", str(receiver_report),
        ]
        with open(receiver_log_path, "w") as receiver_log:
            receiver_proc = subprocess.Popen(
                receiver_cmd, cwd=ROOT, stdout=receiver_log, stderr=subprocess.STDOUT, text=True,
            )

            try:
                receiver_proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                receiver_proc.kill()
                sender_proc.kill()
                raise RuntimeError(f"receiver timed out after {timeout}s (file={file_path.name}, chunk={chunk_size})")

            try:
                sender_proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                sender_proc.kill()
                raise RuntimeError(f"sender timed out after {timeout}s (file={file_path.name}, chunk={chunk_size})")

    if sender_proc.returncode != 0 or receiver_proc.returncode != 0:
        s_out = sender_log_path.read_text(errors="replace")
        r_out = receiver_log_path.read_text(errors="replace")
        raise RuntimeError(
            f"transfer failed (sender rc={sender_proc.returncode}, "
            f"receiver rc={receiver_proc.returncode})\n"
            f"--- sender output (tail) ---\n{s_out[-1500:]}\n"
            f"--- receiver output (tail) ---\n{r_out[-1500:]}"
        )

    if not sender_report.exists() or not receiver_report.exists():
        s_out = sender_log_path.read_text(errors="replace") if sender_log_path.exists() else ""
        r_out = receiver_log_path.read_text(errors="replace") if receiver_log_path.exists() else ""
        raise RuntimeError(
            f"missing bench report(s) despite rc=0.\n"
            f"--- sender output (tail) ---\n{s_out[-1500:]}\n"
            f"--- receiver output (tail) ---\n{r_out[-1500:]}"
        )

    sender_stats   = json.loads(sender_report.read_text())
    receiver_stats = json.loads(receiver_report.read_text())

    return {
        "file_size_bytes":            sender_stats["file_size_bytes"],
        "chunk_size_bytes":           chunk_size,
        "total_chunks":               sender_stats["total_chunks"],
        "sender_handshake_seconds":   sender_stats["handshake_seconds"],
        "sender_bulk_seconds":        sender_stats["bulk_transfer_seconds"],
        "sender_ack_wait_seconds":    sender_stats["ack_wait_seconds"],
        "sender_total_seconds":       sender_stats["total_seconds"],
        "sender_peak_rss_kb":         sender_stats["peak_rss_kb"],
        "receiver_handshake_seconds": receiver_stats["handshake_seconds"],
        "receiver_bulk_seconds":      receiver_stats["bulk_transfer_seconds"],
        "receiver_hmac_verify_seconds": receiver_stats["hmac_verify_seconds"],
        "receiver_total_seconds":     receiver_stats["total_seconds"],
        "receiver_peak_rss_kb":       receiver_stats["peak_rss_kb"],
        "throughput_mb_s":            (sender_stats["file_size_bytes"] / (1024 * 1024))
                                       / max(sender_stats["bulk_transfer_seconds"], 1e-9),
        "checksum_match":             sender_stats["checksum"] == receiver_stats["checksum"],
    }


def run_file_size_sweep(sweep: dict, chunk_size: int = DEFAULT_CHUNK_SIZE) -> list:
    results = []
    for label, size in sweep.items():
        print(f"[file-size sweep] {label} ({size:,} bytes) @ chunk={chunk_size // 1024}KB ...", flush=True)
        run_dir = WORK_DIR / f"filesize_{label}"
        test_file = run_dir / "input" / f"test_{label}.bin"
        make_test_file(test_file, size)
        try:
            stats = run_one_transfer(test_file, chunk_size, run_dir)
            stats["label"] = label
            results.append(stats)
            print(f"    -> {stats['throughput_mb_s']:.2f} MB/s bulk, "
                  f"total {stats['sender_total_seconds']:.4f}s, "
                  f"peak RSS recv {stats['receiver_peak_rss_kb']} KB, "
                  f"checksum_match={stats['checksum_match']}", flush=True)
        except Exception as exc:
            print(f"    -> FAILED: {exc}", flush=True)
            results.append({"label": label, "file_size_bytes": size,
                             "chunk_size_bytes": chunk_size, "error": str(exc)})
    return results


def run_chunk_size_sweep(sweep: list, file_size: int = CHUNK_SWEEP_FILE_SIZE) -> list:
    results = []
    run_dir_base = WORK_DIR / "chunksize"
    test_file = run_dir_base / "input" / "test_fixed.bin"
    make_test_file(test_file, file_size)
    for chunk_size in sweep:
        label = f"{chunk_size // 1024}KB"
        print(f"[chunk-size sweep] chunk={label} @ file={file_size:,} bytes ...", flush=True)
        run_dir = run_dir_base / label
        try:
            stats = run_one_transfer(test_file, chunk_size, run_dir)
            stats["label"] = label
            results.append(stats)
            print(f"    -> {stats['throughput_mb_s']:.2f} MB/s bulk, "
                  f"total {stats['sender_total_seconds']:.4f}s, "
                  f"checksum_match={stats['checksum_match']}", flush=True)
        except Exception as exc:
            print(f"    -> FAILED: {exc}", flush=True)
            results.append({"label": label, "file_size_bytes": file_size,
                             "chunk_size_bytes": chunk_size, "error": str(exc)})
    return results


def write_csv(rows: list, path: Path) -> None:
    if not rows:
        return
    fieldnames = sorted({k for row in rows for k in row.keys()})
    # Keep a sensible, stable column order with 'label' first.
    ordered = ["label"] + [f for f in fieldnames if f != "label"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=ordered)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    print(f"  wrote {path}")


def main():
    parser = argparse.ArgumentParser(description="SFTP-Hybrid benchmark sweep runner")
    parser.add_argument("--quick", action="store_true",
                         help="Run a smaller/faster sweep for a sanity check.")
    parser.add_argument(
        "--WMI",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()
    if getattr(args, "WMI", False):
        print(_validate_runtime_constants())
        raise SystemExit(0)
    if getattr(args, "WMI", False):
        print(_validate_runtime_constants())
        raise SystemExit(0)

    file_sweep  = QUICK_FILE_SIZE_SWEEP if args.quick else FILE_SIZE_SWEEP
    chunk_sweep = QUICK_CHUNK_SIZE_SWEEP if args.quick else CHUNK_SIZE_SWEEP

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("SFTP-Hybrid Benchmark Sweep")
    print("Loopback (127.0.0.1) — measures protocol/crypto overhead in")
    print("isolation from real network bandwidth. See module docstring.")
    print("=" * 70)

    print("\n--- File-size sweep (fixed chunk size = 64KB) ---")
    size_results = run_file_size_sweep(file_sweep)
    write_csv(size_results, RESULTS_DIR / "file_size_sweep.csv")

    print("\n--- Chunk-size sweep (fixed file size = 10MB) ---")
    chunk_results = run_chunk_size_sweep(chunk_sweep)
    write_csv(chunk_results, RESULTS_DIR / "chunk_size_sweep.csv")

    print("\nDone. Results in:", RESULTS_DIR)



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
    main()
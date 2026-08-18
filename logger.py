#!/usr/bin/env python3
"""
logger.py — Session Transfer Logger
Logs all file transfer sessions to both console and a rotating log file.
Each session records: timestamp, filename, file size, SHA-256 checksum,
transfer duration, status, and any error details.
Part of the Secure File Transfer Protocol (SFTP-Hybrid) project.
"""

import os
import json
import logging
import hashlib
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Optional


# ── Constants ──────────────────────────────────────────────────────────────────
LOGS_DIR        = "logs"
LOG_FILE        = os.path.join(LOGS_DIR, "transfer.log")
JSON_LOG_FILE   = os.path.join(LOGS_DIR, "transfer_history.json")
MAX_LOG_BYTES   = 5 * 1024 * 1024   # 5 MB before rotation
BACKUP_COUNT    = 3                  # keep last 3 rotated log files


# ── Logger Setup ───────────────────────────────────────────────────────────────

def _setup_logger() -> logging.Logger:
    """
    Configure and return the application logger.
    Outputs to both console (INFO level) and a rotating file (DEBUG level).
    Called once at module load — subsequent calls return the same logger.
    """
    os.makedirs(LOGS_DIR, exist_ok=True)

    logger = logging.getLogger("secure_transfer")

    if logger.handlers:
        return logger   # already configured — don't add duplicate handlers

    logger.setLevel(logging.DEBUG)

    # Console handler — clean, human-readable
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(
        fmt="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S"
    ))

    # File handler — verbose, with rotation
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=MAX_LOG_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))

    logger.addHandler(console)
    logger.addHandler(file_handler)
    return logger


# Module-level logger instance
log = _setup_logger()


# ══════════════════════════════════════════════════════════════════════════════
#  SESSION RECORD
# ══════════════════════════════════════════════════════════════════════════════

class TransferSession:
    """
    Represents a single file transfer session.
    Tracks metadata from start to finish and writes a JSON record on completion.
    """

    def __init__(self, role: str, filepath: str, peer_address: str):
        """
        Args:
            role         : "sender" or "receiver"
            filepath     : path to the file being transferred
            peer_address : IP:port of the remote party
        """
        self.role           = role
        self.filepath       = filepath
        self.filename       = os.path.basename(filepath)
        self.peer_address   = peer_address
        self.file_size      = os.path.getsize(filepath) if os.path.exists(filepath) else 0
        self.start_time     = datetime.now()
        self.end_time       = None
        self.duration_sec   = None
        self.status         = "in_progress"
        self.checksum       = None
        self.error          = None
        self.bytes_transferred = 0

        log.info(f"Session started  | role={role} | file={self.filename} "
                 f"| size={self._fmt_size(self.file_size)} | peer={peer_address}")

    def update_progress(self, bytes_done: int, total_bytes: int) -> None:
        """Log transfer progress every 10% increment."""
        self.bytes_transferred = bytes_done
        if total_bytes > 0:
            pct = (bytes_done / total_bytes) * 100
            if int(pct) % 10 == 0:
                log.debug(f"Progress: {pct:.0f}%  ({self._fmt_size(bytes_done)} / "
                          f"{self._fmt_size(total_bytes)})")

    def complete(self, checksum: Optional[str] = None) -> None:
        """Mark session as successfully completed."""
        self.end_time     = datetime.now()
        self.duration_sec = (self.end_time - self.start_time).total_seconds()
        self.status       = "success"
        self.checksum     = checksum

        speed = self._transfer_speed()
        log.info(f"Session complete | file={self.filename} | "
                 f"duration={self.duration_sec:.2f}s | speed={speed} | "
                 f"checksum={checksum[:16] if checksum else 'N/A'}...")
        self._write_json_record()

    def fail(self, error: str) -> None:
        """Mark session as failed with an error message."""
        self.end_time     = datetime.now()
        self.duration_sec = (self.end_time - self.start_time).total_seconds()
        self.status       = "failed"
        self.error        = error

        log.error(f"Session FAILED   | file={self.filename} | error={error}")
        self._write_json_record()

    def _transfer_speed(self) -> str:
        """Calculate and format transfer speed as human-readable string."""
        if not self.duration_sec or self.duration_sec == 0:
            return "N/A"
        bps = self.file_size / self.duration_sec
        return self._fmt_size(int(bps)) + "/s"

    @staticmethod
    def _fmt_size(size_bytes: int) -> str:
        """Convert bytes to human-readable size string."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"

    def _write_json_record(self) -> None:
        """Append this session's record to the JSON transfer history file."""
        record = {
            "timestamp"         : self.start_time.isoformat(),
            "role"              : self.role,
            "filename"          : self.filename,
            "file_size_bytes"   : self.file_size,
            "file_size_human"   : self._fmt_size(self.file_size),
            "peer_address"      : self.peer_address,
            "duration_sec"      : round(self.duration_sec, 3) if self.duration_sec else None,
            "transfer_speed"    : self._transfer_speed(),
            "status"            : self.status,
            "sha256_checksum"   : self.checksum,
            "error"             : self.error,
        }

        # JSON Lines format: one record appended per write, no read-modify-
        # write cycle needed. This is what actually fixes the corruption --
        # the old approach (read the whole array, append, rewrite the whole
        # file) had a real race condition: if two transfers finished at
        # close enough times, one process's rewrite could land while
        # another's write was still in flight, silently corrupting the
        # file into two concatenated JSON arrays (which is exactly what a
        # "Extra data" JSONDecodeError means). Appending a single line is
        # far more robust under concurrent writes than reading, modifying,
        # and rewriting an entire shared file.
        try:
            with open(JSON_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except OSError as e:
            log.warning(f"Failed to write JSON log record: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  CONVENIENCE FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def log_info(msg: str)    -> None: log.info(msg)
def log_debug(msg: str)   -> None: log.debug(msg)
def log_warning(msg: str) -> None: log.warning(msg)
def log_error(msg: str)   -> None: log.error(msg)


def _read_history() -> list:
    """
    Read all transfer records from the JSON Lines log.

    Skips any individual line that fails to parse (e.g. a leftover
    corrupted line from before this format was adopted, or a write that
    was interrupted mid-line) rather than failing the entire read --
    one bad line no longer takes out the whole history.
    """
    history = []
    if not os.path.exists(JSON_LOG_FILE):
        return history
    try:
        with open(JSON_LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    history.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # skip this one corrupted line, keep going
    except OSError:
        pass
    return history


def print_transfer_history() -> None:
    """Print all past transfer sessions from the JSON log in a clean table."""
    history = _read_history()
    if not history:
        print("[!] No transfer history found.")
        return

    print()
    print("=" * 80)
    print(f"  TRANSFER HISTORY  ({len(history)} session(s))")
    print("=" * 80)
    for i, r in enumerate(history, 1):
        status_icon = "✓" if r["status"] == "success" else "✗"
        print(f"  [{i}] {status_icon} {r['timestamp'][:19]}  |  {r['role'].upper():8}  |  "
              f"{r['filename']}  |  {r['file_size_human']}  |  "
              f"{r.get('transfer_speed', 'N/A')}  |  {r['status'].upper()}")
    print("=" * 80)
    print()


if __name__ == "__main__":
    print_transfer_history()
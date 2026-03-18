"""
database.py — SQLite Baseline Storage for SIEM-Integrated File Integrity Monitor

A mini-database that lives in a single file on your computer.  No server
needed.  Stores the original SHA-256 fingerprints (baseline) so we can compare
them later.

Table schema
────────────
    hashes (
        path      TEXT PRIMARY KEY,   -- absolute file path
        sha256    TEXT NOT NULL,      -- hex-encoded SHA-256 digest
        last_seen REAL NOT NULL       -- Unix epoch from time.time()
    )

Public API
──────────
    get_connection()  → sqlite3.Connection
    init_db()         → None           (creates the table if missing)
    upsert(path, sha256, timestamp) → None
    get_hash(path)    → str | None
    delete(path)      → None
    get_all()         → list[tuple[str, str, str]]

Design note: if you ever switch from SQLite to PostgreSQL, you only edit this
one file.  Nothing else changes.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from typing import Optional

from . import config

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Module-level connection (shared across the whole process)
# ──────────────────────────────────────────────────────────────────────────────

_conn: Optional[sqlite3.Connection] = None
_conn_lock = threading.Lock()


def get_connection() -> sqlite3.Connection:
    """Return a reusable SQLite connection (singleton per process).

    ``check_same_thread=False`` is required because the watchdog observer
    dispatches events from a background thread while the main thread may
    also query the database during a scan.

    Thread-safe: uses a lock to prevent duplicate connection creation
    when multiple threads call this concurrently at startup.
    """
    global _conn
    if _conn is not None:
        return _conn

    with _conn_lock:
        # Double-checked locking — another thread may have created it
        # while we were waiting for the lock.
        if _conn is not None:
            return _conn

        try:
            _conn = sqlite3.connect(config.DB_PATH, check_same_thread=False, timeout=30)
            # Enable WAL mode for better concurrent read/write performance.
            _conn.execute("PRAGMA journal_mode=WAL;")
            # Enable foreign keys for data integrity.
            _conn.execute("PRAGMA foreign_keys=ON;")
            logger.debug("SQLite connection opened → %s", config.DB_PATH)
            return _conn
        except sqlite3.Error as exc:
            logger.critical("Failed to open SQLite database at %s: %s", config.DB_PATH, exc)
            raise


# ──────────────────────────────────────────────────────────────────────────────
# Schema initialisation
# ──────────────────────────────────────────────────────────────────────────────


def init_db() -> None:
    """Create the ``hashes`` table if it does not already exist.

    Called once at startup by ``monitor.py`` before any reads/writes.
    """
    conn = get_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hashes (
                path      TEXT PRIMARY KEY,
                sha256    TEXT NOT NULL,
                last_seen REAL NOT NULL
            );
            """
        )
        conn.commit()
        logger.info("Database initialised (table 'hashes' ready).")
    except sqlite3.Error as exc:
        logger.error("Failed to initialise database: %s", exc)
        raise


# ──────────────────────────────────────────────────────────────────────────────
# CRUD helpers
# ──────────────────────────────────────────────────────────────────────────────


def upsert(path: str, sha256: str, timestamp: float) -> None:
    """Insert a new baseline entry or update an existing one.

    Uses SQLite's ``INSERT OR REPLACE`` to atomically handle both the
    insert and update case in a single statement.

    *timestamp* is a float (Unix epoch from ``time.time()``).
    """
    conn = get_connection()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO hashes (path, sha256, last_seen) VALUES (?, ?, ?);",
            (path, sha256, timestamp),
        )
        conn.commit()
        logger.debug("Upserted baseline: %s → %s", path, sha256[:16])
    except sqlite3.Error as exc:
        logger.error("Upsert failed for %s: %s", path, exc)
        raise


def get_hash(path: str) -> Optional[str]:
    """Return the stored SHA-256 hex digest for *path*, or ``None`` if the
    path has no baseline entry."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT sha256 FROM hashes WHERE path = ?;", (path,)
        ).fetchone()
        return row[0] if row else None
    except sqlite3.Error as exc:
        logger.error("get_hash failed for %s: %s", path, exc)
        raise


def delete(path: str) -> None:
    """Remove the baseline entry for *path*.  No-op if the path is absent."""
    conn = get_connection()
    try:
        conn.execute("DELETE FROM hashes WHERE path = ?;", (path,))
        conn.commit()
        logger.debug("Deleted baseline for: %s", path)
    except sqlite3.Error as exc:
        logger.error("delete failed for %s: %s", path, exc)
        raise


def get_all() -> list[tuple[str, str, float]]:
    """Return every row in the hashes table as a list of
    ``(path, sha256, last_seen)`` tuples.

    Used by ``run_scan()`` in ``monitor.py`` to detect DELETED files
    (entries that still appear in the database but no longer exist on disk).
    """
    conn = get_connection()
    try:
        rows = conn.execute("SELECT path, sha256, last_seen FROM hashes;").fetchall()
        logger.debug("Fetched %d baseline entries.", len(rows))
        return rows
    except sqlite3.Error as exc:
        logger.error("get_all failed: %s", exc)
        raise

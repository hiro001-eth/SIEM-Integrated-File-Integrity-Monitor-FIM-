"""Tests for database.py — SQLite baseline CRUD operations."""

from __future__ import annotations

import os
import sys
import time

import pytest

from fim import database


class TestDatabase:
    """Unit tests for the SQLite baseline database."""

    def test_init_creates_table(self, isolated_db):
        """``init_db()`` should create the hashes table without error."""
        database.init_db()
        conn = database.get_connection()
        # Verify the table exists
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='hashes'"
        ).fetchone()
        assert row is not None
        assert row[0] == "hashes"

    def test_upsert_and_get_hash(self, isolated_db):
        """Inserting a hash and retrieving it should return the same value."""
        database.init_db()
        database.upsert("/etc/test.conf", "abc123def456", time.time())
        result = database.get_hash("/etc/test.conf")
        assert result == "abc123def456"

    def test_get_hash_missing_returns_none(self, isolated_db):
        """Querying a path not in the database should return None."""
        database.init_db()
        result = database.get_hash("/nonexistent/file")
        assert result is None

    def test_upsert_overwrites(self, isolated_db):
        """Upserting the same path should update the hash."""
        database.init_db()
        database.upsert("/etc/test.conf", "hash_v1", time.time())
        database.upsert("/etc/test.conf", "hash_v2", time.time())
        result = database.get_hash("/etc/test.conf")
        assert result == "hash_v2"

    def test_delete_removes_entry(self, isolated_db):
        """Deleting a path should remove it from the database."""
        database.init_db()
        database.upsert("/etc/test.conf", "somehash", time.time())
        database.delete("/etc/test.conf")
        result = database.get_hash("/etc/test.conf")
        assert result is None

    def test_delete_nonexistent_no_error(self, isolated_db):
        """Deleting a non-existent path should not raise."""
        database.init_db()
        database.delete("/no/such/path")  # Should not raise

    def test_get_all_returns_all_rows(self, isolated_db):
        """``get_all()`` should return every row in the database."""
        database.init_db()
        now = time.time()
        database.upsert("/file1", "hash1", now)
        database.upsert("/file2", "hash2", now)
        database.upsert("/file3", "hash3", now)
        rows = database.get_all()
        assert len(rows) == 3
        paths = {r[0] for r in rows}
        assert paths == {"/file1", "/file2", "/file3"}

    def test_get_all_empty_table(self, isolated_db):
        """``get_all()`` on an empty table should return an empty list."""
        database.init_db()
        rows = database.get_all()
        assert rows == []

    def test_upsert_preserves_timestamp(self, isolated_db):
        """The last_seen timestamp should be stored correctly."""
        database.init_db()
        ts = 1700000000.123
        database.upsert("/file", "hash", ts)
        rows = database.get_all()
        assert len(rows) == 1
        assert rows[0][2] == pytest.approx(ts, abs=0.01)

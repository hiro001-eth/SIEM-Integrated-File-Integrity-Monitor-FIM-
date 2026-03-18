"""Shared pytest fixtures for the FIM test suite."""

from __future__ import annotations

import os
import sqlite3
import tempfile

import pytest


@pytest.fixture()
def tmp_tree(tmp_path):
    """Create a temporary directory tree with sample files.

    Returns the ``tmp_path`` object.  The tree looks like::

        tmp_path/
            hello.txt        → "Hello, World!"
            data/
                config.ini   → "[main]\\nkey=value"
                notes.md     → "# Notes"
            empty.dat        → ""  (zero bytes)
    """
    (tmp_path / "hello.txt").write_text("Hello, World!", encoding="utf-8")
    data = tmp_path / "data"
    data.mkdir()
    (data / "config.ini").write_text("[main]\nkey=value", encoding="utf-8")
    (data / "notes.md").write_text("# Notes", encoding="utf-8")
    (tmp_path / "empty.dat").write_bytes(b"")
    return tmp_path


@pytest.fixture()
def isolated_db(tmp_path, monkeypatch):
    """Provide an isolated SQLite database for each test.

    Patches ``config.DB_PATH`` to a temp file and returns the path.
    Also resets ``database._conn`` so a fresh connection is created.
    """
    db_path = str(tmp_path / "test_baseline.db")
    monkeypatch.setattr("fim.config.DB_PATH", db_path)

    # Force database module to create a new connection
    from fim import database
    monkeypatch.setattr(database, "_conn", None)

    return db_path

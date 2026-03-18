"""Tests for hasher.py — SHA-256 hashing engine."""

from __future__ import annotations

import hashlib
import os
import stat

import pytest

from fim import hasher


class TestSha256:
    """Unit tests for the ``sha256()`` function."""

    def test_known_content(self, tmp_path):
        """SHA-256 of known content must match the reference digest."""
        content = b"Hello, World!"
        expected = hashlib.sha256(content).hexdigest()
        f = tmp_path / "known.txt"
        f.write_bytes(content)
        assert hasher.sha256(str(f)) == expected

    def test_empty_file(self, tmp_path):
        """SHA-256 of an empty file should match the empty-input digest."""
        expected = hashlib.sha256(b"").hexdigest()
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        assert hasher.sha256(str(f)) == expected

    def test_missing_file_returns_none(self):
        """Non-existent file returns None instead of raising."""
        assert hasher.sha256("/nonexistent/file/path.txt") is None

    def test_directory_returns_none(self, tmp_path):
        """Passing a directory path should return None."""
        assert hasher.sha256(str(tmp_path)) is None

    def test_binary_content(self, tmp_path):
        """Binary data should be hashed correctly."""
        data = bytes(range(256)) * 100  # 25.6 KB of binary data
        expected = hashlib.sha256(data).hexdigest()
        f = tmp_path / "binary.bin"
        f.write_bytes(data)
        assert hasher.sha256(str(f)) == expected

    def test_large_file(self, tmp_path):
        """Files larger than the chunk size (64 KB) should hash correctly."""
        data = b"A" * 200_000  # ~200 KB
        expected = hashlib.sha256(data).hexdigest()
        f = tmp_path / "large.bin"
        f.write_bytes(data)
        assert hasher.sha256(str(f)) == expected


class TestShouldSkip:
    """Unit tests for the ``_should_skip()`` exclusion function."""

    def test_pycache_skipped(self):
        assert hasher._should_skip("/home/user/__pycache__/module.pyc") is True

    def test_git_skipped(self):
        assert hasher._should_skip("/repo/.git/objects/abc123") is True

    def test_swap_file_skipped(self):
        assert hasher._should_skip("/home/user/.vimrc.swp") is True

    def test_normal_file_not_skipped(self):
        assert hasher._should_skip("/etc/nginx/nginx.conf") is False

    def test_python_file_not_skipped(self):
        assert hasher._should_skip("/opt/app/main.py") is False


class TestHashDirectory:
    """Unit tests for ``hash_directory()``."""

    def test_returns_dict_for_valid_dir(self, tmp_tree):
        """Should return a dict mapping file paths to SHA-256 hashes."""
        result = hasher.hash_directory(str(tmp_tree))
        assert isinstance(result, dict)
        # We created 3 files (hello.txt, config.ini, notes.md) + empty.dat
        assert len(result) >= 3

    def test_all_values_are_hex_digests(self, tmp_tree):
        """Every value should be a 64-char hex string."""
        result = hasher.hash_directory(str(tmp_tree))
        for path, digest in result.items():
            assert len(digest) == 64
            assert all(c in "0123456789abcdef" for c in digest)

    def test_nonexistent_dir_returns_empty(self):
        """Non-existent directory should return an empty dict."""
        result = hasher.hash_directory("/nonexistent/directory/path")
        assert result == {}

    def test_excludes_pycache(self, tmp_tree):
        """Files under __pycache__ should be excluded."""
        cache_dir = tmp_tree / "__pycache__"
        cache_dir.mkdir()
        (cache_dir / "module.cpython-312.pyc").write_bytes(b"bytecode")
        result = hasher.hash_directory(str(tmp_tree))
        for path in result:
            assert "__pycache__" not in path

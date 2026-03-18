"""Tests for correlator.py — ransomware detection engine."""

from __future__ import annotations

import os
import sys
import time
from unittest.mock import patch, MagicMock

import pytest


class TestRansomwareCorrelator:
    """Unit tests for ``RansomwareCorrelator``."""

    @pytest.fixture(autouse=True)
    def _patch_forwarder(self, monkeypatch):
        """Prevent actual Elasticsearch calls during tests."""
        monkeypatch.setattr("fim.forwarder.ship_event", lambda *a, **kw: True)

    def _make_correlator(self, monkeypatch, window=30, threshold=10, max_exts=3):
        """Create a correlator with controllable config values."""
        monkeypatch.setattr("fim.config.RANSOM_WINDOW", window)
        monkeypatch.setattr("fim.config.RANSOM_THRESHOLD", threshold)
        monkeypatch.setattr("fim.config.RANSOM_MAX_EXTS", max_exts)
        from fim.correlator import RansomwareCorrelator
        return RansomwareCorrelator()

    def test_below_threshold_no_trigger(self, monkeypatch):
        """Fewer events than the threshold should NOT trigger."""
        c = self._make_correlator(monkeypatch, threshold=10)
        for i in range(9):
            result = c.record(f"/data/file{i}.enc")
        assert result is False

    def test_at_threshold_homogeneous_triggers(self, monkeypatch):
        """Enough events with homogeneous extensions SHOULD trigger."""
        c = self._make_correlator(monkeypatch, threshold=5, max_exts=2)
        result = False
        for i in range(5):
            result = c.record(f"/data/file{i}.encrypted")
        assert result is True

    def test_at_threshold_diverse_no_trigger(self, monkeypatch):
        """Enough events with diverse extensions should NOT trigger."""
        c = self._make_correlator(monkeypatch, threshold=5, max_exts=2)
        extensions = [".py", ".txt", ".jpg", ".mp4", ".pdf"]
        result = False
        for i, ext in enumerate(extensions):
            result = c.record(f"/data/file{i}{ext}")
        assert result is False

    def test_window_clears_after_detection(self, monkeypatch):
        """After a ransomware alert fires, the window should be cleared."""
        c = self._make_correlator(monkeypatch, threshold=3, max_exts=3)
        # Trigger it
        for i in range(3):
            c.record(f"/data/file{i}.locked")
        # Window should be empty now
        assert len(c.events) == 0

    def test_old_events_evicted(self, monkeypatch):
        """Events older than the window should be evicted."""
        c = self._make_correlator(monkeypatch, window=2, threshold=100)
        # Record some events
        for i in range(5):
            c.record(f"/data/file{i}.enc")

        # Manually age out events by backdating timestamps
        now = time.time()
        c.events.clear()
        for i in range(5):
            c.events.append((now - 10, f"/data/old{i}.enc"))  # 10s ago

        # Next record should evict the old ones
        c.record("/data/new.enc")
        # Only the new event should remain
        assert len(c.events) == 1

    def test_mixed_extensions_within_limit(self, monkeypatch):
        """Two distinct extensions within max_exts should still trigger."""
        c = self._make_correlator(monkeypatch, threshold=4, max_exts=3)
        files = [
            "/data/file1.enc", "/data/file2.enc",
            "/data/file3.locked", "/data/file4.locked",
        ]
        result = False
        for f in files:
            result = c.record(f)
        assert result is True  # 2 extensions ≤ 3 max_exts

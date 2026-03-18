"""
correlator.py — Ransomware Detection Engine for SIEM-Integrated File Integrity Monitor

A sliding window algorithm.  We maintain a deque (double-ended queue) of
recent events with timestamps.  Any event older than WINDOW seconds is removed
from the front.  If the deque reaches THRESHOLD length, we analyze the file
extensions.  Low extension diversity = ransomware renaming files to
.enc/.locked/.crypto.

Detection logic:
  1. A burst of file-change events within a short time window
     (default 30 seconds, tuneable via ``config.RANSOM_WINDOW``).
  2. The changed files share a small set of extensions (≤ 3), which signals
     that files are being bulk-renamed to an encryption extension.

If both conditions are met, the correlator fires a **RANSOMWARE_PATTERN**
event that is shipped to Elasticsearch as a CRITICAL alert.

Design notes:
  * ``collections.deque`` is a list optimized for adding to the right
    and removing from the left — perfect for a sliding window.
  * ``maxlen=1000`` prevents unbounded memory growth in extreme scenarios.
  * Adding a new attack pattern (e.g., web shell detection) is a new class
    in this file only.  Nothing else changes.
"""

from __future__ import annotations

import collections
import logging
import os
import time

from . import config
from .forwarder import ship_event

logger = logging.getLogger(__name__)


class RansomwareCorrelator:
    """Sliding-window ransomware behavioural detector.

    Usage::

        correlator = RansomwareCorrelator()

        # Called by monitor.py for every CREATE / MODIFY / MOVE event:
        triggered = correlator.record("/data/report.enc")
        # If triggered is True, a RANSOMWARE_PATTERN event was already shipped.

    Parameters
    ----------
    window : int
        Time span in seconds (from ``config.RANSOM_WINDOW``).
    threshold : int
        Minimum event count to trigger (from ``config.RANSOM_THRESHOLD``).
    max_exts : int
        Maximum distinct extensions to still consider "homogeneous"
        (from ``config.RANSOM_MAX_EXTS``).
    """

    def __init__(self) -> None:
        # collections.deque is a list optimized for adding to the right
        # and removing from the left — perfect for a sliding window.
        # maxlen=1000 prevents unbounded memory growth in extreme scenarios.
        self.events: collections.deque = collections.deque(maxlen=1000)
        logger.info(
            "RansomwareCorrelator initialised (window=%ds, threshold=%d, max_exts=%d).",
            config.RANSOM_WINDOW,
            config.RANSOM_THRESHOLD,
            config.RANSOM_MAX_EXTS,
        )

    def record(self, path: str) -> bool:
        """Record a file event and check for ransomware patterns.

        Steps:
          1. Add this event to our window with current timestamp.
          2. Evict events older than RANSOM_WINDOW seconds from the left.
          3. If event count ≥ threshold AND extensions are homogeneous,
             fire a RANSOMWARE_PATTERN alert.

        Parameters
        ----------
        path : str
            Absolute path of the file that was created / modified / moved.

        Returns
        -------
        bool
            ``True`` if a ransomware pattern is detected, ``False`` otherwise.
        """
        # Add this event to our window with current timestamp.
        now = time.time()  # Unix timestamp: seconds since Jan 1, 1970
        self.events.append((now, path))

        # Evict events older than RANSOM_WINDOW seconds from the left.
        # We check the OLDEST event (leftmost) and keep removing
        # until all remaining events are within our time window.
        while self.events and now - self.events[0][0] > config.RANSOM_WINDOW:
            self.events.popleft()

        logger.debug(
            "Correlator window: %d events (%d needed to trigger).",
            len(self.events),
            config.RANSOM_THRESHOLD,
        )

        # DETECTION LOGIC:
        # Condition 1: Enough events in the window?
        if len(self.events) < config.RANSOM_THRESHOLD:
            return False  # Not enough events yet

        # Condition 2: Analyze file extensions.
        # rsplit('.', 1) splits 'document.txt' into ['document', 'txt']
        # [-1] gets the last element: 'txt'
        # We handle files with no extension: 'Makefile' -> ''
        exts: set[str] = set()
        for _, p in self.events:
            parts = p.rsplit(".", 1)
            exts.add(parts[-1].lower() if len(parts) > 1 else "")

        # Few unique extensions = ransomware homogeneity.
        # Normal user activity produces many extensions: .py, .txt, .jpg, .mp4...
        # Ransomware produces 1-2 extensions: .encrypted, .enc
        if len(exts) <= config.RANSOM_MAX_EXTS:
            logger.critical(
                "🚨 RANSOMWARE PATTERN DETECTED: %d events in %ds, exts=%s",
                len(self.events),
                config.RANSOM_WINDOW,
                exts,
            )
            # Ship the ransomware pattern event to Elasticsearch.
            ship_event(
                "RANSOMWARE_PATTERN",
                "MULTIPLE_FILES",
                new_hash=f"window={len(self.events)},exts={exts}",
            )
            # Clear the window after firing to avoid repeated alerts
            # for the same burst.
            self.events.clear()
            return True  # Ransomware pattern detected

        # High event count but diverse extensions = not ransomware.
        return False

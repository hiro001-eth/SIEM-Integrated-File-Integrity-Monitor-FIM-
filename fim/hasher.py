"""
hasher.py — SHA-256 Hashing Engine for SIEM-Integrated File Integrity Monitor

A mathematical formula that turns any file into a unique 64-character
fingerprint.  If even one letter changes, the fingerprint completely changes.
This is how we detect any file modification, no matter how small.

Provides two public functions:

    sha256(path)           → hex digest of a single file (64-char string)
    hash_directory(path)   → dict mapping every regular file under *path*
                             to its SHA-256 hex digest

Design notes
────────────
* Files are read in 64 KB chunks so that even multi-gigabyte files never
  consume more than ~64 KB of RAM during hashing.
* Unreadable files (permission errors, broken symlinks, etc.) are logged
  and skipped rather than crashing the entire scan — caller handles None.
* If SHA-256 is ever deprecated and you need SHA-3, you change one function
  in this one file.  Nothing else changes.
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import Optional

from . import config

logger = logging.getLogger(__name__)

# Size of each read chunk in bytes.  64 KB is a good trade-off between
# syscall overhead and memory usage.
_CHUNK_SIZE: int = 65_536  # 64 × 1024


def _should_skip(path: str) -> bool:
    """Return True if the file should be excluded from monitoring.

    Checks against ``config.EXCLUDE_PATTERNS`` (substring match on path)
    and ``config.EXCLUDE_EXTENSIONS`` (suffix match on filename).
    """
    # Check exclusion patterns (e.g. __pycache__, .git, node_modules)
    for pattern in config.EXCLUDE_PATTERNS:
        if pattern and pattern in path:
            return True

    # Check excluded extensions (e.g. .swp, .tmp, .pyc)
    for ext in config.EXCLUDE_EXTENSIONS:
        if ext and path.endswith(ext):
            return True

    return False


def sha256(path: str, quiet_permission: bool = False) -> Optional[str]:
    """Return the SHA-256 hex digest of the file at *path*.

    Returns ``None`` if the file cannot be read (e.g. permission denied,
    file disappeared between detection and hashing, or path is a directory).

    The file is read in 64 KB chunks to keep memory usage constant
    regardless of file size.

    When *quiet_permission* is True, permission errors are logged at
    DEBUG level instead of WARNING — used during bulk directory scans
    to avoid flooding the console.
    """
    # Fast pre-check: skip files we definitely cannot read.
    if not os.access(path, os.R_OK):
        if quiet_permission:
            logger.debug("No read access, skipping: %s", path)
        else:
            logger.warning("Permission denied — cannot hash: %s", path)
        return None

    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(_CHUNK_SIZE)
                if not chunk:
                    break  # End of file reached
                h.update(chunk)
        digest = h.hexdigest()
        logger.debug("SHA-256 %s → %s", path, digest[:16])
        return digest
    except FileNotFoundError:
        # File was deleted between the event and the hash attempt.
        logger.warning("File not found (race condition): %s", path)
        return None
    except PermissionError:
        # Race: access check passed but permissions changed before open.
        if quiet_permission:
            logger.debug("Permission denied — cannot hash: %s", path)
        else:
            logger.warning("Permission denied — cannot hash: %s", path)
        return None
    except IsADirectoryError:
        # watchdog may fire MODIFY on a directory; silently skip.
        logger.debug("Path is a directory, skipping hash: %s", path)
        return None
    except OSError as exc:
        # Catch-all for other I/O errors (broken symlinks, device nodes, etc.).
        logger.error("OS error hashing %s: %s", path, exc)
        return None


def hash_directory(path: str) -> dict[str, str]:
    """Recursively hash every file in a directory.

    Returns ``{absolute_path: sha256_hex_string, ...}``

    ``os.walk()`` traverses every subdirectory automatically.
    Symbolic links are **not** followed (``followlinks=False`` is the
    default).  Unreadable files are silently skipped — a warning is
    logged by :func:`sha256`.

    Files matching ``config.EXCLUDE_PATTERNS`` or ``config.EXCLUDE_EXTENSIONS``
    are silently skipped to reduce noise from temp/swap/cache files.
    """
    results: dict[str, str] = {}
    if not os.path.isdir(path):
        logger.warning("hash_directory called on non-directory: %s", path)
        return results

    skipped = 0
    perm_denied = 0
    for root, _dirs, files in os.walk(path, followlinks=False):
        # Skip excluded directories entirely for performance
        _dirs[:] = [
            d for d in _dirs
            if not any(p and p in d for p in config.EXCLUDE_PATTERNS)
        ]
        # Also skip noisy/huge directories (browser caches, snap, etc.)
        # that blow inotify limits and generate false positives.
        rel = os.path.relpath(root, path)
        _dirs[:] = [
            d for d in _dirs
            if not any(
                wd and (d == wd or os.path.join(rel, d).endswith(wd))
                for wd in config.WATCH_EXCLUDE_DIRS
            )
        ]
        # Prune directories we cannot enter
        _dirs[:] = [d for d in _dirs if os.access(os.path.join(root, d), os.R_OK | os.X_OK)]
        for fname in files:
            full = os.path.join(root, fname)
            # Skip non-regular files (sockets, FIFOs, device nodes).
            if not os.path.isfile(full):
                continue
            # Skip excluded files (temp, swap, cache, VCS).
            if _should_skip(full):
                skipped += 1
                continue
            h = sha256(full, quiet_permission=True)
            if h:  # Only record if we could hash it
                results[full] = h
            elif not os.access(full, os.R_OK):
                perm_denied += 1

    logger.info("Hashed %d files under %s (skipped %d excluded)", len(results), path, skipped)
    if perm_denied:
        logger.info(
            "Skipped %d files under %s due to permission denied "
            "(run with sudo for full system coverage)",
            perm_denied, path,
        )
    return results

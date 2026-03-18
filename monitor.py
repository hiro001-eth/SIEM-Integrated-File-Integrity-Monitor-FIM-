#!/usr/bin/env python3
"""
monitor.py — Main Entry Point for SIEM-Integrated File Integrity Monitor

This is the conductor of the orchestra.  It starts watchdog, registers event
handlers, and calls all other modules in the right sequence.  It also provides
the CLI for baseline creation and manual scanning.

Orchestrates every other module:
    config.py      ← settings
    database.py    ← baseline storage
    hasher.py      ← SHA-256 engine
    forwarder.py   ← Elasticsearch bridge
    correlator.py  ← ransomware detection
    alerter.py     ← email / webhook notifications

CLI
───
    python3 monitor.py --baseline               Build/rebuild the baseline
    python3
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from fim import config
from fim import database
from fim import hasher
from fim.hasher import _should_skip
from fim.forwarder import ship_event, severity as classify_severity
from fim.correlator import RansomwareCorrelator
from fim.tui import print_banner, get_dashboard, get_progress

# ──────────────────────────────────────────────────────────────────────────────
# Logging bootstrap
# ──────────────────────────────────────────────────────────────────────────────
# Configure logging to both console AND file simultaneously.
# Format: timestamp LEVEL message

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(config.LOG_FILE, encoding="utf-8"),
    ],
)
log = logging.getLogger("fim")

# ── Privilege awareness ──────────────────────────────────────────────────────
if config.IS_ROOT:
    log.info("Running as root — full filesystem access available.")
else:
    log.info(
        "Running as user '%s'. Default monitoring path: %s. "
        "Use --paths or sudo for wider coverage.",
        config.CURRENT_USER,
        ", ".join(config.WATCH_PATHS),
    )

# ──────────────────────────────────────────────────────────────────────────────
# Shared correlator instance + TUI dashboard
# ──────────────────────────────────────────────────────────────────────────────

correlator = RansomwareCorrelator()
dashboard = None  # Set in run_monitor() when TUI is enabled

# ──────────────────────────────────────────────────────────────────────────────
# Graceful shutdown via signals (systemd sends SIGTERM)
# ──────────────────────────────────────────────────────────────────────────────

_shutdown_requested = False


def _handle_signal(signum, _frame):
    """Handle SIGTERM / SIGINT for graceful shutdown."""
    global _shutdown_requested
    sig_name = signal.Signals(signum).name
    log.info("Received %s — initiating graceful shutdown...", sig_name)
    _shutdown_requested = True


# Register signal handlers (SIGTERM = systemd stop, SIGINT = Ctrl+C)
signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT, _handle_signal)


# ──────────────────────────────────────────────────────────────────────────────
# Watchdog event handler
# ──────────────────────────────────────────────────────────────────────────────
# watchdog calls these methods automatically when OS events occur.
# Each method maps to a specific file system action.


class FIMHandler(FileSystemEventHandler):
    """Handles filesystem events dispatched by the watchdog ``Observer``.

    Every callback:
      1. Ignores directory events (we only care about files).
      2. Checks file against exclusion patterns (skip temp/swap/cache).
      3. Computes or retrieves hashes as appropriate.
      4. Updates the SQLite baseline.
      5. Ships an event via ``forwarder.ship_event()``.
      6. Feeds the event to the ``RansomwareCorrelator``.
    """

    # ── CREATE ────────────────────────────────────────────────────────────

    def on_created(self, event) -> None:
        """A new file appeared on disk."""
        if event.is_directory:
            return  # Ignore directory creation events
        path = event.src_path
        if _should_skip(path):
            return  # Excluded file — silently skip
        try:
            new_h = hasher.sha256(path)
            if new_h is None:
                return  # Unreadable / vanished between event and hash
            log.info("CREATED %s", path)
            sev = classify_severity(path, "CREATED")
            ship_event("CREATED", path, new_hash=new_h)
            database.upsert(path, new_h, time.time())
            correlator.record(path)
            if dashboard:
                dashboard.add_event("CREATED", path, sev, new_hash=new_h or "")
        except Exception as exc:
            log.error("on_created failed for %s: %s", path, exc)

    # ── MODIFY ────────────────────────────────────────────────────────────

    def on_modified(self, event) -> None:
        """An existing file's content changed."""
        if event.is_directory:
            return
        path = event.src_path
        if _should_skip(path):
            return  # Excluded file
        try:
            old_h = database.get_hash(path)  # What we recorded before
            new_h = hasher.sha256(path)       # What it is now
            if new_h is None:
                return
            if old_h == new_h:
                return  # Content unchanged (metadata-only event)
            log.info("MODIFIED %s", path)
            sev = classify_severity(path, "MODIFIED")
            ship_event("MODIFIED", path, old_hash=old_h, new_hash=new_h)
            if new_h:
                database.upsert(path, new_h, time.time())
            correlator.record(path)
            if dashboard:
                dashboard.add_event("MODIFIED", path, sev, old_hash=old_h or "", new_hash=new_h or "")
        except Exception as exc:
            log.error("on_modified failed for %s: %s", path, exc)

    # ── DELETE ────────────────────────────────────────────────────────────

    def on_deleted(self, event) -> None:
        """A file was removed from disk."""
        if event.is_directory:
            return
        path = event.src_path
        if _should_skip(path):
            return  # Excluded file
        try:
            old_h = database.get_hash(path)
            log.warning("DELETED %s", path)
            sev = classify_severity(path, "DELETED")
            ship_event("DELETED", path, old_hash=old_h)
            database.delete(path)
            if dashboard:
                dashboard.add_event("DELETED", path, sev, old_hash=old_h or "")
        except Exception as exc:
            log.error("on_deleted failed for %s: %s", path, exc)

    # ── MOVE / RENAME ─────────────────────────────────────────────────────

    def on_moved(self, event) -> None:
        """A file was renamed or moved."""
        if event.is_directory:
            return
        if _should_skip(event.src_path) and _should_skip(event.dest_path):
            return  # Both paths excluded
        try:
            log.info("MOVED %s -> %s", event.src_path, event.dest_path)
            sev = classify_severity(event.dest_path, "MOVED")
            # dest path stored in new_hash field for Elasticsearch visibility.
            ship_event("MOVED", event.src_path, new_hash=event.dest_path)
            # Update database: old path gone, new path gets the hash.
            old_h = database.get_hash(event.src_path)
            database.delete(event.src_path)
            if old_h:
                database.upsert(event.dest_path, old_h, time.time())
            # Moves count toward ransomware threshold.
            correlator.record(event.dest_path)
            if dashboard:
                dashboard.add_event("MOVED", f"{event.src_path} → {event.dest_path}", sev)
        except Exception as exc:
            log.error("on_moved failed for %s -> %s: %s",
                       event.src_path, event.dest_path, exc)


# ──────────────────────────────────────────────────────────────────────────────
# Baseline builder
# ──────────────────────────────────────────────────────────────────────────────


def build_baseline(paths: list[str], use_tui: bool = True) -> None:
    """Scan all specified paths, hash every file, store in SQLite.

    This is your 'clean state' snapshot.  Run BEFORE starting the monitor.
    Shows a Rich progress bar when *use_tui* is True.
    """
    database.init_db()

    # First pass: count total files for the progress bar.
    all_hashes: dict[str, str] = {}
    for watch_path in paths:
        watch_path = watch_path.strip()
        if not os.path.exists(watch_path):
            log.warning("Path does not exist, skipping: %s", watch_path)
            continue
        log.info("Baselining: %s", watch_path)
        all_hashes.update(hasher.hash_directory(watch_path))

    # Store with progress bar.
    progress = get_progress() if use_tui else None
    if progress:
        progress.start(total=len(all_hashes), description="Storing baseline")

    total = 0
    for path, h in all_hashes.items():
        database.upsert(path, h, time.time())
        total += 1
        if progress:
            progress.advance()

    if progress:
        progress.finish()

    log.info("Baseline complete. %d files recorded.", total)


# ──────────────────────────────────────────────────────────────────────────────
# Show stored data
# ──────────────────────────────────────────────────────────────────────────────


def show_baseline() -> None:
    """Display the stored baseline data in a formatted table."""
    database.init_db()
    rows = database.get_all()

    if not rows:
        print("\n  No baseline data found. Run --baseline first.\n")
        return

    try:
        from rich.console import Console
        from rich.table import Table
        from datetime import datetime

        console = Console()
        table = Table(
            title=f"\n  Stored Baseline — {len(rows)} files",
            show_lines=False,
            header_style="bold cyan",
            border_style="dim",
        )
        table.add_column("#", style="dim", width=6)
        table.add_column("File Path", style="white", max_width=60)
        table.add_column("SHA-256 Hash", style="green", width=20)
        table.add_column("Last Seen", style="yellow", width=20)

        for i, (path, hash_val, ts) in enumerate(rows, 1):
            try:
                ts_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            except (TypeError, ValueError, OSError):
                ts_str = str(ts)
            table.add_row(str(i), path, hash_val[:16] + "...", ts_str)

        console.print(table)
        console.print(f"\n  [bold]{len(rows)}[/bold] files in baseline\n")

    except ImportError:
        # Fallback: plain text output
        from datetime import datetime
        print(f"\n  Stored Baseline — {len(rows)} files")
        print("  " + "-" * 100)
        print(f"  {'#':<6} {'File Path':<60} {'SHA-256':<18} {'Last Seen':<20}")
        print("  " + "-" * 100)
        for i, (path, hash_val, ts) in enumerate(rows, 1):
            try:
                ts_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            except (TypeError, ValueError, OSError):
                ts_str = str(ts)
            print(f"  {i:<6} {path:<60} {hash_val[:16]}... {ts_str}")
        print(f"\n  {len(rows)} files in baseline\n")


def show_log() -> None:
    """Display the fallback log file (events recorded when ES was unavailable)."""
    if not os.path.exists(config.LOG_FILE):
        print(f"\n  No log file found at {config.LOG_FILE}")
        print("  Events are logged here when Elasticsearch is unavailable.\n")
        return

    try:
        from rich.console import Console
        from rich.table import Table
        import json

        console = Console()
        events = []
        with open(config.LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        if not events:
            console.print("\n  Log file exists but contains no events.\n")
            return

        table = Table(
            title=f"\n  Event Log — {len(events)} events ({config.LOG_FILE})",
            show_lines=False,
            header_style="bold cyan",
            border_style="dim",
        )
        table.add_column("#", style="dim", width=5)
        table.add_column("Timestamp", style="yellow", width=22)
        table.add_column("Event", style="white", width=12)
        table.add_column("Severity", width=10)
        table.add_column("File Path", style="white", max_width=50)

        sev_colors = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "green"}
        for i, evt in enumerate(events, 1):
            sev = evt.get("severity", "?")
            color = sev_colors.get(sev, "white")
            table.add_row(
                str(i),
                evt.get("@timestamp", "?")[:19],
                evt.get("event.type", "?"),
                f"[{color}]{sev}[/{color}]",
                evt.get("file.path", "?"),
            )

        console.print(table)
        console.print(f"\n  [bold]{len(events)}[/bold] events in log\n")

    except ImportError:
        # Fallback: just cat the file
        with open(config.LOG_FILE, "r", encoding="utf-8") as f:
            print(f.read())



def run_scan(paths: list[str]) -> None:
    """Hash all files right now and compare to the baseline.

    Reports ADDED, MODIFIED, and DELETED files.  Does NOT run
    continuously — useful for scheduled integrity checks (e.g. via cron).
    """
    database.init_db()
    log.info("═══ Starting integrity scan ═══")

    # Collect the current on-disk state.
    live_hashes: dict[str, str] = {}
    for p in paths:
        p = p.strip()
        if not os.path.isdir(p):
            log.warning("Skipping non-directory path: %s", p)
            continue
        live_hashes.update(hasher.hash_directory(p))

    # Retrieve the stored baseline.
    baseline_rows = database.get_all()
    baseline: dict[str, str] = {row[0]: row[1] for row in baseline_rows}

    added = modified = deleted = 0

    # Check for ADDED and MODIFIED files.
    for fpath, live_hash in live_hashes.items():
        stored_hash = baseline.get(fpath)
        if stored_hash is None:
            log.info("ADDED %s", fpath)
            ship_event("CREATED", fpath, new_hash=live_hash)
            added += 1
        elif live_hash != stored_hash:
            log.info("MODIFIED %s", fpath)
            ship_event("MODIFIED", fpath, old_hash=stored_hash, new_hash=live_hash)
            modified += 1

    # Check for DELETED files (in baseline but not on disk).
    for fpath in baseline:
        if fpath not in live_hashes:
            log.warning("DELETED %s", fpath)
            ship_event("DELETED", fpath, old_hash=baseline[fpath])
            deleted += 1

    log.info(
        "═══ Scan complete — ADDED: %d | MODIFIED: %d | DELETED: %d ═══",
        added, modified, deleted,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Real-time monitor
# ──────────────────────────────────────────────────────────────────────────────


def _is_excluded_dir(dirname: str, relpath: str = "") -> bool:
    """Check if a directory should be excluded from inotify watches.

    *dirname* is the final component (e.g. ".cache").
    *relpath* is relative to the watch root (e.g. ".config/chromium").
    """
    for wd in config.WATCH_EXCLUDE_DIRS:
        if not wd:
            continue
        if dirname == wd:
            return True
        if relpath and (relpath == wd or relpath.endswith(os.sep + wd)):
            return True
    for pat in config.EXCLUDE_PATTERNS:
        if pat and pat in dirname:
            return True
    return False


def _schedule_watches(
    observer: Observer,
    handler: "FIMHandler",
    root_path: str,
) -> int:
    """Schedule inotify watches on *root_path*, respecting WATCH_EXCLUDE_DIRS.

    Strategy
    --------
    Each ``observer.schedule()`` call creates ONE inotify file-descriptor.
    Linux limits per-user FDs via ``max_user_instances`` (typically 128).

    • Small directory (< 30 immediate children): use ``recursive=True``
      directly — 1 inotify FD.
    • Large directory (e.g. home): enumerate first-level children, skip
      excluded ones, and schedule ``recursive=True`` on each safe child.
      This keeps the FD count low (typically 30-60 instead of 26K+).

    Returns the number of ``schedule()`` calls made.
    """
    try:
        entries = [
            e for e in os.scandir(root_path)
            if e.is_dir(follow_symlinks=False)
        ]
    except PermissionError:
        log.warning("Cannot read directory: %s", root_path)
        return 0

    # Small directory → single recursive watch is fine
    if len(entries) < 30:
        observer.schedule(handler, root_path, recursive=True)
        return 1

    # Large directory → selective first-level children
    count = 0
    skipped = []
    for entry in entries:
        if _is_excluded_dir(entry.name, entry.name):
            skipped.append(entry.name)
            continue
        if not os.access(entry.path, os.R_OK | os.X_OK):
            skipped.append(entry.name)
            continue
        observer.schedule(handler, entry.path, recursive=True)
        count += 1

    # Also watch files directly in root_path (non-recursive)
    observer.schedule(handler, root_path, recursive=False)
    count += 1

    if skipped:
        log.info(
            "  Excluded %d noisy/inaccessible subdirectories: %s%s",
            len(skipped),
            ", ".join(sorted(skipped)[:10]),
            "..." if len(skipped) > 10 else "",
        )
    return count


def run_monitor(paths: list[str], use_tui: bool = True) -> None:
    """Start the watchdog observer with our event handler.

    One observer can watch multiple paths simultaneously.
    Runs until the user presses Ctrl+C or the process receives SIGTERM.
    When *use_tui* is True, displays a Rich live dashboard.
    """
    global dashboard

    database.init_db()
    handler = FIMHandler()
    observer = Observer()

    total_schedules = 0
    for p in paths:
        p = p.strip()
        if os.path.exists(p):
            n = _schedule_watches(observer, handler, p)
            total_schedules += n
            log.info("Watching: %s (%d inotify instances)", p, n)
        else:
            log.warning("Path does not exist, skipping: %s", p)

    log.info("Total inotify instances to create: %d", total_schedules)

    # Start TUI dashboard
    if use_tui:
        print_banner()
        dashboard = get_dashboard()
        dashboard.start()

    # ── Check inotify limits proactively ──────────────────────────────────
    try:
        with open("/proc/sys/fs/inotify/max_user_instances") as f:
            max_instances = int(f.read().strip())
        with open("/proc/sys/fs/inotify/max_user_watches") as f:
            max_watches = int(f.read().strip())
        log.info(
            "System limits: max_user_instances=%d, max_user_watches=%d",
            max_instances, max_watches,
        )
        if total_schedules > max_instances - 10:
            log.warning(
                "Planned instances (%d) may exceed limit (%d). Consider:\n"
                "  sudo sysctl fs.inotify.max_user_instances=512\n"
                "  sudo sysctl -p",
                total_schedules, max_instances,
            )
    except (OSError, ValueError):
        pass

    # ── Start the observer ────────────────────────────────────────────────
    try:
        observer.start()
    except OSError as exc:
        log.critical(
            "Failed to start filesystem watcher: %s\n\n"
            "  FIX OPTIONS:\n"
            "  1) Increase inotify limits:\n"
            "       sudo sysctl fs.inotify.max_user_instances=512\n"
            "       sudo sysctl fs.inotify.max_user_watches=524288\n"
            "       sudo sysctl -p\n"
            "  2) Add noisy directories to WATCH_EXCLUDE_DIRS in config.py\n"
            "  3) Monitor a smaller directory with --paths\n",
            exc,
        )
        if dashboard:
            dashboard.stop()
            dashboard = None
        return

    log.info("FIM Monitor running. Press Ctrl+C to stop.")

    try:
        while not _shutdown_requested:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    if dashboard:
        dashboard.stop()
        dashboard = None

    observer.stop()
    observer.join()
    log.info("Monitor stopped gracefully.")


# ──────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────────────────────────────────────


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SIEM-Integrated File Integrity Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s --baseline                   Build the SHA-256 baseline
  %(prog)s --scan                       One-time integrity scan
  %(prog)s --watch                      Start real-time monitoring
  %(prog)s --watch --paths /home/hiro/Downloads/udaan_files/    Monitor custom directories
  %(prog)s --baseline --scan            Rebuild baseline then scan
""",
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="Build initial hash baseline",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="One-time integrity scan vs baseline",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Start real-time monitoring (default)",
    )
    parser.add_argument(
        "--paths",
        nargs="+",
        default=config.WATCH_PATHS,
        help="Override the directories to monitor/scan.",
    )
    parser.add_argument(
        "--no-tui",
        action="store_true",
        help="Disable Rich TUI (plain log output, suitable for daemons).",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Display the stored baseline data (files, hashes, timestamps).",
    )
    parser.add_argument(
        "--show-log",
        action="store_true",
        help="Display the fallback event log (events captured when ES was down).",
    )

    args = parser.parse_args()
    use_tui = not args.no_tui

    # -- View commands (exit after displaying) --
    if args.show:
        show_baseline()
        sys.exit(0)
    if args.show_log:
        show_log()
        sys.exit(0)

    # Dispatch to the requested mode(s).
    # --baseline and --scan can be combined: build first, then scan.
    if args.baseline:
        build_baseline(args.paths, use_tui=use_tui)
    if args.scan:
        run_scan(args.paths)
    if args.watch or (not args.baseline and not args.scan):
        # Default: start real-time monitoring (matches PDF behaviour).
        run_monitor(args.paths, use_tui=use_tui)

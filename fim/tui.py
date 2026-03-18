#!/usr/bin/env python3
"""
tui.py — Rich Terminal UI for SIEM-Integrated File Integrity Monitor

Provides a professional SOC-style terminal dashboard for the FIM's
``--watch`` and ``--baseline`` modes using the ``rich`` library.

Components
──────────
    FIMDashboard     — Live dashboard for ``--watch`` mode
    BaselineProgress — Progress bar for ``--baseline`` mode
    print_banner()   — Startup banner with system info

Usage::

    from tui import FIMDashboard, BaselineProgress, print_banner

    # Show startup banner
    print_banner()

    # During --watch mode
    dashboard = FIMDashboard()
    dashboard.start()
    dashboard.add_event("CREATED", "/etc/test.conf", "HIGH")
    dashboard.stop()

    # During --baseline mode
    progress = BaselineProgress()
    progress.start(total_files=1500)
    progress.advance()
    progress.finish()

If ``rich`` is not installed, the module provides no-op stubs so the
rest of the application continues to work with plain logging.
"""

from __future__ import annotations

import datetime
import os
import socket
import time
import threading
from collections import deque
from typing import Optional

try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.text import Text
    from rich.progress import (
        Progress,
        BarColumn,
        TextColumn,
        TimeRemainingColumn,
        SpinnerColumn,
        MofNCompleteColumn,
    )
    from rich.columns import Columns
    from rich import box

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from . import config

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

VERSION = "1.0.0"

SEVERITY_STYLES = {
    "CRITICAL": ("bold white on red", "🔴"),
    "HIGH":     ("bold bright_red", "🟠"),
    "MEDIUM":   ("bold yellow", "🟡"),
    "LOW":      ("dim green", "🟢"),
}

EVENT_STYLES = {
    "CREATED":             "bright_green",
    "MODIFIED":            "bright_yellow",
    "DELETED":             "bright_red",
    "MOVED":               "bright_cyan",
    "RANSOMWARE_PATTERN":  "bold white on red",
}

MAX_EVENTS = 30  # Max events shown in the live table


# ──────────────────────────────────────────────────────────────────────────────
# Elasticsearch health check
# ──────────────────────────────────────────────────────────────────────────────

def _check_es_connection() -> str:
    """Return a short status string for Elasticsearch connectivity."""
    try:
        from elasticsearch import Elasticsearch
        es_kwargs = {"hosts": [config.ES_HOST], "request_timeout": 2}
        if config.ES_USER and config.ES_PASS:
            es_kwargs["basic_auth"] = (config.ES_USER, config.ES_PASS)
        es = Elasticsearch(**es_kwargs)
        if es.ping():
            return "[bold green]● CONNECTED[/]"
        return "[bold red]● UNREACHABLE[/]"
    except Exception:
        return "[bold red]● OFFLINE[/]"


# ──────────────────────────────────────────────────────────────────────────────
# Banner
# ──────────────────────────────────────────────────────────────────────────────

def print_banner() -> None:
    """Display a startup banner with version and system info."""
    if not RICH_AVAILABLE:
        return

    console = Console()
    hostname = socket.gethostname()
    es_status = _check_es_connection()
    watch_paths = ", ".join(config.WATCH_PATHS)

    banner_text = Text.assemble(
        ("╔══════════════════════════════════════════════════════════════╗\n", "bold cyan"),
        ("║  ", "bold cyan"),
        ("SIEM-INTEGRATED FILE INTEGRITY MONITOR", "bold bright_white"),
        ("              ║\n", "bold cyan"),
        ("║  ", "bold cyan"),
        (f"v{VERSION}", "dim white"),
        ("                                                      ║\n", "bold cyan"),
        ("╚══════════════════════════════════════════════════════════════╝", "bold cyan"),
    )

    console.print()
    console.print(banner_text)
    console.print()

    info_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    info_table.add_column("Key", style="bold cyan", width=22)
    info_table.add_column("Value")

    info_table.add_row("🖥  Hostname", hostname)
    info_table.add_row("📡 Elasticsearch", es_status)
    info_table.add_row("📂 Watch Paths", watch_paths)
    info_table.add_row("🗄  Database", config.DB_PATH)
    info_table.add_row("⏰ Started", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    console.print(Panel(info_table, title="[bold]System Info[/]", border_style="cyan"))
    console.print()


# ──────────────────────────────────────────────────────────────────────────────
# Live Dashboard (for --watch mode)
# ──────────────────────────────────────────────────────────────────────────────

class FIMDashboard:
    """Real-time Rich dashboard for the ``--watch`` monitoring mode.

    Thread-safe: ``add_event()`` can be called from watchdog's background
    threads while the dashboard renders in the main thread.
    """

    def __init__(self) -> None:
        if not RICH_AVAILABLE:
            return

        self._console = Console()
        self._events: deque[dict] = deque(maxlen=MAX_EVENTS)
        self._lock = threading.Lock()
        self._live: Optional[Live] = None
        self._start_time = time.time()
        self._total_events = 0
        self._severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        self._last_alert_time: Optional[str] = None
        self._running = False

    def start(self) -> None:
        """Begin the live-updating dashboard display."""
        if not RICH_AVAILABLE:
            return
        self._running = True
        self._live = Live(
            self._build_layout(),
            console=self._console,
            refresh_per_second=2,
            screen=False,
        )
        self._live.start()

    def stop(self) -> None:
        """Stop the live dashboard."""
        if not RICH_AVAILABLE or not self._live:
            return
        self._running = False
        self._live.stop()

    def add_event(
        self,
        event_type: str,
        path: str,
        severity: str = "LOW",
        old_hash: str = "",
        new_hash: str = "",
    ) -> None:
        """Record a new event and refresh the dashboard.

        Thread-safe — called from watchdog background threads.
        """
        if not RICH_AVAILABLE:
            return

        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        event = {
            "time": timestamp,
            "type": event_type,
            "severity": severity,
            "path": path,
            "old_hash": old_hash[:12] if old_hash else "—",
            "new_hash": new_hash[:12] if new_hash else "—",
        }

        with self._lock:
            self._events.appendleft(event)
            self._total_events += 1
            if severity in self._severity_counts:
                self._severity_counts[severity] += 1
            if severity == "CRITICAL":
                self._last_alert_time = timestamp

        if self._live and self._running:
            self._live.update(self._build_layout())

    def _build_layout(self) -> Table:
        """Build the full dashboard layout."""
        # -- Stats bar --
        uptime = int(time.time() - self._start_time)
        hours, remainder = divmod(uptime, 3600)
        minutes, seconds = divmod(remainder, 60)
        uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        with self._lock:
            total = self._total_events
            crit = self._severity_counts["CRITICAL"]
            high = self._severity_counts["HIGH"]
            med = self._severity_counts["MEDIUM"]
            low = self._severity_counts["LOW"]
            last_alert = self._last_alert_time or "None"

        stats_text = Text.assemble(
            ("⏱ Uptime: ", "bold"),
            (uptime_str, "cyan"),
            ("  │  ", "dim"),
            ("📊 Events: ", "bold"),
            (str(total), "bright_white"),
            ("  │  ", "dim"),
            ("🔴 ", ""),
            (str(crit), "bold red"),
            ("  ", ""),
            ("🟠 ", ""),
            (str(high), "bold bright_red"),
            ("  ", ""),
            ("🟡 ", ""),
            (str(med), "bold yellow"),
            ("  ", ""),
            ("🟢 ", ""),
            (str(low), "green"),
            ("  │  ", "dim"),
            ("🚨 Last Alert: ", "bold"),
            (last_alert, "bright_red" if last_alert != "None" else "dim"),
        )

        stats_panel = Panel(
            stats_text,
            title="[bold cyan]FIM Monitor — LIVE[/]",
            border_style="cyan",
            padding=(0, 1),
        )

        # -- Event table --
        table = Table(
            box=box.ROUNDED,
            border_style="dim",
            header_style="bold bright_cyan",
            title="[bold]Recent Events[/]",
            title_style="bold white",
            expand=True,
            padding=(0, 1),
        )
        table.add_column("Time", style="dim", width=10, no_wrap=True)
        table.add_column("Severity", width=12, justify="center")
        table.add_column("Event", width=12)
        table.add_column("File Path", ratio=3)
        table.add_column("Old Hash", width=14, style="dim")
        table.add_column("New Hash", width=14)

        with self._lock:
            for ev in self._events:
                sev = ev["severity"]
                sev_style, sev_icon = SEVERITY_STYLES.get(sev, ("dim", "⚪"))
                ev_style = EVENT_STYLES.get(ev["type"], "white")

                table.add_row(
                    ev["time"],
                    Text(f"{sev_icon} {sev}", style=sev_style),
                    Text(ev["type"], style=ev_style),
                    Text(
                        ev["path"] if len(ev["path"]) <= 60
                        else "…" + ev["path"][-59:],
                        style="white",
                    ),
                    ev["old_hash"],
                    ev["new_hash"],
                )

        if not self._events:
            table.add_row(
                "—", "—", "—",
                Text("Waiting for file system events…", style="dim italic"),
                "—", "—",
            )

        # -- Combine into outer table (vertical stack) --
        outer = Table.grid(expand=True)
        outer.add_row(stats_panel)
        outer.add_row(table)

        return outer


# ──────────────────────────────────────────────────────────────────────────────
# Progress bar (for --baseline mode)
# ──────────────────────────────────────────────────────────────────────────────

class BaselineProgress:
    """Rich progress bar for baseline scanning with a professional look."""

    def __init__(self) -> None:
        if not RICH_AVAILABLE:
            self._progress = None
            return

        self._console = Console()
        self._progress = Progress(
            SpinnerColumn("dots", style="cyan"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=40, style="cyan", complete_style="bold green"),
            MofNCompleteColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=self._console,
        )
        self._task_id = None

    def start(self, total: int, description: str = "Building baseline") -> None:
        """Start the progress bar with the given total file count."""
        if not RICH_AVAILABLE or not self._progress:
            return
        self._progress.start()
        self._task_id = self._progress.add_task(description, total=total)

    def advance(self, count: int = 1) -> None:
        """Advance the progress bar by *count* files."""
        if not RICH_AVAILABLE or self._task_id is None:
            return
        self._progress.advance(self._task_id, count)

    def finish(self) -> None:
        """Complete and stop the progress bar."""
        if not RICH_AVAILABLE or not self._progress:
            return
        self._progress.stop()


# ──────────────────────────────────────────────────────────────────────────────
# No-op stubs (when Rich is not installed)
# ──────────────────────────────────────────────────────────────────────────────

class _NoOpDashboard:
    """Placeholder when Rich is unavailable."""
    def start(self) -> None: pass
    def stop(self) -> None: pass
    def add_event(self, *a, **kw) -> None: pass


class _NoOpProgress:
    """Placeholder when Rich is unavailable."""
    def start(self, *a, **kw) -> None: pass
    def advance(self, *a, **kw) -> None: pass
    def finish(self) -> None: pass


def get_dashboard() -> FIMDashboard:
    """Factory: return a real dashboard or a no-op stub."""
    if RICH_AVAILABLE:
        return FIMDashboard()
    return _NoOpDashboard()  # type: ignore[return-value]


def get_progress() -> BaselineProgress:
    """Factory: return a real progress bar or a no-op stub."""
    if RICH_AVAILABLE:
        return BaselineProgress()
    return _NoOpProgress()  # type: ignore[return-value]

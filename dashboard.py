#!/usr/bin/env python3
"""
dashboard.py — Web-Based GUI Dashboard for SIEM-Integrated File Integrity Monitor

Launch:  python3 dashboard.py
Open:    http://localhost:5000

Provides a visual interface for all FIM operations:
  • Build Baseline  — one-click SHA-256 snapshot
  • Run Scan        — one-click integrity audit
  • Start/Stop Monitor — toggle real-time watching
  • Live Event Feed — events appear as they happen
  • Event History   — searchable table of all events
  • Settings        — view current configuration

No extra dependencies — uses Python's built-in http.server.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Import FIM package modules
from fim import config
from fim import database
from fim import hasher
from fim.forwarder import ship_event
from fim.correlator import RansomwareCorrelator
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger("dashboard")

# ──────────────────────────────────────────────────────────────────────────────
# Global state
# ──────────────────────────────────────────────────────────────────────────────

_observer: Observer | None = None
_monitor_thread: threading.Thread | None = None
_monitor_running = False
_correlator = RansomwareCorrelator()
_event_log: list[dict] = []          # In-memory event log for the dashboard
_event_queue: queue.Queue = queue.Queue()  # For SSE streaming
_sse_clients: list[queue.Queue] = []


def _broadcast_event(event_data: dict):
    """Push an event to all SSE clients and the in-memory log."""
    _event_log.append(event_data)
    # Keep only latest 500 events in memory
    if len(_event_log) > 500:
        _event_log.pop(0)
    for q in _sse_clients[:]:
        try:
            q.put_nowait(event_data)
        except queue.Full:
            pass


# ──────────────────────────────────────────────────────────────────────────────
# Watchdog handler for GUI
# ──────────────────────────────────────────────────────────────────────────────

def _should_skip(path: str) -> bool:
    for pattern in config.EXCLUDE_PATTERNS:
        if pattern and pattern in path:
            return True
    for ext in config.EXCLUDE_EXTENSIONS:
        if ext and path.endswith(ext):
            return True
    return False


class _GUIHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory or _should_skip(event.src_path):
            return
        path = event.src_path
        new_h = hasher.sha256(path)
        if not new_h:
            return
        doc = ship_event("CREATED", path, new_hash=new_h)
        database.upsert(path, new_h, time.time())
        _correlator.record(path)
        _broadcast_event({
            "time": time.strftime("%H:%M:%S"),
            "type": "CREATED",
            "path": path,
            "severity": doc.get("severity", "LOW") if isinstance(doc, dict) else "LOW",
            "hash": (new_h or "")[:16],
        })

    def on_modified(self, event):
        if event.is_directory or _should_skip(event.src_path):
            return
        path = event.src_path
        old_h = database.get_hash(path)
        new_h = hasher.sha256(path)
        if not new_h or old_h == new_h:
            return
        doc = ship_event("MODIFIED", path, old_hash=old_h, new_hash=new_h)
        database.upsert(path, new_h, time.time())
        _correlator.record(path)
        _broadcast_event({
            "time": time.strftime("%H:%M:%S"),
            "type": "MODIFIED",
            "path": path,
            "severity": doc.get("severity", "LOW") if isinstance(doc, dict) else "LOW",
            "hash": (new_h or "")[:16],
        })

    def on_deleted(self, event):
        if event.is_directory or _should_skip(event.src_path):
            return
        path = event.src_path
        old_h = database.get_hash(path)
        doc = ship_event("DELETED", path, old_hash=old_h)
        database.delete(path)
        _broadcast_event({
            "time": time.strftime("%H:%M:%S"),
            "type": "DELETED",
            "path": path,
            "severity": doc.get("severity", "HIGH") if isinstance(doc, dict) else "HIGH",
            "hash": "—",
        })

    def on_moved(self, event):
        if event.is_directory:
            return
        doc = ship_event("MOVED", event.src_path, new_hash=event.dest_path)
        old_h = database.get_hash(event.src_path)
        database.delete(event.src_path)
        if old_h:
            database.upsert(event.dest_path, old_h, time.time())
        _correlator.record(event.dest_path)
        _broadcast_event({
            "time": time.strftime("%H:%M:%S"),
            "type": "MOVED",
            "path": f"{event.src_path} → {event.dest_path}",
            "severity": doc.get("severity", "MEDIUM") if isinstance(doc, dict) else "MEDIUM",
            "hash": "—",
        })


# ──────────────────────────────────────────────────────────────────────────────
# API logic
# ──────────────────────────────────────────────────────────────────────────────

def _do_baseline(paths: list[str]) -> dict:
    database.init_db()
    total = 0
    for p in paths:
        p = p.strip()
        if not os.path.isdir(p):
            continue
        hashes = hasher.hash_directory(p)
        for fpath, h in hashes.items():
            database.upsert(fpath, h, time.time())
            total += 1
    return {"status": "ok", "files": total, "paths": paths}


def _do_scan(paths: list[str]) -> dict:
    database.init_db()
    live: dict[str, str] = {}
    for p in paths:
        p = p.strip()
        if os.path.isdir(p):
            live.update(hasher.hash_directory(p))

    rows = database.get_all()
    baseline = {r[0]: r[1] for r in rows}
    added = modified = deleted = 0
    results = []

    for fpath, lhash in live.items():
        stored = baseline.get(fpath)
        if stored is None:
            added += 1
            results.append({"type": "ADDED", "path": fpath, "severity": "MEDIUM"})
            ship_event("CREATED", fpath, new_hash=lhash)
        elif lhash != stored:
            modified += 1
            results.append({"type": "MODIFIED", "path": fpath, "severity": "HIGH"})
            ship_event("MODIFIED", fpath, old_hash=stored, new_hash=lhash)

    for fpath in baseline:
        if fpath not in live:
            deleted += 1
            results.append({"type": "DELETED", "path": fpath, "severity": "HIGH"})
            ship_event("DELETED", fpath, old_hash=baseline[fpath])

    return {"status": "ok", "added": added, "modified": modified, "deleted": deleted, "results": results}


def _is_excluded_dir(dirname: str, relpath: str = "") -> bool:
    """Check if a directory should be excluded from inotify watches."""
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


def _start_monitor(paths: list[str]) -> dict:
    global _observer, _monitor_running
    if _monitor_running:
        return {"status": "already_running"}

    database.init_db()
    handler = _GUIHandler()
    _observer = Observer()
    watched = []
    total_schedules = 0

    for p in paths:
        p = p.strip()
        if not os.path.exists(p):
            continue
        try:
            entries = [
                e for e in os.scandir(p)
                if e.is_dir(follow_symlinks=False)
            ]
        except PermissionError:
            continue

        if len(entries) < 30:
            _observer.schedule(handler, p, recursive=True)
            total_schedules += 1
        else:
            # Large dir: schedule on filtered first-level children
            for entry in entries:
                if _is_excluded_dir(entry.name, entry.name):
                    continue
                if not os.access(entry.path, os.R_OK | os.X_OK):
                    continue
                _observer.schedule(handler, entry.path, recursive=True)
                total_schedules += 1
            # Watch files in root (non-recursive)
            _observer.schedule(handler, p, recursive=False)
            total_schedules += 1
        watched.append(p)

    try:
        _observer.start()
    except OSError as exc:
        logger.error("Failed to start watcher: %s", exc)
        _observer = None
        return {
            "status": "error",
            "error": (
                f"Watcher failed: {exc}. "
                "Run: sudo sysctl fs.inotify.max_user_instances=512 && "
                "sudo sysctl fs.inotify.max_user_watches=524288"
            ),
        }

    _monitor_running = True
    _broadcast_event({
        "time": time.strftime("%H:%M:%S"),
        "type": "SYSTEM",
        "path": f"Monitor started — watching {', '.join(watched)} ({total_schedules} watchers)",
        "severity": "INFO",
        "hash": "—",
    })
    return {"status": "ok", "watching": watched}


def _stop_monitor() -> dict:
    global _observer, _monitor_running
    if not _monitor_running:
        return {"status": "not_running"}
    if _observer:
        _observer.stop()
        _observer.join(timeout=5)
        _observer = None
    _monitor_running = False
    _broadcast_event({
        "time": time.strftime("%H:%M:%S"),
        "type": "SYSTEM",
        "path": "Monitor stopped",
        "severity": "INFO",
        "hash": "—",
    })
    return {"status": "ok"}


# ──────────────────────────────────────────────────────────────────────────────
# HTML Dashboard
# ──────────────────────────────────────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FIM Dashboard — File Integrity Monitor</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

  :root {
    --bg-primary: #0a0e17;
    --bg-secondary: #111827;
    --bg-card: #1a2232;
    --bg-card-hover: #1f2937;
    --border: #2d3748;
    --text-primary: #e2e8f0;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --accent-blue: #3b82f6;
    --accent-cyan: #06b6d4;
    --accent-green: #10b981;
    --accent-red: #ef4444;
    --accent-orange: #f59e0b;
    --accent-purple: #8b5cf6;
    --glow-blue: rgba(59, 130, 246, 0.15);
    --glow-green: rgba(16, 185, 129, 0.15);
    --glow-red: rgba(239, 68, 68, 0.15);
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    font-family: 'Inter', -apple-system, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* ── Animated background ── */
  body::before {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background:
      radial-gradient(ellipse at 20% 50%, rgba(59, 130, 246, 0.08) 0%, transparent 50%),
      radial-gradient(ellipse at 80% 20%, rgba(139, 92, 246, 0.06) 0%, transparent 50%),
      radial-gradient(ellipse at 50% 80%, rgba(6, 182, 212, 0.05) 0%, transparent 50%);
    z-index: 0;
    pointer-events: none;
  }

  .container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 24px;
    position: relative;
    z-index: 1;
  }

  /* ── Header ── */
  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 20px 28px;
    background: linear-gradient(135deg, var(--bg-card), var(--bg-secondary));
    border: 1px solid var(--border);
    border-radius: 16px;
    margin-bottom: 24px;
    backdrop-filter: blur(12px);
  }
  .header-left { display: flex; align-items: center; gap: 16px; }
  .header-icon {
    width: 48px; height: 48px;
    background: linear-gradient(135deg, var(--accent-blue), var(--accent-cyan));
    border-radius: 12px;
    display: flex; align-items: center; justify-content: center;
    font-size: 24px;
    box-shadow: 0 4px 20px rgba(59, 130, 246, 0.3);
  }
  .header h1 {
    font-size: 22px;
    font-weight: 700;
    background: linear-gradient(135deg, #fff, var(--accent-cyan));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }
  .header p { color: var(--text-muted); font-size: 13px; margin-top: 2px; }
  .status-badge {
    padding: 6px 16px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    display: flex; align-items: center; gap: 8px;
  }
  .status-badge.active { background: var(--glow-green); color: var(--accent-green); border: 1px solid rgba(16,185,129,0.3); }
  .status-badge.inactive { background: rgba(100,116,139,0.15); color: var(--text-muted); border: 1px solid var(--border); }
  .status-dot {
    width: 8px; height: 8px; border-radius: 50%;
  }
  .status-badge.active .status-dot { background: var(--accent-green); animation: pulse 2s infinite; }
  .status-badge.inactive .status-dot { background: var(--text-muted); }

  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

  /* ── Stats grid ── */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 24px;
  }
  .stat-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 20px 24px;
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
  }
  .stat-card:hover { transform: translateY(-2px); border-color: var(--accent-blue); }
  .stat-card::after {
    content: '';
    position: absolute;
    top: 0; right: 0;
    width: 100px; height: 100px;
    border-radius: 50%;
    filter: blur(40px);
    opacity: 0.15;
  }
  .stat-card:nth-child(1)::after { background: var(--accent-blue); }
  .stat-card:nth-child(2)::after { background: var(--accent-green); }
  .stat-card:nth-child(3)::after { background: var(--accent-orange); }
  .stat-card:nth-child(4)::after { background: var(--accent-red); }
  .stat-label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; font-weight: 600; }
  .stat-value { font-size: 32px; font-weight: 700; margin: 8px 0 4px; font-family: 'JetBrains Mono', monospace; }
  .stat-sub { font-size: 12px; color: var(--text-secondary); }

  /* ── Controls ── */
  .controls {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 16px;
    margin-bottom: 24px;
  }
  .control-group {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 24px;
  }
  .control-group h3 {
    font-size: 14px;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 16px;
    display: flex; align-items: center; gap: 8px;
  }

  .path-input-group {
    display: flex; gap: 8px; margin-bottom: 12px;
  }
  .path-input {
    flex: 1;
    padding: 10px 16px;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 10px;
    color: var(--text-primary);
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    outline: none;
    transition: border-color 0.2s;
  }
  .path-input:focus { border-color: var(--accent-blue); }

  .btn {
    padding: 10px 24px;
    border: none;
    border-radius: 10px;
    font-family: 'Inter', sans-serif;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s ease;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    white-space: nowrap;
  }
  .btn:active { transform: scale(0.97); }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }

  .btn-blue { background: linear-gradient(135deg, var(--accent-blue), #2563eb); color: white; }
  .btn-blue:hover:not(:disabled) { box-shadow: 0 4px 20px rgba(59, 130, 246, 0.4); }
  .btn-green { background: linear-gradient(135deg, var(--accent-green), #059669); color: white; }
  .btn-green:hover:not(:disabled) { box-shadow: 0 4px 20px rgba(16, 185, 129, 0.4); }
  .btn-orange { background: linear-gradient(135deg, var(--accent-orange), #d97706); color: white; }
  .btn-orange:hover:not(:disabled) { box-shadow: 0 4px 20px rgba(245, 158, 11, 0.4); }
  .btn-red { background: linear-gradient(135deg, var(--accent-red), #dc2626); color: white; }
  .btn-red:hover:not(:disabled) { box-shadow: 0 4px 20px rgba(239, 68, 68, 0.4); }

  .btn-group { display: flex; gap: 10px; flex-wrap: wrap; }

  /* ── Event feed ── */
  .event-section {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 14px;
    overflow: hidden;
  }
  .event-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 18px 24px;
    border-bottom: 1px solid var(--border);
  }
  .event-header h3 {
    font-size: 14px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 1px;
    color: var(--text-secondary);
    display: flex; align-items: center; gap: 8px;
  }
  .event-count {
    padding: 4px 12px; border-radius: 12px;
    background: var(--glow-blue); color: var(--accent-blue);
    font-size: 12px; font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
  }
  .event-list {
    max-height: 500px;
    overflow-y: auto;
    scroll-behavior: smooth;
  }
  .event-list::-webkit-scrollbar { width: 6px; }
  .event-list::-webkit-scrollbar-track { background: transparent; }
  .event-list::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

  .event-item {
    display: grid;
    grid-template-columns: 70px 100px 1fr 80px;
    gap: 12px;
    align-items: center;
    padding: 12px 24px;
    border-bottom: 1px solid rgba(45, 55, 72, 0.5);
    font-size: 13px;
    transition: background 0.2s;
    animation: fadeIn 0.3s ease;
  }
  .event-item:hover { background: var(--bg-card-hover); }

  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(-8px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .event-time { font-family: 'JetBrains Mono', monospace; color: var(--text-muted); font-size: 12px; }
  .event-type {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 600;
    padding: 3px 10px;
    border-radius: 6px;
    text-align: center;
  }
  .event-type.CREATED { background: rgba(16,185,129,0.15); color: var(--accent-green); }
  .event-type.MODIFIED { background: rgba(245,158,11,0.15); color: var(--accent-orange); }
  .event-type.DELETED { background: rgba(239,68,68,0.15); color: var(--accent-red); }
  .event-type.MOVED { background: rgba(139,92,246,0.15); color: var(--accent-purple); }
  .event-type.SYSTEM { background: rgba(59,130,246,0.15); color: var(--accent-blue); }
  .event-type.RANSOMWARE_PATTERN { background: rgba(239,68,68,0.25); color: #ff6b6b; }

  .event-path {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .event-severity {
    font-size: 11px; font-weight: 700;
    text-align: center; padding: 3px 8px; border-radius: 6px;
  }
  .event-severity.CRITICAL { background: rgba(239,68,68,0.2); color: #ff6b6b; }
  .event-severity.HIGH { background: rgba(245,158,11,0.2); color: var(--accent-orange); }
  .event-severity.MEDIUM { background: rgba(59,130,246,0.15); color: var(--accent-blue); }
  .event-severity.LOW { background: rgba(100,116,139,0.15); color: var(--text-muted); }
  .event-severity.INFO { background: rgba(6,182,212,0.15); color: var(--accent-cyan); }

  .empty-state {
    padding: 60px 24px;
    text-align: center;
    color: var(--text-muted);
  }
  .empty-state .icon { font-size: 48px; margin-bottom: 16px; }
  .empty-state p { font-size: 14px; }

  /* ── Toast ── */
  .toast-container { position: fixed; top: 24px; right: 24px; z-index: 1000; display: flex; flex-direction: column; gap: 8px; }
  .toast {
    padding: 14px 20px;
    border-radius: 12px;
    font-size: 13px; font-weight: 500;
    animation: slideIn 0.3s ease;
    max-width: 400px;
    backdrop-filter: blur(12px);
  }
  .toast.success { background: rgba(16,185,129,0.9); color: white; }
  .toast.error { background: rgba(239,68,68,0.9); color: white; }
  .toast.info { background: rgba(59,130,246,0.9); color: white; }
  @keyframes slideIn { from { opacity: 0; transform: translateX(40px); } to { opacity: 1; transform: translateX(0); } }

  /* ── Loading spinner ── */
  .spinner {
    width: 16px; height: 16px;
    border: 2px solid rgba(255,255,255,0.3);
    border-top-color: white;
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
    display: none;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── Responsive ── */
  @media (max-width: 900px) {
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
    .controls { grid-template-columns: 1fr; }
    .event-item { grid-template-columns: 70px 80px 1fr; }
    .event-item .event-severity { display: none; }
  }
</style>
</head>
<body>

<div class="container">

  <!-- Header -->
  <div class="header">
    <div class="header-left">
      <div class="header-icon">🛡️</div>
      <div>
        <h1>File Integrity Monitor</h1>
        <p>SIEM-Integrated Security Dashboard</p>
      </div>
    </div>
    <div id="statusBadge" class="status-badge inactive">
      <span class="status-dot"></span>
      <span id="statusText">Monitor Idle</span>
    </div>
  </div>

  <!-- Stats -->
  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-label">Baselined Files</div>
      <div class="stat-value" id="statFiles">—</div>
      <div class="stat-sub">SHA-256 hashes stored</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Events Today</div>
      <div class="stat-value" id="statEvents">0</div>
      <div class="stat-sub">File changes detected</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Alerts</div>
      <div class="stat-value" id="statAlerts">0</div>
      <div class="stat-sub">CRITICAL + HIGH severity</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Monitoring</div>
      <div class="stat-value" id="statPaths">—</div>
      <div class="stat-sub">Active watch paths</div>
    </div>
  </div>

  <!-- Controls -->
  <div class="controls">
    <div class="control-group">
      <h3>📁 Paths to Monitor</h3>
      <div class="path-input-group">
        <input type="text" class="path-input" id="pathInput"
               placeholder="/etc, /home, /var/www, /tmp/mytest"
               value="/tmp/mytest">
      </div>
      <p style="font-size: 11px; color: var(--text-muted); margin-bottom: 12px;">
        Comma-separated directories. Create the directory first if it doesn't exist.
      </p>
    </div>
    <div class="control-group">
      <h3>⚡ Actions</h3>
      <div class="btn-group">
        <button class="btn btn-blue" id="btnBaseline" onclick="doBaseline()">
          <span>🏗️</span> Build Baseline
          <div class="spinner" id="spinBaseline"></div>
        </button>
        <button class="btn btn-orange" id="btnScan" onclick="doScan()">
          <span>🔍</span> Run Scan
          <div class="spinner" id="spinScan"></div>
        </button>
        <button class="btn btn-green" id="btnWatch" onclick="toggleWatch()">
          <span>▶️</span> <span id="watchLabel">Start Monitor</span>
          <div class="spinner" id="spinWatch"></div>
        </button>
        <button class="btn btn-red" id="btnClear" onclick="clearEvents()">
          <span>🗑️</span> Clear Log
        </button>
      </div>
    </div>
  </div>

  <!-- Event feed -->
  <div class="event-section">
    <div class="event-header">
      <h3>📡 Live Event Feed</h3>
      <span class="event-count" id="eventCount">0 events</span>
    </div>
    <div class="event-list" id="eventList">
      <div class="empty-state" id="emptyState">
        <div class="icon">📡</div>
        <p>No events yet. Build a baseline, then start monitoring.</p>
        <p style="margin-top: 8px; font-size: 12px;">Modify files in your watch directory to see live alerts.</p>
      </div>
    </div>
  </div>

</div>

<div class="toast-container" id="toasts"></div>

<script>
  const API = '';
  let watching = false;
  let eventSource = null;
  let totalEvents = 0;
  let totalAlerts = 0;

  function getPaths() {
    return document.getElementById('pathInput').value.split(',').map(p => p.trim()).filter(Boolean);
  }

  function toast(msg, type = 'info') {
    const c = document.getElementById('toasts');
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.textContent = msg;
    c.appendChild(t);
    setTimeout(() => t.remove(), 4000);
  }

  function addEvent(ev) {
    const list = document.getElementById('eventList');
    const empty = document.getElementById('emptyState');
    if (empty) empty.remove();

    // Build event row using textContent (NOT innerHTML) to prevent XSS.
    // File paths can contain attacker-controlled characters like <script>.
    const item = document.createElement('div');
    item.className = 'event-item';

    const timeEl = document.createElement('span');
    timeEl.className = 'event-time';
    timeEl.textContent = ev.time || '--:--:--';

    const typeEl = document.createElement('span');
    typeEl.className = 'event-type ' + (ev.type || '');
    typeEl.textContent = ev.type || '';

    const pathEl = document.createElement('span');
    pathEl.className = 'event-path';
    pathEl.title = ev.path || '';
    pathEl.textContent = ev.path || '';

    const sevEl = document.createElement('span');
    sevEl.className = 'event-severity ' + (ev.severity || '');
    sevEl.textContent = ev.severity || '';

    item.appendChild(timeEl);
    item.appendChild(typeEl);
    item.appendChild(pathEl);
    item.appendChild(sevEl);

    list.insertBefore(item, list.firstChild);
    totalEvents++;
    if (['CRITICAL', 'HIGH'].includes(ev.severity)) totalAlerts++;
    document.getElementById('statEvents').textContent = totalEvents;
    document.getElementById('statAlerts').textContent = totalAlerts;
    document.getElementById('eventCount').textContent = `${totalEvents} events`;
  }

  async function doBaseline() {
    const btn = document.getElementById('btnBaseline');
    const spin = document.getElementById('spinBaseline');
    btn.disabled = true; spin.style.display = 'block';
    try {
      const res = await fetch(API + '/api/baseline', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({paths: getPaths()})
      });
      const data = await res.json();
      if (data.status === 'ok') {
        toast(`Baseline built: ${data.files} files hashed`, 'success');
        document.getElementById('statFiles').textContent = data.files;
        addEvent({time: new Date().toTimeString().slice(0,8), type: 'SYSTEM', path: `Baseline: ${data.files} files hashed`, severity: 'INFO'});
      } else {
        toast('Baseline failed: ' + (data.error || 'unknown'), 'error');
      }
    } catch (e) { toast('Request failed: ' + e.message, 'error'); }
    btn.disabled = false; spin.style.display = 'none';
  }

  async function doScan() {
    const btn = document.getElementById('btnScan');
    const spin = document.getElementById('spinScan');
    btn.disabled = true; spin.style.display = 'block';
    try {
      const res = await fetch(API + '/api/scan', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({paths: getPaths()})
      });
      const data = await res.json();
      if (data.status === 'ok') {
        const total = data.added + data.modified + data.deleted;
        if (total === 0) {
          toast('Scan complete — no changes detected ✅', 'success');
          addEvent({time: new Date().toTimeString().slice(0,8), type: 'SYSTEM', path: 'Scan: All files intact', severity: 'INFO'});
        } else {
          toast(`Scan: ${data.added} added, ${data.modified} modified, ${data.deleted} deleted`, 'error');
          (data.results || []).forEach(r => {
            addEvent({time: new Date().toTimeString().slice(0,8), type: r.type, path: r.path, severity: r.severity});
          });
        }
      }
    } catch(e) { toast('Scan failed: ' + e.message, 'error'); }
    btn.disabled = false; spin.style.display = 'none';
  }

  async function toggleWatch() {
    const spin = document.getElementById('spinWatch');
    spin.style.display = 'block';
    if (!watching) {
      try {
        const res = await fetch(API + '/api/watch/start', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({paths: getPaths()})
        });
        const data = await res.json();
        if (data.status === 'ok') {
          watching = true;
          document.getElementById('watchLabel').textContent = 'Stop Monitor';
          document.getElementById('btnWatch').className = 'btn btn-red';
          document.getElementById('statusBadge').className = 'status-badge active';
          document.getElementById('statusText').textContent = 'Monitoring Active';
          document.getElementById('statPaths').textContent = data.watching.length;
          toast(`Monitoring ${data.watching.length} paths`, 'success');
          startSSE();
        } else {
          toast(data.status, 'info');
        }
      } catch(e) { toast('Failed: ' + e.message, 'error'); }
    } else {
      try {
        await fetch(API + '/api/watch/stop', { method: 'POST' });
        watching = false;
        document.getElementById('watchLabel').textContent = 'Start Monitor';
        document.getElementById('btnWatch').className = 'btn btn-green';
        document.getElementById('statusBadge').className = 'status-badge inactive';
        document.getElementById('statusText').textContent = 'Monitor Idle';
        document.getElementById('statPaths').textContent = '—';
        toast('Monitor stopped', 'info');
        if (eventSource) { eventSource.close(); eventSource = null; }
      } catch(e) { toast('Failed: ' + e.message, 'error'); }
    }
    spin.style.display = 'none';
  }

  function startSSE() {
    if (eventSource) eventSource.close();
    eventSource = new EventSource(API + '/api/events/stream');
    eventSource.onmessage = function(e) {
      try {
        const ev = JSON.parse(e.data);
        addEvent(ev);
      } catch(err) {}
    };
    eventSource.onerror = function() {
      // Reconnect silently
      setTimeout(() => { if (watching) startSSE(); }, 3000);
    };
  }

  function clearEvents() {
    const list = document.getElementById('eventList');
    list.innerHTML = `<div class="empty-state" id="emptyState">
      <div class="icon">📡</div>
      <p>Event log cleared.</p>
    </div>`;
    totalEvents = 0; totalAlerts = 0;
    document.getElementById('statEvents').textContent = '0';
    document.getElementById('statAlerts').textContent = '0';
    document.getElementById('eventCount').textContent = '0 events';
  }

  // Load initial stats
  fetch(API + '/api/stats').then(r => r.json()).then(data => {
    document.getElementById('statFiles').textContent = data.files || '—';
  }).catch(() => {});
</script>
</body>
</html>"""


# ──────────────────────────────────────────────────────────────────────────────
# HTTP Request Handler
# ──────────────────────────────────────────────────────────────────────────────

class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP handler for the FIM dashboard."""

    def log_message(self, format, *args):
        logger.debug(format, *args)

    def _json_response(self, data: dict, status: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            body = DASHBOARD_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/api/stats":
            try:
                database.init_db()
                rows = database.get_all()
                self._json_response({"files": len(rows), "monitoring": _monitor_running})
            except Exception as exc:
                self._json_response({"files": 0, "error": str(exc)})

        elif path == "/api/events":
            self._json_response({"events": _event_log[-100:]})

        elif path == "/api/events/stream":
            # Server-Sent Events
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            client_queue: queue.Queue = queue.Queue(maxsize=100)
            _sse_clients.append(client_queue)

            try:
                while True:
                    try:
                        event = client_queue.get(timeout=15)
                        data = json.dumps(event)
                        self.wfile.write(f"data: {data}\n\n".encode("utf-8"))
                        self.wfile.flush()
                    except queue.Empty:
                        # Send heartbeat to keep connection alive
                        self.wfile.write(b": heartbeat\n\n")
                        self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                if client_queue in _sse_clients:
                    _sse_clients.remove(client_queue)

        else:
            self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        body = self._read_body()

        if path == "/api/baseline":
            paths = body.get("paths", config.WATCH_PATHS)
            try:
                result = _do_baseline(paths)
                self._json_response(result)
            except Exception as exc:
                self._json_response({"status": "error", "error": str(exc)}, 500)

        elif path == "/api/scan":
            paths = body.get("paths", config.WATCH_PATHS)
            try:
                result = _do_scan(paths)
                self._json_response(result)
            except Exception as exc:
                self._json_response({"status": "error", "error": str(exc)}, 500)

        elif path == "/api/watch/start":
            paths = body.get("paths", config.WATCH_PATHS)
            try:
                result = _start_monitor(paths)
                self._json_response(result)
            except Exception as exc:
                self._json_response({"status": "error", "error": str(exc)}, 500)

        elif path == "/api/watch/stop":
            try:
                result = _stop_monitor()
                self._json_response(result)
            except Exception as exc:
                self._json_response({"status": "error", "error": str(exc)}, 500)

        else:
            self.send_error(404)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    port = int(os.getenv("DASHBOARD_PORT", "5000"))

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    database.init_db()

    server = HTTPServer(("0.0.0.0", port), DashboardHandler)
    server.daemon_threads = True

    url = f"http://localhost:{port}"
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🛡️  FIM Dashboard — File Integrity Monitor                 ║
║                                                              ║
║   Open in browser:  {url:<38s}  ║
║                                                              ║
║   Press Ctrl+C to stop                                       ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down dashboard...")
        _stop_monitor()
        server.shutdown()


if __name__ == "__main__":
    main()

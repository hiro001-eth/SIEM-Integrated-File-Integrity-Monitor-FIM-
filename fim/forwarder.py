"""
forwarder.py — Elasticsearch SIEM Bridge for SIEM-Integrated File Integrity Monitor

This is the file that transforms this project from a local script into a real
enterprise security tool.  It ships structured JSON events to Elasticsearch
with full metadata, enabling KQL searches, Kibana dashboards, and detection
rule correlation.

Responsible for:
  1. Classifying event severity    (CRITICAL / HIGH / MEDIUM / LOW)
  2. Building an ECS-compliant JSON document
  3. Shipping the document to Elasticsearch
  4. Falling back to a local JSON log file when Elasticsearch is unreachable
     (events are NEVER silently dropped)

ECS (Elastic Common Schema) field mapping
─────────────────────────────────────────
  @timestamp          ← UTC ISO-8601
  event.type          ← "CREATED" | "MODIFIED" | "DELETED" | "MOVED" | "RANSOMWARE_PATTERN"
  file.path           ← absolute path
  hash.old            ← previous SHA-256 hex digest (if available)
  hash.new            ← current SHA-256 hex digest (if available)
  hash.changed        ← boolean — did the hash actually change?
  severity            ← "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  host.name           ← machine hostname
  host.ip             ← machine IP address
  tags                ← ["fim", "integrity", "python"]

If you want to add Splunk alongside Elasticsearch, you add it here.
Nothing else changes.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import socket
from typing import Optional

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import (
    AuthenticationException,
    ConnectionError as ESConnectionError,
    ConnectionTimeout,
    TransportError,
)

from . import config
from . import alerter

logger = logging.getLogger(__name__)

# ── Silence the extremely verbose ES / urllib3 retry traceback spam ──────────
# These libraries log full tracebacks at WARNING level for every retry attempt.
# We only need our own clean one-line warnings in ship_event().
logging.getLogger("elastic_transport").setLevel(logging.ERROR)
logging.getLogger("elastic_transport.transport").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)

# ──────────────────────────────────────────────────────────────────────────────
# Elasticsearch client initialisation
# ──────────────────────────────────────────────────────────────────────────────
# Initialize Elasticsearch client with timeout.
# If ES_USER and ES_PASS are set, use HTTP authentication.

_es_kwargs: dict = {
    "hosts": [config.ES_HOST],
    "request_timeout": config.ES_TIMEOUT,
    "max_retries": 0,           # Don't retry — fall back to local log immediately
    "retry_on_timeout": False,  # Don't retry on timeout either
}

# Add HTTP authentication only when both user and password are provided.
if config.ES_USER and config.ES_PASS:
    _es_kwargs["basic_auth"] = (config.ES_USER, config.ES_PASS)
    logger.info(
        "Elasticsearch client configured WITH authentication (user=%s).",
        config.ES_USER,
    )
else:
    logger.info("Elasticsearch client configured WITHOUT authentication.")

es: Elasticsearch = Elasticsearch(**_es_kwargs)

# ──────────────────────────────────────────────────────────────────────────────
# Host identity (resolved once at import time)
# ──────────────────────────────────────────────────────────────────────────────

_HOSTNAME: str = socket.gethostname()

try:
    _HOST_IP: str = socket.gethostbyname(_HOSTNAME)
except socket.gaierror:
    _HOST_IP = "127.0.0.1"  # Fallback if DNS resolution fails

# ──────────────────────────────────────────────────────────────────────────────
# Severity classification
# ──────────────────────────────────────────────────────────────────────────────


def severity(path: str, event: str) -> str:
    """Classify the security severity of a file-system event.

    SEVERITY CLASSIFICATION ALGORITHM
    Checks most specific (exact path) to least specific (general patterns).
    Returns first match found — ORDER MATTERS.

    Classification order (first match wins):
      1. CRITICAL — path is in ``config.CRITICAL_PATHS``
      2. HIGH     — path matches a ``config.HIGH_PATTERNS`` substring,
                    OR event is a DELETION (could be covering tracks)
      3. MEDIUM   — path matches a ``config.MEDIUM_PATTERNS`` substring
      4. LOW      — everything else
    """
    # CRITICAL: exact-path match.
    # /etc/passwd, /etc/shadow, /etc/sudoers, .ssh/authorized_keys, etc.
    if any(c in path for c in config.CRITICAL_PATHS):
        return "CRITICAL"

    # HIGH: .ssh/, cron, sudoers, root home, bash profiles
    if any(p in path for p in config.HIGH_PATTERNS):
        return "HIGH"

    # ALL deletions are HIGH — could be covering tracks or evidence tampering.
    if event == "DELETED":
        return "HIGH"

    # MEDIUM: /etc/ configs, web server files, certs, logs
    if any(p in path for p in config.MEDIUM_PATTERNS):
        return "MEDIUM"

    # LOW: everything else — normal file activity.
    return "LOW"


# ──────────────────────────────────────────────────────────────────────────────
# Document builder (ECS-compliant)
# ──────────────────────────────────────────────────────────────────────────────


def build_doc(
    event_type: str,
    path: str,
    old_hash: Optional[str] = None,
    new_hash: Optional[str] = None,
) -> dict:
    """Build a structured JSON document following Elastic Common Schema (ECS).

    ECS field names (event.type, file.path, host.name) are industry standard.
    Using ECS makes events compatible with ANY Elastic SIEM installation.

    Parameters
    ----------
    event_type : str
        One of "CREATED", "MODIFIED", "DELETED", "MOVED",
        or "RANSOMWARE_PATTERN".
    path : str
        Absolute file path that triggered the event.
    old_hash : str or None
        Previous SHA-256 hex digest (for MODIFIED / MOVED events).
    new_hash : str or None
        Current SHA-256 hex digest (for CREATED / MODIFIED events).

    Returns
    -------
    dict
        A structured dictionary using ECS field names for direct
        Elasticsearch indexing.
    """
    return {
        # ISO-8601 UTC timestamp — Elasticsearch's native time format.
        "@timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        # Event classification fields.
        "event.type": event_type,
        "file.path": path,
        # Hash fields — old, new, and whether they changed.
        "hash.old": old_hash,
        "hash.new": new_hash,
        "hash.changed": old_hash != new_hash if (old_hash and new_hash) else None,
        # Severity classification from our rule engine.
        "severity": severity(path, event_type),
        # Host identity — who generated this event.
        "host.name": _HOSTNAME,
        "host.ip": _HOST_IP,
        # Tags for Kibana filtering and dashboard grouping.
        "tags": ["fim", "integrity", "python"],
    }


# ──────────────────────────────────────────────────────────────────────────────
# Event shipper with graceful fallback
# ──────────────────────────────────────────────────────────────────────────────


def ship_event(
    event_type: str,
    path: str,
    old_hash: Optional[str] = None,
    new_hash: Optional[str] = None,
) -> bool:
    """Build a document and send it to Elasticsearch.

    If Elasticsearch fails for ANY reason (offline, network error, timeout),
    the document is written to the local log file as fallback.
    Events are NEVER silently dropped.

    Returns
    -------
    bool
        ``True`` if shipped to Elasticsearch, ``False`` if fell back to log.
    """
    doc = build_doc(event_type, path, old_hash, new_hash)

    # Always log a human-readable summary to the application logger.
    logger.info(
        "[%s] %s  %s  hash=%s",
        doc["severity"],
        event_type,
        path,
        (new_hash or "n/a")[:16],
    )

    # ── Dispatch external alerts for CRITICAL / RANSOMWARE events ──
    # This runs in background threads, so it won't block the main loop.
    # It's a no-op if alerting is not configured.
    alerter.send_alert(doc)

    # Try Elasticsearch first.
    # If it fails for ANY reason (offline, network error, timeout),
    # fall back to local log file.  Events are NEVER silently dropped.
    try:
        es.index(index=config.ES_INDEX, document=doc)
        logger.debug("Shipped to ES: %s %s", event_type, path)
        return True
    except (ESConnectionError, ConnectionTimeout) as exc:
        logger.warning("ES unavailable (%s), writing to local log", exc)
    except AuthenticationException as exc:
        logger.warning("ES auth failed (%s), writing to local log", exc)
    except TransportError as exc:
        logger.warning("ES transport error (%s), writing to local log", exc)
    except Exception as exc:
        # Graceful degradation: never crash, always record.
        logger.warning("ES unexpected error (%s), writing to local log", exc)

    # Fallback: persist to local log so no event is lost.
    # The log can later be bulk-imported into Elasticsearch.
    try:
        with open(config.LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(doc, default=str) + "\n")
    except OSError as exc:
        # If even the local log fails, we still log to stderr via the logger.
        logger.error("Failed to write to local log %s: %s", config.LOG_FILE, exc)

    return False


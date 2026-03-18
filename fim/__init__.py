"""
fim — Core package for the SIEM-Integrated File Integrity Monitor.

Modules:
    config      — Environment-based configuration
    database    — SQLite baseline CRUD operations
    hasher      — SHA-256 file/directory hashing
    forwarder   — Elasticsearch ECS event shipping
    correlator  — Ransomware sliding-window detection
    alerter     — Email & webhook alert dispatch
    tui         — Rich terminal UI components
"""

__version__ = "1.0.0"

"""
config.py — Centralized Configuration for SIEM-Integrated File Integrity Monitor

Every tuneable setting lives here.  Values are read from environment variables
at import time; if the variable is not set, a sensible default is used.
No other file in the project contains magic numbers or hard-coded paths.

Usage:
    import config
    print(config.ES_HOST)          # → http://localhost:9200
    print(config.WATCH_PATHS)      # → ['/etc', '/home', '/var/www']

Environment variable overrides (production deployment):
    export ES_HOST='http://192.168.1.100:9200'
    export WATCH_PATHS='/etc,/home/myuser,/var/www'
    export RANSOM_THRESHOLD=5
    python3 monitor.py --baseline
"""

from __future__ import annotations

import os

# ──────────────────────────────────────────────────────────────────────────────
# Elasticsearch connection
# ──────────────────────────────────────────────────────────────────────────────

# Full URL (scheme + host + port) of the Elasticsearch instance.
ES_HOST: str = os.getenv("ES_HOST", "http://localhost:9200")

# Name of the Elasticsearch index where FIM events are stored.
ES_INDEX: str = os.getenv("ES_INDEX", "fim-events")

# HTTP timeout (seconds) for every Elasticsearch request.
ES_TIMEOUT: int = int(os.getenv("ES_TIMEOUT", "5"))

# Optional HTTP-Basic credentials.  Leave unset for anonymous access.
# If ES_USER and ES_PASS are set, use HTTP authentication.
ES_USER: str | None = os.getenv("ES_USER")           # None → no auth header
ES_PASS: str | None = os.getenv("ES_PASS")           # None → no auth header

# ──────────────────────────────────────────────────────────────────────────────
# Monitoring paths  (privilege-aware defaults)
# ──────────────────────────────────────────────────────────────────────────────

# Detect privilege level once at import time.
IS_ROOT: bool = os.geteuid() == 0
CURRENT_USER: str = os.getenv("USER", os.getenv("LOGNAME", "unknown"))

# Comma-separated list of directories to watch / scan.
# • Root  → broad system coverage (/etc, /usr/bin, /usr/sbin, /home, /var/www)
# • User  → security-relevant subdirectories only.
#           Watching all of ~ at once exhausts the inotify watch limit on
#           systems with many projects, downloads, or tooling installed.
#           Use WATCH_PATHS env-var or --paths flag to override.
_home = os.path.expanduser("~")
_DEFAULT_ROOT_PATHS = "/etc,/usr/bin,/usr/sbin,/usr/local/bin,/home,/var/www"
_DEFAULT_USER_PATHS = ",".join([
    f"{_home}/Desktop",
    f"{_home}/Documents",
    f"{_home}/.ssh",
    f"{_home}/.config",
    "/etc",          # Always include system config even as non-root (read-only is fine)
])
_DEFAULT_PATHS = _DEFAULT_ROOT_PATHS if IS_ROOT else _DEFAULT_USER_PATHS
WATCH_PATHS: list[str] = os.getenv("WATCH_PATHS", _DEFAULT_PATHS).split(",")

# ──────────────────────────────────────────────────────────────────────────────
# Ransomware correlation engine
# ──────────────────────────────────────────────────────────────────────────────

# Sliding-window span in seconds.  Events older than this are evicted.
RANSOM_WINDOW: int = int(os.getenv("RANSOM_WINDOW", "30"))

# Minimum number of events inside the window to consider a ransomware pattern.
RANSOM_THRESHOLD: int = int(os.getenv("RANSOM_THRESHOLD", "10"))

# Maximum distinct file extensions allowed before the "homogeneity" check
# fails.  Ransomware typically renames everything to a single extension
# (e.g. .enc, .locked).  If extensions are too diverse, it is likely
# normal activity rather than encryption.
RANSOM_MAX_EXTS: int = int(os.getenv("RANSOM_MAX_EXTS", "3"))

# ──────────────────────────────────────────────────────────────────────────────
# Local storage
# ──────────────────────────────────────────────────────────────────────────────

# SQLite database file that holds the SHA-256 baseline for every tracked file.
DB_PATH: str = os.getenv("DB_PATH", "fim_baseline.db")

# Fallback log file used when Elasticsearch is unreachable.
LOG_FILE: str = os.getenv("LOG_FILE", "fim.log")

# ──────────────────────────────────────────────────────────────────────────────
# Severity classification — path-based rules
# ──────────────────────────────────────────────────────────────────────────────
# Severity is a rating of how dangerous or important an event is.
# CRITICAL > HIGH > MEDIUM > LOW.
# So analysts know which alerts to respond to first.

# CRITICAL: any change to these exact paths demands IMMEDIATE investigation.
# Active attack likely.
CRITICAL_PATHS: list[str] = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/crontab",
    "/boot/grub/grub.cfg",
    # SSH authorized_keys — direct backdoor access
    ".ssh/authorized_keys",
]

# HIGH: glob-style substrings — if any appears in the path, severity = HIGH.
# Investigate within minutes. Potential persistence mechanism or cover-up.
HIGH_PATTERNS: list[str] = [
    ".ssh/",
    "/etc/cron",
    "/root/",
    ".bash_profile",
    ".bashrc",
    ".profile",
    "/etc/sudoers.d/",
]

# MEDIUM: broadened config / log / certificate paths.
# Investigate same day. Could be legitimate admin activity.
MEDIUM_PATTERNS: list[str] = [
    "/etc/",
    "/var/log/",
    "nginx.conf",
    "httpd.conf",
    "apache2.conf",
    ".pem",
    ".crt",
    ".key",
    "/var/www/",
]

# ──────────────────────────────────────────────────────────────────────────────
# File exclusion patterns (production noise reduction)
# ──────────────────────────────────────────────────────────────────────────────
# Without exclusions, a FIM generates thousands of false positives from
# temporary files, editor swap files, build artifacts, and VCS metadata.
# Any file matching these patterns is silently skipped.

# Glob-style substrings — if any appears in the path, the file is SKIPPED.
# Includes known permission-restricted system directories that are
# unreadable without root — prevents floods of "Permission denied" warnings.
#
# NOTE: /etc/shadow and /etc/gshadow are intentionally NOT excluded here
# because they are in CRITICAL_PATHS — excluding them would create a
# dangerous blind spot.  The os.access() pre-check in hasher.py already
# suppresses the permission-denied noise for non-root users.
EXCLUDE_PATTERNS: list[str] = os.getenv(
    "EXCLUDE_PATTERNS",
    "__pycache__,.git,.svn,.hg,.DS_Store,.pytest_cache,node_modules"
    ",/etc/NetworkManager/system-connections"
    ",/etc/libvirt/"
    ",/etc/sudoers.d/"
    ",/etc/ssh/ssh_host_"
    ",/etc/security/opasswd"
    ",/etc/ppp/"
).split(",")

# File extensions to exclude — editor swap files, temp files, compiled bytecode.
EXCLUDE_EXTENSIONS: list[str] = os.getenv(
    "EXCLUDE_EXTENSIONS",
    ".swp,.swo,.swn,.tmp,.temp,.bak,.pyc,.pyo,.o,.so,.class,.lock",
).split(",")

# Directories to skip during recursive inotify watches AND os.walk().
# These dirs generate massive filesystem noise and can blow the inotify
# watch limit (default 65536).  A typical home directory contains
# 10K+ subdirs under .cache, .mozilla, snap, etc.
WATCH_EXCLUDE_DIRS: list[str] = os.getenv(
    "WATCH_EXCLUDE_DIRS",
    ".cache,.local/share,.mozilla,.config/chromium,.config/google-chrome,"
    ".config/Code,.config/discord,.config/slack,"
    "snap,.thumbnails,.cargo,.rustup,.npm,.nvm,"
    "node_modules,.vscode,.steam,__pycache__,.git,"
    ".local/lib,.local/pipx,go,"
    ".wine,.var/app"
).split(",")

# ──────────────────────────────────────────────────────────────────────────────
# Alerting — email & webhook notifications
# ──────────────────────────────────────────────────────────────────────────────
# Alerts fire ONLY for CRITICAL and RANSOMWARE_PATTERN events.
# All settings are optional — if not set, alerting is simply disabled.

# SMTP email alerts
ALERT_EMAIL_ENABLED: bool = os.getenv("ALERT_EMAIL_ENABLED", "false").lower() == "true"
ALERT_EMAIL_TO: str = os.getenv("ALERT_EMAIL_TO", "")
ALERT_EMAIL_FROM: str = os.getenv("ALERT_EMAIL_FROM", "fim@localhost")
SMTP_HOST: str = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT: int = int(os.getenv("SMTP_PORT", "25"))
SMTP_USER: str | None = os.getenv("SMTP_USER")
SMTP_PASS: str | None = os.getenv("SMTP_PASS")
SMTP_TLS: bool = os.getenv("SMTP_TLS", "false").lower() == "true"

# Webhook alerts (Slack, Teams, PagerDuty, custom)
WEBHOOK_URL: str | None = os.getenv("WEBHOOK_URL")        # None → disabled
WEBHOOK_TIMEOUT: int = int(os.getenv("WEBHOOK_TIMEOUT", "10"))

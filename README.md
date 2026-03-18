# SIEM-Integrated File Integrity Monitor (FIM)

A production-grade, real-time File Integrity Monitoring system built in Python.
Detects unauthorized file changes, ships alerts to Elasticsearch / SIEM, and includes behavioral ransomware detection — with a Rich TUI dashboard and full Docker Compose deployment.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     monitor.py                          │
│               (CLI + watchdog orchestrator)              │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────────┐  │
│  │ hasher   │  │ database │  │     correlator        │  │
│  │ SHA-256  │  │ SQLite   │  │ ransomware detection  │  │
│  └─────┬────┘  └────┬─────┘  └──────────┬────────────┘  │
│        │            │                    │               │
│        └────────────┼────────────────────┘               │
│                     ▼                                    │
│  ┌──────────────────────────────────────────────────┐    │
│  │              forwarder.py                        │    │
│  │  Elasticsearch ─→ alerter.py (email / webhook)   │    │
│  │  Fallback      ─→ fim.log (local JSON)           │    │
│  └──────────────────────────────────────────────────┘    │
│                                                         │
│  config.py  ←  Environment variables                    │
└─────────────────────────────────────────────────────────┘
```

## Features

| Feature | Description |
|---|---|
| **Real-time monitoring** | OS-level file event detection via `watchdog` |
| **SHA-256 integrity verification** | Cryptographic fingerprinting of every file |
| **Elasticsearch / SIEM integration** | ECS-compliant JSON events for Kibana dashboards |
| **Rich Terminal UI** | Color-coded live event table, stats panel, progress bars |
| **Ransomware detection** | Behavioral analysis — sliding window + extension homogeneity |
| **Email & webhook alerting** | Instant notifications for CRITICAL events (Slack, Teams, PagerDuty) |
| **Docker Compose deployment** | One-command ELK stack with Elasticsearch + Kibana |
| **Graceful fallback** | Events never lost — local JSON log when ES is down |
| **Comprehensive test suite** | 62 pytest tests covering all modules |
| **Severity classification** | Automatic CRITICAL / HIGH / MEDIUM / LOW based on file paths |

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/<YOUR_USERNAME>/<YOUR_REPO>.git
cd <YOUR_REPO>
pip install -r requirements.txt
```

### 2. Build Baseline

```bash
# Hash all monitored files to establish the "known good" state
python3 monitor.py --baseline
```

### 3. Start Monitoring

```bash
# Real-time monitoring (default paths: /etc, /home, /var/www)
python3 monitor.py --watch

# Custom paths
python3 monitor.py --watch --paths /etc /opt/myapp /var/www

# Headless mode (no Rich TUI — for daemons / systemd)
python3 monitor.py --watch --no-tui

# One-time scan (compare current state to baseline)
python3 monitor.py --scan

# Build baseline then scan in one command
python3 monitor.py --baseline --scan
```

---

## Terminal Dashboard

The `--watch` mode includes a SOC-style terminal dashboard:

- **Startup banner** — hostname, Elasticsearch status, watch paths, uptime
- **Live event table** — color-coded by severity (CRITICAL, HIGH, MEDIUM, LOW)
- **Real-time stats panel** — total events, severity counters, last alert timestamp
- **Progress bar** — displays during `--baseline` with file count and ETA

```bash
# Rich TUI enabled by default
python3 monitor.py --watch

# Disable TUI for daemon/headless mode
python3 monitor.py --watch --no-tui
```

The TUI degrades gracefully — if `rich` is not installed, plain logging is used.

---

## Configuration

All settings are via **environment variables** — no config files to manage.

### Core Settings

| Variable | Default | Description |
|---|---|---|
| `WATCH_PATHS` | `/etc,/home,/var/www` | Comma-separated directories to monitor |
| `DB_PATH` | `fim_baseline.db` | SQLite database path |
| `LOG_FILE` | `fim.log` | Local fallback log path |

### Elasticsearch

| Variable | Default | Description |
|---|---|---|
| `ES_HOST` | `http://localhost:9200` | Elasticsearch URL |
| `ES_INDEX` | `fim-events` | Index name for FIM events |
| `ES_TIMEOUT` | `5` | Request timeout (seconds) |
| `ES_USER` | *(none)* | HTTP Basic auth username |
| `ES_PASS` | *(none)* | HTTP Basic auth password |

### Ransomware Detection

| Variable | Default | Description |
|---|---|---|
| `RANSOM_WINDOW` | `30` | Detection window (seconds) |
| `RANSOM_THRESHOLD` | `10` | Minimum events to trigger |
| `RANSOM_MAX_EXTS` | `3` | Max distinct extensions (low = suspicious) |

### File Exclusions

| Variable | Default | Description |
|---|---|---|
| `EXCLUDE_PATTERNS` | `__pycache__,.git,.svn,...` | Substring patterns to skip |
| `EXCLUDE_EXTENSIONS` | `.swp,.tmp,.pyc,.bak,...` | File extensions to skip |

### Email Alerting

| Variable | Default | Description |
|---|---|---|
| `ALERT_EMAIL_ENABLED` | `false` | Enable email alerts |
| `ALERT_EMAIL_TO` | *(none)* | Comma-separated recipients |
| `ALERT_EMAIL_FROM` | `fim@localhost` | Sender address |
| `SMTP_HOST` | `localhost` | SMTP server |
| `SMTP_PORT` | `25` | SMTP port |
| `SMTP_USER` / `SMTP_PASS` | *(none)* | SMTP auth credentials |
| `SMTP_TLS` | `false` | Enable STARTTLS |

### Webhook Alerting

| Variable | Default | Description |
|---|---|---|
| `WEBHOOK_URL` | *(none)* | Slack/Teams/PagerDuty webhook URL |
| `WEBHOOK_TIMEOUT` | `10` | HTTP timeout (seconds) |

---

## Production Deployment

### Systemd Service

```bash
# 1. Create FIM user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin fim

# 2. Install files
sudo mkdir -p /opt/fim /etc/fim /var/log/fim
sudo cp *.py requirements.txt /opt/fim/
sudo pip install -r /opt/fim/requirements.txt

# 3. Create environment file
sudo tee /etc/fim/fim.env << 'EOF'
ES_HOST=http://elasticsearch:9200
ES_INDEX=fim-events
WATCH_PATHS=/etc,/home,/var/www,/opt
DB_PATH=/opt/fim/fim_baseline.db
LOG_FILE=/var/log/fim/fim.log
ALERT_EMAIL_ENABLED=true
ALERT_EMAIL_TO=soc@company.com
SMTP_HOST=smtp.company.com
SMTP_TLS=true
WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
EOF

# 4. Install and start service
sudo cp fim.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fim.service

# 5. Check status
sudo systemctl status fim
sudo journalctl -u fim -f
```

### Docker (Optional)

```dockerfile
FROM python:3.12-slim
WORKDIR /opt/fim
COPY *.py requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python3", "monitor.py", "--watch", "--no-tui"]
```

### Docker Compose (Recommended)

Spin up the full ELK stack with one command:

```bash
# Start FIM + Elasticsearch + Kibana
docker compose up -d

# View FIM logs
docker compose logs -f fim

# Open Kibana at http://localhost:5601

# Stop everything
docker compose down
```

The `docker-compose.yml` includes:
- **FIM Monitor** — watches `/monitored` directory
- **Elasticsearch 8.13** — single-node with health checks
- **Kibana 8.13** — accessible at `http://localhost:5601`

---

## Testing

62 unit tests covering all core modules:

```bash
# Install dev dependencies (includes pytest)
pip install -r requirements-dev.txt

# Run all tests
python3 -m pytest tests/ -v

# Run specific module tests
python3 -m pytest tests/test_hasher.py -v
python3 -m pytest tests/test_correlator.py -v
```

| Test File | Module | Tests |
|---|---|---|
| `test_hasher.py` | SHA-256 hashing engine | 15 |
| `test_correlator.py` | Ransomware detection | 6 |
| `test_database.py` | SQLite baseline CRUD | 9 |
| `test_forwarder.py` | Severity + ECS builder | 23 |
| `test_alerter.py` | Alert filtering | 9 |

---

## Compliance Mapping

This FIM satisfies requirements across major security frameworks:

| Framework | Requirement | How FIM Addresses It |
|---|---|---|
| **PCI-DSS 11.5** | Monitor critical system files | Real-time watchdog + SHA-256 baseline |
| **HIPAA §164.312(c)** | Integrity controls for ePHI | Tamper detection with SIEM forwarding |
| **SOC 2 (CC6.1)** | Detect unauthorized changes | Severity classification + alerting |
| **NIST 800-53 (SI-7)** | Software & information integrity | Cryptographic hash verification |
| **MITRE ATT&CK** | T1565 (Data Manipulation) | Detects file content changes |
| **MITRE ATT&CK** | T1486 (Data Encrypted for Impact) | Ransomware behavioral detection |

---

## Project Structure

```
├── monitor.py                 # CLI entry point
├── dashboard.py               # Web GUI dashboard
│
├── fim/                       # Core FIM package
│   ├── __init__.py
│   ├── config.py              # Centralized settings (env vars)
│   ├── database.py            # SQLite baseline storage
│   ├── hasher.py              # SHA-256 hashing engine
│   ├── forwarder.py           # Elasticsearch bridge + fallback
│   ├── correlator.py          # Ransomware detection engine
│   ├── alerter.py             # Email and webhook notifications
│   └── tui.py                 # Rich terminal UI components
│
├── tests/                     # 62 pytest tests
│   ├── conftest.py            # Shared fixtures
│   ├── test_hasher.py
│   ├── test_correlator.py
│   ├── test_database.py
│   ├── test_forwarder.py
│   └── test_alerter.py
│
├── docs/                      # Documentation and guides
│   ├── FIM_Setup_Guide.pdf
│   ├── FIM_Project_Proposal.pdf
│   ├── TUTORIAL.md
│   └── generate_setup_pdf.py
│
├── deploy/                    # Deployment configs
│   └── fim.service            # Systemd unit file
│
├── monitored/                 # Sample test directory
│
├── Dockerfile                 # Container image
├── docker-compose.yml         # ELK stack deployment
├── requirements.txt           # Python dependencies
├── setup.sh                   # One-click setup script
├── .env / .env.example        # Environment configuration
├── .gitignore
└── README.md
```

---

## Who Is This For?

| User | Use Case |
|---|---|
| **Security Operations Centers (SOC)** | Real-time file integrity alerts in Kibana/SIEM dashboards |
| **System Administrators** | Detect unauthorized config changes on production servers |
| **Compliance Teams** | Automated PCI-DSS / HIPAA / SOC 2 file monitoring |
| **Incident Responders** | Forensic evidence of file tampering with timestamps and hashes |
| **Security Professionals** | Lightweight FIM for personal lab or client systems |
| **DevOps / SRE Teams** | Monitor deployment artifacts and infrastructure-as-code |

---

## License

MIT License — use freely in personal and commercial projects. See [LICENSE](LICENSE) for full text.

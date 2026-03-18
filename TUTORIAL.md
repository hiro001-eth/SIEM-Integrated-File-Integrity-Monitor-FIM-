# 🛡️ FIM Operations Tutorial — SOC Professional Guide

A step-by-step guide to deploy and operate the SIEM-Integrated File Integrity Monitor in a real security operations environment.

---

## Phase 1: Installation & Setup

### Step 1.1 — Clone & Install Dependencies

```bash
# Navigate to the project
cd ~/Desktop/SIEM-Integrated\ File\ Integrity\ Monitor

# Install Python dependencies
pip install -r requirements.txt
```

**Expected output:**
```
Successfully installed watchdog-4.0.1 elasticsearch-8.13.1
```

### Step 1.2 — Verify Installation

```bash
python3 monitor.py --help
```

**Expected output:**
```
usage: monitor.py [-h] [--baseline] [--scan] [--watch] [--paths PATHS [PATHS ...]]

SIEM-Integrated File Integrity Monitor

options:
  --baseline    Build initial hash baseline
  --scan        One-time integrity scan vs baseline
  --watch       Start real-time monitoring (default)
  --paths       Override the directories to monitor/scan
```

---

## Phase 2: Build the Baseline (Clean State Snapshot)

> [!IMPORTANT]
> Always build the baseline on a **known-clean system**. The baseline IS your definition of "normal." If you baseline a compromised system, the FIM will consider the malicious files as legitimate.

### Step 2.1 — Choose What to Monitor

```bash
# Option A: Default paths (/etc, /home, /var/www)
python3 monitor.py --baseline

# Option B: Custom paths (recommended for SOC)
python3 monitor.py --baseline --paths /etc /home /var/www /opt /usr/local/bin
```

**What happens:**
```
2026-03-17 23:00:00 INFO     Baselining: /etc
2026-03-17 23:00:01 INFO     Hashed 847 files under /etc (skipped 12 excluded)
2026-03-17 23:00:01 INFO     Baselining: /home
2026-03-17 23:00:03 INFO     Hashed 2341 files under /home (skipped 189 excluded)
2026-03-17 23:00:03 INFO     Baseline complete. 3188 files recorded.
```

The baseline is stored in `fim_baseline.db` (SQLite). Each file's SHA-256 hash and last-seen timestamp are recorded.

### Step 2.2 — Verify the Baseline

```bash
# Check how many files were baselined
python3 -c "
import database
database.init_db()
rows = database.get_all()
print(f'Baseline: {len(rows)} files recorded')
# Show first 5 entries
for path, sha256, ts in rows[:5]:
    print(f'  {sha256[:16]}...  {path}')
"
```

---

## Phase 3: One-Time Integrity Scan

Use `--scan` for a scheduled audit — cron job, manual check before/after maintenance, or incident response.

### Step 3.1 — Run the Scan

```bash
python3 monitor.py --scan --paths /etc /home
```

**Clean system output:**
```
2026-03-17 23:05:00 INFO     ═══ Starting integrity scan ═══
2026-03-17 23:05:02 INFO     ═══ Scan complete — ADDED: 0 | MODIFIED: 0 | DELETED: 0 ═══
```

**Compromised system output:**
```
2026-03-17 23:05:00 INFO     ═══ Starting integrity scan ═══
2026-03-17 23:05:01 INFO     MODIFIED /etc/passwd
2026-03-17 23:05:01 WARNING  [CRITICAL] MODIFIED /etc/passwd hash=a1b2c3d4e5f6...
2026-03-17 23:05:01 INFO     ADDED /etc/cron.d/backdoor
2026-03-17 23:05:01 WARNING  [HIGH] CREATED /etc/cron.d/backdoor
2026-03-17 23:05:02 WARNING  DELETED /var/log/auth.log
2026-03-17 23:05:02 WARNING  [HIGH] DELETED /var/log/auth.log
2026-03-17 23:05:02 INFO     ═══ Scan complete — ADDED: 1 | MODIFIED: 1 | DELETED: 1 ═══
```

> [!CAUTION]
> If you see modifications to `/etc/passwd`, `/etc/shadow`, or `.ssh/authorized_keys`, treat this as a **potential active compromise**. Initiate incident response immediately.

### Step 3.2 — Schedule with cron (Automated Scans)

```bash
# Edit crontab
crontab -e

# Add: scan every 6 hours, log output
0 */6 * * * cd /opt/fim && python3 monitor.py --scan --paths /etc /home >> /var/log/fim/scan.log 2>&1
```

---

## Phase 4: Real-Time Monitoring (SOC Mode)

This is the primary mode — the FIM watches for file changes in real time and ships events instantly.

### Step 4.1 — Start the Monitor

```bash
# Foreground (for testing / demo)
python3 monitor.py --watch --paths /etc /home /var/www

# Or simply (uses default paths from config)
python3 monitor.py --watch
```

**Output when running:**
```
2026-03-17 23:10:00 INFO     Watching: /etc
2026-03-17 23:10:00 INFO     Watching: /home
2026-03-17 23:10:00 INFO     Watching: /var/www
2026-03-17 23:10:00 INFO     FIM Monitor running. Press Ctrl+C to stop.
```

### Step 4.2 — Simulate an Attack (Demo / SOC Training)

Open a **second terminal** and create test events:

```bash
# 1. Create a suspicious file (triggers CREATED event)
echo "malicious payload" > /tmp/test_fim/backdoor.sh

# 2. Modify a config file (triggers MODIFIED event)
echo "# test change" >> /tmp/test_fim/config.conf

# 3. Delete evidence (triggers DELETED event — always HIGH severity)
rm /tmp/test_fim/config.conf

# 4. Simulate ransomware (rapid file creation with same extension)
mkdir -p /tmp/test_fim/ransom
for i in $(seq 1 15); do
    echo "encrypted" > /tmp/test_fim/ransom/file_$i.encrypted
done
```

**FIM output in the first terminal:**
```
2026-03-17 23:10:05 INFO     CREATED /tmp/test_fim/backdoor.sh
2026-03-17 23:10:05 INFO     [LOW] CREATED /tmp/test_fim/backdoor.sh hash=a1b2c3d4...
2026-03-17 23:10:08 INFO     MODIFIED /tmp/test_fim/config.conf
2026-03-17 23:10:08 INFO     [LOW] MODIFIED /tmp/test_fim/config.conf hash=e5f6a7b8...
2026-03-17 23:10:10 WARNING  DELETED /tmp/test_fim/config.conf
2026-03-17 23:10:10 INFO     [HIGH] DELETED /tmp/test_fim/config.conf hash=n/a
2026-03-17 23:10:15 CRITICAL 🚨 RANSOMWARE PATTERN DETECTED: 12 events in 30s, exts={'.encrypted'}
2026-03-17 23:10:15 INFO     [CRITICAL] RANSOMWARE_PATTERN MULTIPLE_FILES
```

### Step 4.3 — Stop Gracefully

```bash
# From the terminal running the FIM
Ctrl+C

# Or from another terminal (if running as a service)
kill -SIGTERM $(pgrep -f "monitor.py")
```

---

## Phase 5: Elasticsearch + Kibana Integration (SIEM)

### Step 5.1 — Configure Elasticsearch Connection

```bash
# Set environment variables before starting the FIM
export ES_HOST="http://your-elasticsearch:9200"
export ES_INDEX="fim-events"

# If authentication is required
export ES_USER="elastic"
export ES_PASS="your-password"

# Start monitoring with ES enabled
python3 monitor.py --watch
```

### Step 5.2 — Kibana Dashboard Queries (KQL)

Once events are flowing to Elasticsearch, use these queries in Kibana:

```
# All CRITICAL events (SOC priority queue)
severity: "CRITICAL"

# Ransomware alerts
event.type: "RANSOMWARE_PATTERN"

# All deletions (potential evidence tampering)
event.type: "DELETED"

# Changes to SSH keys (lateral movement indicator)
file.path: *authorized_keys*

# Changes to password files
file.path: "/etc/passwd" OR file.path: "/etc/shadow"

# All events from a specific host
host.name: "prod-web-01"

# Events in the last hour
@timestamp >= now-1h
```

### Step 5.3 — Create Detection Rules in Kibana

| Rule Name | KQL Query | Severity | Action |
|---|---|---|---|
| Shadow file modified | `file.path:"/etc/shadow" AND event.type:"MODIFIED"` | Critical | Page SOC |
| SSH keys changed | `file.path:*authorized_keys*` | Critical | Page SOC |
| Ransomware detected | `event.type:"RANSOMWARE_PATTERN"` | Critical | Page SOC + IR |
| Evidence tampering | `event.type:"DELETED" AND severity:"HIGH"` | High | Alert SOC |
| Web shell upload | `file.path:"/var/www/*" AND event.type:"CREATED"` | High | Alert SOC |
| Cron job modified | `file.path:*cron*` | High | Alert SOC |

---

## Phase 6: Email & Webhook Alerts

### Step 6.1 — Email Alerts (Gmail Example)

```bash
export ALERT_EMAIL_ENABLED=true
export ALERT_EMAIL_TO="soc-team@company.com,analyst@company.com"
export ALERT_EMAIL_FROM="fim-alerts@company.com"
export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_TLS=true
export SMTP_USER="fim-alerts@company.com"
export SMTP_PASS="your-app-password"

python3 monitor.py --watch
```

### Step 6.2 — Slack Alerts

```bash
# Get webhook URL from: Slack → Apps → Incoming Webhooks → Add New
export WEBHOOK_URL="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"

python3 monitor.py --watch
```

**Slack message format:**
```
🚨 FIM ALERT — CRITICAL
Event: RANSOMWARE_PATTERN
File: MULTIPLE_FILES
Host: prod-web-01
Time: 2026-03-17T23:15:00+00:00
```

---

## Phase 7: Production Deployment (systemd)

### Step 7.1 — Install as System Service

```bash
# 1. Create service account
sudo useradd --system --no-create-home --shell /usr/sbin/nologin fim

# 2. Deploy files
sudo mkdir -p /opt/fim /etc/fim /var/log/fim
sudo cp *.py requirements.txt /opt/fim/
sudo pip install -r /opt/fim/requirements.txt
sudo chown -R fim:fim /opt/fim /var/log/fim

# 3. Create environment file
sudo nano /etc/fim/fim.env
```

**Example `/etc/fim/fim.env`:**
```bash
ES_HOST=http://elasticsearch:9200
ES_INDEX=fim-events
WATCH_PATHS=/etc,/home,/var/www,/opt,/usr/local/bin
DB_PATH=/opt/fim/fim_baseline.db
LOG_FILE=/var/log/fim/fim.log
ALERT_EMAIL_ENABLED=true
ALERT_EMAIL_TO=soc@company.com
SMTP_HOST=smtp.company.com
SMTP_PORT=587
SMTP_TLS=true
WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

```bash
# 4. Install systemd service
sudo cp fim.service /etc/systemd/system/
sudo systemctl daemon-reload

# 5. Build baseline FIRST
sudo -u fim bash -c 'cd /opt/fim && source /etc/fim/fim.env && python3 monitor.py --baseline'

# 6. Start and enable service
sudo systemctl enable --now fim.service
```

### Step 7.2 — Service Management Commands

```bash
# Check status
sudo systemctl status fim

# View live logs
sudo journalctl -u fim -f

# Restart after config change
sudo systemctl restart fim

# Stop the service
sudo systemctl stop fim

# Rebuild baseline (during maintenance window)
sudo systemctl stop fim
sudo -u fim bash -c 'cd /opt/fim && python3 monitor.py --baseline'
sudo systemctl start fim
```

---

## Quick Reference Card

| Task | Command |
|---|---|
| Build baseline | `python3 monitor.py --baseline` |
| One-time scan | `python3 monitor.py --scan` |
| Real-time monitor | `python3 monitor.py --watch` |
| Custom paths | `python3 monitor.py --watch --paths /etc /opt` |
| Baseline + scan | `python3 monitor.py --baseline --scan` |
| Service start | `sudo systemctl start fim` |
| Service logs | `sudo journalctl -u fim -f` |
| View local events | `cat fim.log \| python3 -m json.tool` |
| View baseline DB | `sqlite3 fim_baseline.db "SELECT * FROM hashes LIMIT 10;"` |

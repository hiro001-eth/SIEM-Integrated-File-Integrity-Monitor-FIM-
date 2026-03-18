#!/usr/bin/env python3
"""Generate a professional Setup Guide & User Manual PDF for the SIEM FIM project."""

from fpdf import FPDF
import os

OUTPUT = os.path.join(os.path.dirname(__file__), "FIM_Setup_Guide.pdf")


class SetupPDF(FPDF):
    """Custom PDF with header/footer branding."""

    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, "SIEM-Integrated File Integrity Monitor", align="R")
        self.ln(12)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(140, 140, 140)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    # ── Helpers ────────────────────────────────────────────────────────────

    def section_title(self, num, title):
        self.ln(4)
        self.set_font("Helvetica", "B", 15)
        self.set_text_color(22, 100, 180)
        self.cell(0, 10, f"{num}. {title}", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(22, 100, 180)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(4)

    def sub_title(self, title):
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(40, 40, 40)
        self.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def body(self, text):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(50, 50, 50)
        self.multi_cell(0, 5.5, text)
        self.ln(2)

    def code_block(self, code):
        self.set_font("Courier", "", 9)
        self.set_fill_color(240, 240, 240)
        self.set_text_color(30, 30, 30)
        x = self.get_x()
        w = self.w - self.l_margin - self.r_margin
        for line in code.strip().split("\n"):
            self.set_x(x + 2)
            self.cell(w - 4, 5.5, line, new_x="LMARGIN", new_y="NEXT", fill=True)
        self.ln(3)

    def output_block(self, code):
        """A code block styled as sample terminal output (slightly different shade)."""
        self.set_font("Courier", "", 8.5)
        self.set_fill_color(232, 245, 232)
        self.set_text_color(30, 80, 30)
        x = self.get_x()
        w = self.w - self.l_margin - self.r_margin
        for line in code.strip().split("\n"):
            self.set_x(x + 2)
            self.cell(w - 4, 5.2, line, new_x="LMARGIN", new_y="NEXT", fill=True)
        self.set_text_color(50, 50, 50)
        self.ln(3)

    def bullet(self, text, bold_prefix=""):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(50, 50, 50)
        x = self.get_x()
        self.set_x(x + 4)
        if bold_prefix:
            self.set_font("Helvetica", "B", 10)
            self.write(5.5, f"  {bold_prefix}")
            self.set_font("Helvetica", "", 10)
            self.write(5.5, f"  {text}")
        else:
            self.write(5.5, f"  {text}")
        self.ln(6)

    def table_row(self, col1, col2, header=False):
        w1 = 65
        w2 = self.w - self.l_margin - self.r_margin - w1
        if header:
            self.set_font("Helvetica", "B", 9)
            self.set_fill_color(22, 100, 180)
            self.set_text_color(255, 255, 255)
        else:
            self.set_font("Helvetica", "", 9)
            self.set_fill_color(248, 248, 248)
            self.set_text_color(50, 50, 50)
        self.cell(w1, 7, f"  {col1}", border=1, fill=True)
        self.cell(w2, 7, f"  {col2}", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

    def table_row3(self, c1, c2, c3, header=False):
        w1, w2 = 50, 50
        w3 = self.w - self.l_margin - self.r_margin - w1 - w2
        if header:
            self.set_font("Helvetica", "B", 9)
            self.set_fill_color(22, 100, 180)
            self.set_text_color(255, 255, 255)
        else:
            self.set_font("Helvetica", "", 9)
            self.set_fill_color(248, 248, 248)
            self.set_text_color(50, 50, 50)
        self.cell(w1, 7, f"  {c1}", border=1, fill=True)
        self.cell(w2, 7, f"  {c2}", border=1, fill=True)
        self.cell(w3, 7, f"  {c3}", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

    def info_box(self, title, text):
        """A highlighted info/tip box."""
        self.set_fill_color(235, 245, 255)
        self.set_draw_color(22, 100, 180)
        y0 = self.get_y()
        # Estimate height
        lines = len(text) / 85 + 2
        h = max(18, lines * 6 + 10)
        self.rect(self.l_margin, y0, self.w - self.l_margin - self.r_margin, h, style="DF")
        self.set_xy(self.l_margin + 4, y0 + 3)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(22, 100, 180)
        self.write(5, title)
        self.ln(7)
        self.set_x(self.l_margin + 4)
        self.set_font("Helvetica", "", 9.5)
        self.set_text_color(50, 50, 50)
        self.multi_cell(self.w - self.l_margin - self.r_margin - 8, 5, text)
        self.set_y(y0 + h + 4)


def build_pdf():
    pdf = SetupPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # ══════════════════════════════════════════════════════════════════════
    # COVER PAGE
    # ══════════════════════════════════════════════════════════════════════
    pdf.ln(20)
    pdf.set_font("Helvetica", "B", 30)
    pdf.set_text_color(22, 100, 180)
    pdf.cell(0, 14, "SIEM-Integrated", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 14, "File Integrity Monitor", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(8)
    pdf.set_draw_color(22, 100, 180)
    pdf.line(60, pdf.get_y(), pdf.w - 60, pdf.get_y())
    pdf.ln(8)
    pdf.set_font("Helvetica", "", 18)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 10, "Setup Guide & User Manual", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)
    pdf.set_font("Helvetica", "I", 12)
    pdf.cell(0, 8, "Version 1.0.0", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(20)

    # Feature highlights box
    pdf.set_fill_color(235, 245, 255)
    pdf.set_draw_color(22, 100, 180)
    y_start = pdf.get_y()
    pdf.rect(pdf.l_margin, y_start, pdf.w - pdf.l_margin - pdf.r_margin, 62, style="DF")
    pdf.set_xy(pdf.l_margin + 5, y_start + 5)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(22, 100, 180)
    pdf.cell(0, 6, "Key Capabilities")
    pdf.ln(9)
    for h in [
        "Real-time file system monitoring with SHA-256 integrity verification",
        "Elasticsearch SIEM integration with ECS-compliant event documents",
        "Behavioural ransomware detection (sliding window algorithm)",
        "Professional Rich terminal UI with live color-coded dashboard",
        "Automated email & webhook alerting for CRITICAL events",
        "Full Docker Compose deployment (FIM + Elasticsearch + Kibana)",
        "62 automated pytest unit tests with isolated fixtures",
        "Systemd service file for production daemon deployment",
    ]:
        pdf.set_x(pdf.l_margin + 8)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(50, 50, 50)
        pdf.cell(0, 5.5, f"  {h}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_y(y_start + 66)

    # ══════════════════════════════════════════════════════════════════════
    # TABLE OF CONTENTS
    # ══════════════════════════════════════════════════════════════════════
    pdf.ln(8)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(22, 100, 180)
    pdf.cell(0, 8, "Table of Contents", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    toc = [
        "1.  Prerequisites",
        "2.  Installation",
        "3.  Configuration Reference",
        "4.  User Manual - Building a Baseline",
        "5.  User Manual - Real-Time Monitoring",
        "6.  User Manual - Integrity Scanning",
        "7.  User Manual - Rich Terminal UI",
        "8.  User Manual - Web Dashboard",
        "9.  Docker Compose Deployment",
        "10. Running Tests",
        "11. Systemd Production Deployment",
        "12. Architecture & Module Reference",
        "13. Compliance Mapping",
        "14. Troubleshooting",
    ]
    for t in toc:
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(50, 50, 50)
        pdf.set_x(pdf.l_margin + 8)
        pdf.cell(0, 6.5, t, new_x="LMARGIN", new_y="NEXT")

    # ══════════════════════════════════════════════════════════════════════
    # 1. PREREQUISITES
    # ══════════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("1", "Prerequisites")

    pdf.sub_title("System Requirements")
    pdf.bullet("Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+, Arch)")
    pdf.bullet("Python 3.10 or higher")
    pdf.bullet("pip (Python package manager)")
    pdf.bullet("Git (for cloning the repository)")
    pdf.bullet("Docker & Docker Compose v2 (optional, for ELK stack)")

    pdf.sub_title("Verify Python")
    pdf.code_block(
        "python3 --version\n"
        "pip --version"
    )
    pdf.body("Expected output:")
    pdf.output_block(
        "Python 3.12.3\n"
        "pip 24.0 from /usr/lib/python3/dist-packages/pip (python 3.12)"
    )

    pdf.sub_title("Verify Docker (Optional)")
    pdf.code_block(
        "docker --version\n"
        "docker compose version"
    )
    pdf.body("Expected output:")
    pdf.output_block(
        "Docker version 27.0.3, build 7d4bcd8\n"
        "Docker Compose version v2.28.1"
    )

    # ══════════════════════════════════════════════════════════════════════
    # 2. INSTALLATION
    # ══════════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("2", "Installation")

    pdf.sub_title("Step 1: Clone the Repository")
    pdf.body("Download the project source code from GitHub:")
    pdf.code_block(
        "git clone https://github.com/yourusername/fim.git\n"
        "cd fim"
    )

    pdf.sub_title("Step 2: Create a Virtual Environment")
    pdf.body(
        "A virtual environment isolates the project's packages from your system Python. "
        "This prevents version conflicts with other Python projects."
    )
    pdf.code_block(
        "python3 -m venv venv\n"
        "source venv/bin/activate"
    )
    pdf.body("Your shell prompt will change to show (venv) at the start.")

    pdf.sub_title("Step 3: Install Dependencies")
    pdf.body("Install all required Python packages with pinned versions:")
    pdf.code_block("pip install -r requirements.txt")
    pdf.body("Expected output (last few lines):")
    pdf.output_block(
        "Successfully installed watchdog-4.0.1 elasticsearch-8.13.1\n"
        "  rich-13.7.1 Flask-3.0.3 pytest-8.2.2"
    )

    pdf.info_box("What Each Dependency Does:",
        "watchdog - Monitors the filesystem for changes in real-time using OS-level events.  "
        "elasticsearch - Python client for shipping events to Elasticsearch/SIEM.  "
        "rich - Provides the color-coded terminal UI dashboard.  "
        "Flask - Powers the optional web-based GUI dashboard.  "
        "pytest - Test framework for running the 62 unit tests."
    )

    pdf.sub_title("Step 4: Configure Environment Variables")
    pdf.body(
        "Copy the example config file and edit it with your settings. "
        "All variables have sensible defaults, so this step is optional for a quick start."
    )
    pdf.code_block("cp .env.example .env\nnano .env")

    # ══════════════════════════════════════════════════════════════════════
    # 3. CONFIGURATION REFERENCE
    # ══════════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("3", "Configuration Reference")

    pdf.body(
        "All settings are controlled via environment variables defined in config.py. "
        "Set them in a .env file or export in your shell. No source code changes needed."
    )

    pdf.sub_title("Core Settings")
    pdf.table_row("Variable", "Default / Description", header=True)
    pdf.table_row("WATCH_PATHS", "/etc,/home,/var/www (comma-separated)")
    pdf.table_row("DB_PATH", "fim_baseline.db (SQLite file location)")
    pdf.table_row("LOG_FILE", "fim.log (fallback when ES is down)")
    pdf.ln(4)

    pdf.sub_title("Elasticsearch Connection")
    pdf.table_row("Variable", "Default / Description", header=True)
    pdf.table_row("ES_HOST", "http://localhost:9200")
    pdf.table_row("ES_INDEX", "fim-events (index name in ES)")
    pdf.table_row("ES_TIMEOUT", "5 (HTTP timeout in seconds)")
    pdf.table_row("ES_USER", "unset (HTTP Basic auth username)")
    pdf.table_row("ES_PASS", "unset (HTTP Basic auth password)")
    pdf.ln(4)

    pdf.sub_title("Ransomware Detection Tuning")
    pdf.table_row("Variable", "Default / Description", header=True)
    pdf.table_row("RANSOM_WINDOW", "30 (sliding window in seconds)")
    pdf.table_row("RANSOM_THRESHOLD", "10 (events needed to trigger)")
    pdf.table_row("RANSOM_MAX_EXTS", "3 (max distinct extensions)")
    pdf.ln(3)
    pdf.body(
        "The ransomware engine triggers when RANSOM_THRESHOLD events occur within "
        "RANSOM_WINDOW seconds AND the distinct file extensions are <= RANSOM_MAX_EXTS. "
        "This catches encryption tools that rename files to .enc, .locked, etc."
    )

    pdf.sub_title("Email & Webhook Alerts")
    pdf.table_row("Variable", "Default / Description", header=True)
    pdf.table_row("ALERT_EMAIL_ENABLED", "false (set to true to enable)")
    pdf.table_row("ALERT_EMAIL_TO", "comma-separated recipient emails")
    pdf.table_row("ALERT_EMAIL_FROM", "fim@localhost")
    pdf.table_row("SMTP_HOST / SMTP_PORT", "localhost / 25")
    pdf.table_row("SMTP_TLS", "false (enable for Gmail/Office365)")
    pdf.table_row("WEBHOOK_URL", "unset (Slack/Teams webhook URL)")

    # ══════════════════════════════════════════════════════════════════════
    # 4. USER MANUAL — BASELINE
    # ══════════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("4", "User Manual - Building a Baseline")

    pdf.body(
        "A baseline is a 'known good' snapshot of every file's SHA-256 hash in your "
        "monitored directories. It's stored in a SQLite database (fim_baseline.db). "
        "You must build a baseline BEFORE scanning or monitoring can detect changes."
    )

    pdf.sub_title("Command: Build Baseline")
    pdf.code_block("python3 monitor.py --baseline")
    pdf.body("What this command does:")
    pdf.bullet("Reads WATCH_PATHS from config (default: /etc, /home, /var/www)")
    pdf.bullet("Walks every file in those directories recursively")
    pdf.bullet("Skips excluded files (.swp, .pyc, __pycache__, .git, etc.)")
    pdf.bullet("Computes SHA-256 hash of each file (reads in 64KB chunks)")
    pdf.bullet("Stores each file path + hash + timestamp in SQLite database")
    pdf.bullet("Displays a Rich progress bar showing files processed and ETA")

    pdf.body("Expected output:")
    pdf.output_block(
        "$ python3 monitor.py --baseline\n"
        "\n"
        "  SIEM File Integrity Monitor v1.0.0\n"
        "  Hostname: server01 | ES: http://localhost:9200\n"
        "  Watch Paths: /etc, /home, /var/www\n"
        "\n"
        "  Storing baseline [==============>--------]  67%  1,847/2,753 files  ETA 0:12\n"
        "\n"
        "  Baseline complete: 2,753 files hashed and stored."
    )

    pdf.sub_title("Command: Baseline with Custom Paths")
    pdf.code_block("python3 monitor.py --baseline --paths /opt/myapp /srv/data")
    pdf.body(
        "Overrides WATCH_PATHS from config. Only the specified directories are scanned. "
        "Useful for targeting specific application directories."
    )

    pdf.info_box("When to Rebuild the Baseline:",
        "Rebuild after authorized changes (software updates, config edits, deployments). "
        "Any file that was legitimately changed will show as MODIFIED in the next scan "
        "until you rebuild the baseline."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 5. USER MANUAL — MONITORING
    # ══════════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("5", "User Manual - Real-Time Monitoring")

    pdf.body(
        "The --watch mode starts a persistent monitoring daemon that detects file changes "
        "AS THEY HAPPEN using the OS-level watchdog library. Events are displayed in the "
        "Rich TUI dashboard and simultaneously shipped to Elasticsearch."
    )

    pdf.sub_title("Command: Start Monitoring (with Rich TUI)")
    pdf.code_block("python3 monitor.py --watch")
    pdf.body("What this command does:")
    pdf.bullet("Prints the startup banner (hostname, ES status, paths, DB location)")
    pdf.bullet("Starts the watchdog filesystem observer on all WATCH_PATHS")
    pdf.bullet("Opens the Rich Live dashboard showing a color-coded event table")
    pdf.bullet("For each file event (create/modify/delete/move):")
    pdf.bullet("  - Computes new SHA-256 hash and compares against baseline")
    pdf.bullet("  - Classifies severity (CRITICAL / HIGH / MEDIUM / LOW)")
    pdf.bullet("  - Ships ECS-compliant JSON document to Elasticsearch")
    pdf.bullet("  - Runs ransomware correlation (sliding window analysis)")
    pdf.bullet("  - Triggers email/webhook alerts for CRITICAL events")
    pdf.bullet("  - Updates the TUI dashboard in real-time")
    pdf.bullet("Handles Ctrl+C (SIGINT) for graceful shutdown")

    pdf.body("Expected terminal output:")
    pdf.output_block(
        "$ python3 monitor.py --watch\n"
        "\n"
        "  SIEM File Integrity Monitor v1.0.0\n"
        "  Hostname: server01 | ES: connected\n"
        "  Watch Paths: /etc, /home, /var/www\n"
        "  Database: fim_baseline.db (2,753 files)\n"
        "\n"
        "  +----------+------+----------------------------+----------+\n"
        "  | Time     | Sev  | File Path                  | Event    |\n"
        "  +----------+------+----------------------------+----------+\n"
        "  | 14:23:01 | CRIT | /etc/passwd                | MODIFIED |\n"
        "  | 14:23:05 | HIGH | /home/user/.bashrc         | MODIFIED |\n"
        "  | 14:23:12 | MED  | /etc/nginx/nginx.conf      | MODIFIED |\n"
        "  | 14:23:18 | LOW  | /home/user/docs/readme.txt | CREATED  |\n"
        "  +----------+------+----------------------------+----------+\n"
        "\n"
        "  Events: 4 | CRIT: 1 | HIGH: 1 | Uptime: 00:01:23"
    )

    pdf.sub_title("Command: Watch with Custom Paths")
    pdf.code_block("python3 monitor.py --watch --paths /etc /opt/webapp")

    pdf.sub_title("Command: Watch in Headless/Daemon Mode")
    pdf.code_block("python3 monitor.py --watch --no-tui")
    pdf.body(
        "The --no-tui flag disables the Rich dashboard and outputs plain log lines instead. "
        "Use this when running as a systemd service, in Docker, or in CI/CD pipelines."
    )
    pdf.body("Expected output with --no-tui:")
    pdf.output_block(
        "2026-03-18 14:23:01 INFO  [HIGH] MODIFIED /etc/nginx/nginx.conf  hash=a3b8d1f2...\n"
        "2026-03-18 14:23:05 INFO  [LOW]  CREATED  /home/user/report.pdf  hash=f7c92e4a...\n"
        "2026-03-18 14:24:00 WARN  ES unavailable, writing to local log"
    )

    pdf.sub_title("Stopping the Monitor")
    pdf.body("Press Ctrl+C to gracefully stop the monitor. It will:")
    pdf.bullet("Stop the watchdog filesystem observer")
    pdf.bullet("Close the Rich TUI dashboard")
    pdf.bullet("Flush any pending Elasticsearch writes")
    pdf.bullet("Close the SQLite database connection")

    # ══════════════════════════════════════════════════════════════════════
    # 6. USER MANUAL — SCANNING
    # ══════════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("6", "User Manual - Integrity Scanning")

    pdf.body(
        "The --scan mode performs a one-time comparison of the current file system state "
        "against the stored baseline. It reports any files that were ADDED, MODIFIED, or "
        "DELETED since the baseline was built. Unlike --watch, it exits after the scan."
    )

    pdf.sub_title("Command: Run an Integrity Scan")
    pdf.code_block("python3 monitor.py --scan")
    pdf.body("What this command does:")
    pdf.bullet("Loads the baseline database (all stored file paths + hashes)")
    pdf.bullet("Re-hashes every file in the watched directories")
    pdf.bullet("Compares current hashes against the stored baseline")
    pdf.bullet("Reports 3 categories of changes:")
    pdf.bullet("  - CREATED: files that exist now but were not in the baseline")
    pdf.bullet("  - MODIFIED: files whose SHA-256 hash has changed")
    pdf.bullet("  - DELETED: files that were in the baseline but no longer exist")
    pdf.bullet("Ships each change event to Elasticsearch (or fallback log)")
    pdf.bullet("Exits when the scan is complete")

    pdf.body("Expected output:")
    pdf.output_block(
        "$ python3 monitor.py --scan\n"
        "\n"
        "[HIGH]   MODIFIED  /etc/nginx/nginx.conf         hash=a3b8d1f2...\n"
        "[CRIT]   MODIFIED  /etc/shadow                   hash=9f2c74e8...\n"
        "[LOW]    CREATED   /home/user/new_script.sh       hash=d4e5f6a7...\n"
        "[HIGH]   DELETED   /var/www/html/backup.php       hash=n/a\n"
        "\n"
        "Scan complete: 4 changes detected (1 created, 2 modified, 1 deleted)"
    )

    pdf.sub_title("Command: Build Baseline + Scan Together")
    pdf.code_block("python3 monitor.py --baseline --scan")
    pdf.body(
        "Rebuilds the baseline first, then immediately scans. "
        "Since the baseline was just built, the scan should show 0 changes "
        "(confirming the baseline is fresh). Useful for initial setup verification."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 7. USER MANUAL — RICH TUI
    # ══════════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("7", "User Manual - Rich Terminal UI")

    pdf.body(
        "The Rich TUI provides a professional SOC-style (Security Operations Center) "
        "terminal interface. It activates automatically in --watch mode."
    )

    pdf.sub_title("Startup Banner")
    pdf.body(
        "Shown when monitoring starts. Displays system identification, "
        "Elasticsearch connectivity status, and configuration summary."
    )
    pdf.output_block(
        "+-----------------------------------------------------+\n"
        "|     SIEM File Integrity Monitor v1.0.0               |\n"
        "|     Hostname: server01                                |\n"
        "|     ES Status: Connected (http://localhost:9200)      |\n"
        "|     Watch Paths: /etc, /home, /var/www                |\n"
        "|     Database: fim_baseline.db                         |\n"
        "+-----------------------------------------------------+"
    )

    pdf.sub_title("Live Event Dashboard")
    pdf.body(
        "The main panel that shows file events in real-time. "
        "Events are color-coded by severity for instant visual triage:"
    )
    pdf.table_row("Severity Level", "Color & Meaning", header=True)
    pdf.table_row("CRITICAL (Red)", "/etc/passwd, shadow, SSH keys, sudoers")
    pdf.table_row("HIGH (Orange)", ".ssh/, cron, root home, ALL deletions")
    pdf.table_row("MEDIUM (Yellow)", "/etc/ configs, certs, web files, logs")
    pdf.table_row("LOW (Green)", "Normal file activity in user dirs")
    pdf.ln(3)

    pdf.sub_title("Stats Panel")
    pdf.body("The footer shows aggregate statistics updated in real-time:")
    pdf.bullet("Total events detected since monitoring started", bold_prefix="Events:")
    pdf.bullet("Breakdown: CRITICAL count, HIGH count, etc.", bold_prefix="Severity:")
    pdf.bullet("Timestamp of the last CRITICAL-level event", bold_prefix="Last Alert:")
    pdf.bullet("How long the monitor has been running", bold_prefix="Uptime:")

    pdf.sub_title("Baseline Progress Bar")
    pdf.body("During --baseline, a progress bar shows:")
    pdf.output_block(
        "  Storing baseline [===============>------]  72%  1,983/2,753 files  ETA 0:08"
    )
    pdf.bullet("Number of files processed vs total files found")
    pdf.bullet("Estimated time remaining (ETA)")
    pdf.bullet("Percentage complete with visual bar")

    pdf.sub_title("Disabling the TUI")
    pdf.code_block("python3 monitor.py --watch --no-tui")
    pdf.body(
        "Use --no-tui for daemon mode, Docker containers, or CI environments. "
        "If the 'rich' library is not installed, the TUI degrades gracefully "
        "to plain logging output. No features are lost."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 8. USER MANUAL — WEB DASHBOARD
    # ══════════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("8", "User Manual - Web Dashboard")

    pdf.body(
        "The project includes a Flask-based web GUI (dashboard.py) that provides "
        "a browser-based interface for all FIM operations. No additional dependencies needed."
    )

    pdf.sub_title("Starting the Web Dashboard")
    pdf.code_block("python3 dashboard.py")
    pdf.body("Expected output:")
    pdf.output_block(
        "* Running on http://127.0.0.1:5000\n"
        "* Press CTRL+C to quit"
    )
    pdf.body("Open http://localhost:5000 in your browser.")

    pdf.sub_title("Dashboard Features")
    pdf.bullet("Start/stop real-time monitoring from the web UI", bold_prefix="Controls:")
    pdf.bullet("Trigger baseline builds with one click", bold_prefix="Baseline:")
    pdf.bullet("Server-Sent Events (SSE) for real-time event feed", bold_prefix="Live Feed:")
    pdf.bullet("Browse past events with filtering", bold_prefix="History:")

    # ══════════════════════════════════════════════════════════════════════
    # 9. DOCKER COMPOSE
    # ══════════════════════════════════════════════════════════════════════
    pdf.section_title("9", "Docker Compose Deployment")

    pdf.body(
        "Deploy the complete ELK stack (Elasticsearch + Kibana) alongside the FIM monitor "
        "with a single command. No manual Elasticsearch installation needed."
    )

    pdf.sub_title("Quick Start")
    pdf.code_block(
        "# Create a directory for the FIM to monitor\n"
        "mkdir -p monitored\n"
        "\n"
        "# Start all 3 services\n"
        "docker compose up -d\n"
        "\n"
        "# Verify all services are running\n"
        "docker compose ps"
    )
    pdf.body("Expected output:")
    pdf.output_block(
        "NAME               STATUS                  PORTS\n"
        "fim-monitor        Up 2 minutes            \n"
        "fim-elasticsearch  Up 2 minutes (healthy)  0.0.0.0:9200->9200/tcp\n"
        "fim-kibana         Up 1 minute             0.0.0.0:5601->5601/tcp"
    )

    pdf.sub_title("View FIM Logs")
    pdf.code_block("docker compose logs -f fim")

    pdf.sub_title("Access Kibana")
    pdf.body(
        "Open http://localhost:5601 in your browser. "
        "Navigate to: Management > Stack Management > Index Patterns > "
        "Create index pattern: fim-events* > Then go to Discover to see events."
    )

    pdf.sub_title("Test It: Create a File Change")
    pdf.code_block(
        "# Create a test file in the monitored directory\n"
        "echo 'test content' > monitored/testfile.txt\n"
        "\n"
        "# Modify it\n"
        "echo 'changed' >> monitored/testfile.txt\n"
        "\n"
        "# The FIM should detect and log both events"
    )

    pdf.sub_title("Stop Everything")
    pdf.code_block(
        "docker compose down       # Stop containers, keep data\n"
        "docker compose down -v    # Stop + delete all data volumes"
    )

    # ══════════════════════════════════════════════════════════════════════
    # 10. TESTING
    # ══════════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("10", "Running Tests")

    pdf.body(
        "The project includes 62 pytest unit tests covering all core modules. "
        "Tests use temporary directories and isolated SQLite databases so "
        "no Elasticsearch or external services are needed to run them."
    )

    pdf.sub_title("Run All Tests")
    pdf.code_block("python3 -m pytest tests/ -v")
    pdf.body("Expected output:")
    pdf.output_block(
        "tests/test_alerter.py::TestShouldAlert::test_critical_triggers    PASSED\n"
        "tests/test_alerter.py::TestShouldAlert::test_ransomware_triggers  PASSED\n"
        "tests/test_correlator.py::TestRansomwareCorrelator::test_below..  PASSED\n"
        "tests/test_correlator.py::TestRansomwareCorrelator::test_at_th..  PASSED\n"
        "tests/test_database.py::TestDatabase::test_init_creates_table    PASSED\n"
        "tests/test_database.py::TestDatabase::test_upsert_and_get_hash   PASSED\n"
        "...    (62 tests total)\n"
        "\n"
        "============================== 62 passed in 6.30s ==================="
    )

    pdf.sub_title("Run Specific Module Tests")
    pdf.code_block(
        "python3 -m pytest tests/test_hasher.py -v       # SHA-256 tests\n"
        "python3 -m pytest tests/test_correlator.py -v   # Ransomware tests\n"
        "python3 -m pytest tests/test_database.py -v     # SQLite CRUD tests\n"
        "python3 -m pytest tests/test_forwarder.py -v    # Severity + ECS tests\n"
        "python3 -m pytest tests/test_alerter.py -v      # Alert filter tests"
    )

    pdf.sub_title("Test Coverage Summary")
    pdf.table_row3("Test File", "Module Tested", "# Tests", header=True)
    pdf.table_row3("test_hasher.py", "SHA-256 engine", "11")
    pdf.table_row3("test_correlator.py", "Ransomware detection", "6")
    pdf.table_row3("test_database.py", "SQLite CRUD ops", "10")
    pdf.table_row3("test_forwarder.py", "Severity + ECS docs", "21")
    pdf.table_row3("test_alerter.py", "Alert filtering", "9")
    pdf.ln(2)
    pdf.body("Total: 62 tests, all passing.")

    # ══════════════════════════════════════════════════════════════════════
    # 11. SYSTEMD
    # ══════════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("11", "Systemd Production Deployment")

    pdf.body(
        "For production Linux servers, run the FIM as a systemd service. "
        "The included fim.service file has security hardening (non-root user, "
        "read-only filesystem, restricted system calls)."
    )

    pdf.sub_title("Step 1: Create a Dedicated FIM User")
    pdf.code_block(
        "sudo useradd --system --no-create-home \\\n"
        "  --shell /usr/sbin/nologin fim"
    )
    pdf.body("Creates a system user with no login shell for security.")

    pdf.sub_title("Step 2: Install Application Files")
    pdf.code_block(
        "sudo mkdir -p /opt/fim /etc/fim /var/log/fim\n"
        "sudo cp *.py requirements.txt /opt/fim/\n"
        "sudo pip install -r /opt/fim/requirements.txt\n"
        "sudo chown -R fim:fim /opt/fim /var/log/fim"
    )

    pdf.sub_title("Step 3: Create Production Environment File")
    pdf.code_block(
        "sudo cp .env.example /etc/fim/fim.env\n"
        "sudo chmod 600 /etc/fim/fim.env     # Restrict access\n"
        "sudo nano /etc/fim/fim.env           # Set production values"
    )

    pdf.sub_title("Step 4: Install and Enable the Service")
    pdf.code_block(
        "sudo cp fim.service /etc/systemd/system/\n"
        "sudo systemctl daemon-reload\n"
        "sudo systemctl enable fim.service    # Start on boot\n"
        "sudo systemctl start fim.service     # Start now"
    )

    pdf.sub_title("Step 5: Verify Service Status")
    pdf.code_block("sudo systemctl status fim")
    pdf.body("Expected output:")
    pdf.output_block(
        "  fim.service - SIEM File Integrity Monitor\n"
        "     Active: active (running) since Wed 2026-03-18 14:30:00 UTC\n"
        "   Main PID: 12345 (python3)\n"
        "     Memory: 28.4M\n"
        "        CPU: 1.234s"
    )

    pdf.sub_title("View Live Logs")
    pdf.code_block("sudo journalctl -u fim -f")

    # ══════════════════════════════════════════════════════════════════════
    # 12. ARCHITECTURE
    # ══════════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("12", "Architecture & Module Reference")

    pdf.body(
        "The FIM is designed with a modular architecture. Each module has a single "
        "responsibility and can be independently tested, maintained, and extended."
    )

    pdf.sub_title("Data Flow")
    pdf.code_block(
        "  File Event (OS)  -->  monitor.py (watchdog)       \n"
        "       |                     |                       \n"
        "       v                     v                       \n"
        "  hasher.py          correlator.py                   \n"
        "  (SHA-256)          (ransomware check)              \n"
        "       |                     |                       \n"
        "       +----------+----------+                       \n"
        "                  |                                   \n"
        "                  v                                   \n"
        "           forwarder.py                               \n"
        "           (severity + ECS)                           \n"
        "                  |                                   \n"
        "         +--------+--------+                         \n"
        "         |                 |                          \n"
        "         v                 v                          \n"
        "   Elasticsearch      alerter.py                     \n"
        "   (SIEM/Kibana)   (email/webhook)                   "
    )

    pdf.sub_title("Module Reference")
    pdf.table_row("Module", "Responsibility", header=True)
    pdf.table_row("config.py", "All settings from environment variables")
    pdf.table_row("monitor.py", "CLI entry point, watchdog integration")
    pdf.table_row("hasher.py", "SHA-256 hashing with exclusion logic")
    pdf.table_row("database.py", "SQLite CRUD for baseline storage")
    pdf.table_row("forwarder.py", "ECS doc builder + ES shipper + fallback")
    pdf.table_row("correlator.py", "Ransomware sliding-window detection")
    pdf.table_row("alerter.py", "Email & webhook alert dispatch")
    pdf.table_row("tui.py", "Rich terminal UI components")
    pdf.table_row("dashboard.py", "Flask web GUI dashboard")

    # ══════════════════════════════════════════════════════════════════════
    # 13. COMPLIANCE
    # ══════════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("13", "Compliance Mapping")

    pdf.body(
        "File Integrity Monitoring is required by multiple security frameworks. "
        "This tool addresses the following compliance requirements:"
    )
    pdf.ln(2)

    pdf.table_row("Framework", "Requirement Addressed", header=True)
    pdf.table_row("PCI-DSS 11.5", "Monitor critical system files for changes")
    pdf.table_row("HIPAA 164.312(c)(1)", "Integrity controls for ePHI data")
    pdf.table_row("SOC 2 (CC6.1)", "Detect unauthorized system changes")
    pdf.table_row("NIST 800-53 (SI-7)", "Software & information integrity")
    pdf.table_row("CIS Controls (3.14)", "Log and alert on file changes")
    pdf.table_row("MITRE ATT&CK T1565", "Data manipulation detection")
    pdf.table_row("MITRE ATT&CK T1486", "Ransomware behavioral detection")
    pdf.ln(4)

    pdf.info_box("For Auditors:",
        "The tool generates ECS-compliant JSON documents with @timestamp, file.path, "
        "hash values, severity classification, and host identity for every detected "
        "change. All events are persisted (Elasticsearch or local log fallback) and "
        "can be queried for audit evidence."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 14. TROUBLESHOOTING
    # ══════════════════════════════════════════════════════════════════════
    pdf.section_title("14", "Troubleshooting")

    pdf.sub_title("Elasticsearch Connection Failed")
    pdf.body("Symptom: 'ES unavailable' warnings in logs.")
    pdf.bullet("Verify ES is running: curl http://localhost:9200")
    pdf.bullet("Check ES_HOST in .env matches your ES instance URL")
    pdf.bullet("If using Docker Compose, ensure the ES container is healthy")
    pdf.bullet("Events are NEVER lost - they fall back to fim.log automatically")

    pdf.sub_title("Permission Denied")
    pdf.body("Symptom: Cannot read files in /etc or /root")
    pdf.bullet("Run with elevated privileges: sudo python3 monitor.py --watch")
    pdf.bullet("Or deploy as systemd service (runs as dedicated 'fim' user)")

    pdf.sub_title("Rich TUI Not Showing")
    pdf.bullet("Install rich: pip install rich")
    pdf.bullet("Ensure terminal supports ANSI colors (not a dumb terminal)")
    pdf.bullet("SSH sessions: ensure TERM=xterm-256color is set")
    pdf.bullet("Use --no-tui for non-interactive environments")

    pdf.sub_title("Tests Failing")
    pdf.bullet("Ensure you are in the project root directory")
    pdf.bullet("Install pytest: pip install pytest")
    pdf.bullet("Run with verbose output: python3 -m pytest tests/ -v --tb=long")

    pdf.sub_title("Docker Issues")
    pdf.bullet("Docker daemon: sudo systemctl start docker")
    pdf.bullet("Port conflicts: lsof -i :9200 or lsof -i :5601")
    pdf.bullet("Container logs: docker compose logs elasticsearch")
    pdf.bullet("Reset everything: docker compose down -v && docker compose up -d")

    # ══════════════════════════════════════════════════════════════════════
    # Save
    # ══════════════════════════════════════════════════════════════════════
    pdf.output(OUTPUT)
    print(f"\n  PDF generated successfully: {OUTPUT}\n")


if __name__ == "__main__":
    build_pdf()

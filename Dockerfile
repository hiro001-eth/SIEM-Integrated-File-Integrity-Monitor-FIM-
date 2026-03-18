FROM python:3.12-slim

LABEL maintainer="Manjil"
LABEL description="SIEM-Integrated File Integrity Monitor"

WORKDIR /opt/fim

# Install dependencies first (layer caching optimisation)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY fim/ ./fim/
COPY monitor.py dashboard.py ./

# Default: watch mode with TUI disabled (daemon-friendly)
CMD ["python3", "monitor.py", "--watch", "--no-tui"]

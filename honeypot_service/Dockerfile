FROM python:3.11-slim

# Create non-root user (security)
RUN groupadd -r honeypot && useradd -r -g honeypot honeypot

WORKDIR /app

# Install minimal dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py sql_utils.py ./

# Create log directory
RUN mkdir -p /var/log/honeypot && chown honeypot:honeypot /var/log/honeypot

# Switch to non-root user
USER honeypot

EXPOSE 80

# Start via Gunicorn (bez dev-serwera Werkzeug)
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:80", "app:app", \
     "--access-logfile", "-", "--error-logfile", "-"]

FROM python:3.11-slim

# Create non-root user
RUN groupadd -r analytics && useradd -r -g analytics analytics

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && rm -rf /var/lib/apt/lists/*

# Copy and install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app.py ./

# Create log directory
RUN mkdir -p /var/log/analytics && chown analytics:analytics /var/log/analytics

# Switch to non-root user
USER analytics

EXPOSE 5000

# Start via Gunicorn (bez dev-serwera Werkzeug)
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app", \
     "--access-logfile", "-", "--error-logfile", "-"]

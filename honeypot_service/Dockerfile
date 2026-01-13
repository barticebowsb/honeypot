FROM python:3.11-slim

# Create non-root user (security)
RUN groupadd -r honeypot && useradd -r -g honeypot honeypot

WORKDIR /app

# Install minimal dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && rm -rf /var/lib/apt/lists/*

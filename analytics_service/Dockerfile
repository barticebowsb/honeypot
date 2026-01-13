FROM python:3.11-slim

# Create non-root user
RUN groupadd -r analytics && useradd -r -g analytics analytics

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && rm -rf /var/lib/apt/lists/*

# syntax: docker/dockerfile:1

# ============================================================
# Stage 1: Build dependencies
# ============================================================
FROM python:3.12-slim AS builder

WORKDIR /app

# Install build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy only dependency files first for layer caching
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt


# ============================================================
# Stage 2: Runtime image
# ============================================================
FROM python:3.12-slim AS runtime

LABEL maintainer="Apex-SOC Team"
LABEL description="Apex-SOC Backend API"

# Create non-root user for security
RUN groupadd -r apexsoc && useradd -r -g apexsoc apexsoc

WORKDIR /app

# Copy installed dependencies from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY --chown=apexsoc:apexsoc . .

# Drop to non-root
USER apexsoc

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--proxy-headers"]

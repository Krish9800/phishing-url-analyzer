# ==========================================
# Build Stage
# ==========================================
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefix=/install .

# ==========================================
# Runtime Stage
# ==========================================
FROM python:3.12-slim AS runtime

LABEL maintainer="Defensive Security Engineering" \
      version="0.1.0" \
      description="Phishing URL & Domain Threat Intelligence Analyzer Microservice"

# Create unprivileged service user and group
RUN groupadd -g 10001 phishuser && \
    useradd -u 10001 -g phishuser -s /sbin/nologin -M phishuser

WORKDIR /app

# Copy installed dependencies from builder
COPY --from=builder /install /usr/local
COPY --from=builder /build/src /app/src

# Set secure environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    PHISH_DEBUG=false

# Drop privileges to non-root user
USER phishuser:phishuser

EXPOSE 8000

# Health check verifies the live HTTP health probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

ENTRYPOINT ["uvicorn", "phish_analyzer.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

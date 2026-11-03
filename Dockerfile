# Multi-stage build for SentinelGate
FROM python:3.12-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Final stage
FROM python:3.12-slim

# Create non-root user
RUN useradd -m -u 1000 sentinel && \
    mkdir -p /app/logs /app/models && \
    chown -R sentinel:sentinel /app

WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /root/.local /home/sentinel/.local

# Copy application code
COPY --chown=sentinel:sentinel . .

# Switch to non-root user
USER sentinel

# Add .local/bin to PATH
ENV PATH=/home/sentinel/.local/bin:$PATH

# Expose ports
EXPOSE 8000 8501

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health', timeout=2)"

# Default command (gateway)
CMD ["python", "-m", "uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]

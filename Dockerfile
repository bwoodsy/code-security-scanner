# Build stage
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install poetry
RUN pip install --no-cache-dir poetry==1.8.0

# Copy dependency files
COPY pyproject.toml poetry.lock* ./

# Configure poetry to not create virtualenv and install dependencies
RUN poetry config virtualenvs.create false \
    && poetry install --only main --no-interaction --no-ansi

# Runtime stage
FROM python:3.11-slim AS runtime

WORKDIR /app

# Security: Create non-root user
RUN useradd --create-home --shell /bin/bash scanner \
    && mkdir -p /app /results \
    && chown -R scanner:scanner /app /results

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --chown=scanner:scanner src/ ./src/

# Switch to non-root user
USER scanner

# Set Python path
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -m securecode --version || exit 1

# Default entrypoint
ENTRYPOINT ["python", "-m", "securecode"]
CMD ["--help"]

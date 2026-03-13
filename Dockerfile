# Multi-stage build for mcp-security-scanner
# Stage 1: Build wheel
FROM python:3.11-slim as builder

WORKDIR /build
COPY . .

RUN python -m pip install --upgrade pip setuptools wheel && \
    python -m pip wheel --no-cache-dir --no-deps --wheel-dir /build/wheels .

# Stage 2: Runtime (distroless base)
FROM python:3.11-slim

WORKDIR /app

# Copy Python site-packages from builder
COPY --from=builder /build/wheels /wheels

# Install the wheel
RUN pip install --no-cache-dir /wheels/*.whl && \
    rm -rf /wheels

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=2 \
    CMD mcp-scan --version || exit 1

# Default command
ENTRYPOINT ["mcp-scan"]
CMD ["--help"]

# Labels
LABEL org.opencontainers.image.title="MCP Security Scanner"
LABEL org.opencontainers.image.description="Security scanner for Model Context Protocol (MCP) servers"
LABEL org.opencontainers.image.source="https://github.com/ogulcanaydogan/mcp-security-scanner"
LABEL org.opencontainers.image.licenses="Apache-2.0"

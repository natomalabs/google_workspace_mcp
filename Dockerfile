FROM us-docker.pkg.dev/natoma-ops/nms-images/mcp-bridge-streaming-dd:latest AS bridge
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv for faster dependency management
RUN pip install --no-cache-dir uv

COPY . .

# Install Python dependencies using uv sync
RUN uv sync --frozen --no-dev

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app

# Give read and write access to the store_creds volume
RUN mkdir -p /app/store_creds \
    && chown -R app:app /app/store_creds \
    && chmod 755 /app/store_creds

USER app

# Copy MCP bridge binaries
COPY --from=bridge /local/bin/mcp-bridge /local/bin/mcp-bridge
RUN chmod +x /local/bin/mcp-bridge || true
COPY --from=bridge /local/bin/datadog-init /local/bin/datadog-init
RUN chmod +x /local/bin/datadog-init || true
COPY --from=bridge /local/bin/run_bridge.sh /local/bin/run_bridge.sh
RUN chmod +x /local/bin/run_bridge.sh || true

# Ensure Smithery config is available
COPY smithery.yaml ./

EXPOSE 9090
ENTRYPOINT ["/local/bin/run_bridge.sh"]

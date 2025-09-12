# -------------------------------------------------------------
# Go MCP Proxy Server
# Includes:
#   • Go (for the proxy server)
#   • Node.js + npm (for npx MCP servers)
#   • Python 3 + uv (for Python MCP servers)
# -------------------------------------------------------------
FROM golang:1.23-bookworm AS builder

# Use the repository root as workspace so the local
# `replace ../../../` path resolves correctly during build.
WORKDIR /workspace

# Copy the entire repository into the builder's workspace.
# Build context MUST be the repo root for this to work.
COPY . /workspace

# Switch to the example app directory
WORKDIR /workspace/examples/server/cloudmcp-session-auth

# Download dependencies (uses local replace to the repo contents)
RUN go mod download

# Build the Go application
RUN CGO_ENABLED=0 GOOS=linux go build -o mcp-proxy-server .

# -------------------------------------------------------------
# Runtime image with Go binary and required tools
# -------------------------------------------------------------
FROM debian:bookworm-slim

ARG NODE_MAJOR=22

ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# 1. Core OS packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        tar \
        xz-utils \
        gzip \
        gnupg \
        python3 \
        git \
        python3-venv && \
    rm -rf /var/lib/apt/lists/*

# 2. Node.js (+npm) for npx MCP servers
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - && \
    apt-get update && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# 3. pnpm (optional, for faster package management)
RUN npm install -g pnpm

# 4. uv (Python package installer) for Python MCP servers
RUN curl -Ls https://astral.sh/uv/install.sh | bash && \
    install -Dm755 /root/.local/bin/uv /usr/local/bin/uv

# 5. Final cleanup
RUN apt-get autoremove -y && \
    apt-get clean

# Create app directory
WORKDIR /app

# Copy the Go binary from builder
COPY --from=builder /workspace/examples/server/cloudmcp-session-auth/mcp-proxy-server /app/mcp-proxy-server

# Make binary executable
RUN chmod +x /app/mcp-proxy-server

# Create a non-root user to run the app
RUN useradd -m -u 1001 mcpuser && \
    chown -R mcpuser:mcpuser /app

# Switch to non-root user
USER mcpuser

# Expose port (default 8080)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/healthcheck || exit 1

# Start the application
CMD ["/app/mcp-proxy-server"]

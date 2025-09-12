#!/bin/bash
set -euo pipefail

# Ensure Docker is authenticated to Fly.io registry
fly auth docker

# Build with the repository root as context so the Dockerfile can
# access the local go-sdk via the replace path.
ROOT_DIR="$(git rev-parse --show-toplevel)"
DOCKERFILE_PATH="$ROOT_DIR/examples/server/cloudmcp-session-auth/Dockerfile"

docker build \
  --platform linux/amd64 \
  --push \
  -t registry.fly.io/mcp-manager:latest \
  -f "$DOCKERFILE_PATH" \
  "$ROOT_DIR"

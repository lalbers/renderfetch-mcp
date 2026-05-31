#!/usr/bin/env bash
# Build the renderfetch-mcp container image.
#   ./build.sh            -> localhost/renderfetch-mcp:latest
#   IMAGE=foo ./build.sh  -> custom tag
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="${IMAGE:-localhost/renderfetch-mcp:latest}"

echo "Building ${IMAGE} ..."
podman build -t "${IMAGE}" -f Containerfile .

echo
echo "Built ${IMAGE}."
echo "Start/restart via compose, the Quadlet unit, or podman run (see README)."
echo "For the Quadlet service:  systemctl --user restart renderfetch-mcp"

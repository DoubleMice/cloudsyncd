#!/bin/bash
set -e

PORT="${PORT:-21891}"
TUNNEL_CONFIG="${TUNNEL_CONFIG:-cloudflared-config.yml}"

echo "Starting cloudsyncd on port ${PORT}..."

# Optional: also bring up the Cloudflare Tunnel so the public hostname is live.
# Run as: WITH_TUNNEL=1 ./start.sh   (tunnel runs in the background, logs to /tmp/cloudflared-sync.log)
if [ "${WITH_TUNNEL:-0}" = "1" ]; then
  if ! command -v cloudflared >/dev/null 2>&1; then
    echo "WITH_TUNNEL=1 but cloudflared is not installed; skipping tunnel." >&2
  else
    echo "Starting Cloudflare Tunnel (sync) in the background..."
    cloudflared tunnel --config "$TUNNEL_CONFIG" run sync > /tmp/cloudflared-sync.log 2>&1 &
    TUNNEL_PID=$!
    echo "  tunnel pid: $TUNNEL_PID  (logs: /tmp/cloudflared-sync.log)"
    trap 'kill $TUNNEL_PID 2>/dev/null || true' EXIT
  fi
fi

node server.js

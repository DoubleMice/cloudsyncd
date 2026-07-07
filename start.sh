#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-21891}"
TUNNEL_CONFIG="${TUNNEL_CONFIG:-$SCRIPT_DIR/cloudflared-config.yml}"
TUNNEL_PIDFILE="${TUNNEL_PIDFILE:-/tmp/cloudflared-sync.pid}"
TUNNEL_LOGFILE="${TUNNEL_LOGFILE:-/tmp/cloudflared-sync.log}"

echo "Starting cloudsyncd on port ${PORT}..."

# Compatibility path. Prefer: cloudsyncd server start --tunnel
# Run as: WITH_TUNNEL=1 ./start.sh   (tunnel runs in the background, logs to /tmp/cloudflared-sync.log)
if [ "${WITH_TUNNEL:-0}" = "1" ]; then
  if ! command -v cloudflared >/dev/null 2>&1; then
    echo "WITH_TUNNEL=1 but cloudflared is not installed; skipping tunnel." >&2
  else
    echo "Starting Cloudflare Tunnel from config in the background..."
    TUNNEL_ARGS=(tunnel --config "$TUNNEL_CONFIG" --pidfile "$TUNNEL_PIDFILE" run)
    if [ -n "${TUNNEL_NAME:-}" ]; then
      TUNNEL_ARGS+=("$TUNNEL_NAME")
    fi
    cloudflared "${TUNNEL_ARGS[@]}" > "$TUNNEL_LOGFILE" 2>&1 &
    TUNNEL_PID=$!
    echo "$TUNNEL_PID" > "$TUNNEL_PIDFILE"
    echo "  tunnel pid: $TUNNEL_PID  (pidfile: $TUNNEL_PIDFILE, logs: $TUNNEL_LOGFILE)"
    trap 'kill $TUNNEL_PID 2>/dev/null || true; rm -f "$TUNNEL_PIDFILE"' EXIT
  fi
fi

cd "$SCRIPT_DIR"
node "$SCRIPT_DIR/server.js"

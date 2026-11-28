#!/bin/sh
set -eu

KEY_SRC="/run/secrets/callback_ssh_key"
KEY_TMP="/tmp/id_key"
KNOWN_HOSTS_SRC="/run/secrets/callback_known_hosts"
KNOWN_HOSTS_TMP="/tmp/known_hosts"
CONFIG_FILE="/tmp/ssh_relay_config"
CTL_PATH="/tmp/ssh-relay.ctl"

log() {
  printf '[callback-relay] %s\n' "$*" >&2
}

if [ ! -f "$KEY_SRC" ] || [ ! -s "$KEY_SRC" ]; then
  log "ERROR: SSH private key missing at $KEY_SRC (set CALLBACK_SSH_KEY_FILE or place key at ./deploy/private/callback_id_ed25519)"
  exit 1
fi

rm -f "$KEY_TMP" "$KNOWN_HOSTS_TMP" "$CONFIG_FILE" "$CTL_PATH"
cp "$KEY_SRC" "$KEY_TMP"
chmod 0600 "$KEY_TMP"

if [ -f "$KNOWN_HOSTS_SRC" ] && [ -s "$KNOWN_HOSTS_SRC" ]; then
  cp "$KNOWN_HOSTS_SRC" "$KNOWN_HOSTS_TMP"
  chmod 0600 "$KNOWN_HOSTS_TMP"
fi

python3 /usr/local/lib/artex-callback/render_relay.py \
  --config-out "$CONFIG_FILE" \
  --key-file "$KEY_TMP" \
  --known-hosts "$KNOWN_HOSTS_TMP" \
  --control-path "$CTL_PATH"

STOP=0
SSH_PID=""

handle_signal() {
  STOP=1
  if [ -n "$SSH_PID" ]; then
    kill -TERM "$SSH_PID" 2>/dev/null || true
  fi
}

trap handle_signal INT TERM

backoff=2
while [ "$STOP" = 0 ]; do
  rm -f "$CTL_PATH"
  started_at=$(date +%s)
  log "opening SSH reverse tunnel..."
  ssh -NT -F "$CONFIG_FILE" relay &
  SSH_PID=$!
  rc=0
  wait "$SSH_PID" || rc=$?
  SSH_PID=""
  rm -f "$CTL_PATH"

  [ "$STOP" = 1 ] && break

  now=$(date +%s)
  elapsed=$((now - started_at))
  if [ "$elapsed" -ge 30 ]; then
    backoff=2
  fi
  log "SSH tunnel exited (code=$rc); reconnecting in ${backoff}s..."
  sleep "$backoff" &
  wait $! || true
  if [ "$backoff" -lt 30 ]; then
    backoff=$((backoff * 2))
    [ "$backoff" -gt 30 ] && backoff=30
  fi
done

log "stopped cleanly"

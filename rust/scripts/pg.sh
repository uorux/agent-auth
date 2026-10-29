#!/usr/bin/env bash
# A throwaway local Postgres for development and tests: lives under
# target/pg, listens on a unix socket there and on 127.0.0.1 (a port derived
# from the checkout's path), trusts local connections. Never for anything real.
#
#   scripts/pg.sh start   # prints the DATABASE_URL to export
#   scripts/pg.sh stop
#   scripts/pg.sh url
set -euo pipefail
cd "$(dirname "$0")/.."
DIR="$PWD/target/pg"
# One server per checkout (worktrees run side by side): the port is derived
# from this directory unless PGPORT_AGENT_AUTH is set.
PORT="${PGPORT_AGENT_AUTH:-$((54000 + $(printf '%s' "$PWD" | cksum | cut -d' ' -f1) % 900))}"
URL="postgres://agent_auth@127.0.0.1:$PORT/agent_auth"

# Sandboxes and containers may run us under a uid with no passwd entry, which
# initdb refuses; give it one through nss_wrapper when that is the case.
if ! getent passwd "$(id -u)" >/dev/null 2>&1 && [ -n "${NSS_WRAPPER_LIB:-}" ]; then
  mkdir -p "$DIR"
  echo "agent_auth:x:$(id -u):$(id -g):pg:$DIR:/bin/sh" > "$DIR/passwd"
  echo "agent_auth:x:$(id -g):" > "$DIR/group"
  export LD_PRELOAD="$NSS_WRAPPER_LIB" NSS_WRAPPER_PASSWD="$DIR/passwd" NSS_WRAPPER_GROUP="$DIR/group"
fi

case "${1:-start}" in
  start)
    if [ ! -d "$DIR/data" ]; then
      mkdir -p "$DIR"
      initdb -D "$DIR/data" -U agent_auth --auth=trust --no-instructions >/dev/null
    fi
    if ! pg_ctl -D "$DIR/data" status >/dev/null 2>&1; then
      pg_ctl -D "$DIR/data" -l "$DIR/log" -w start \
        -o "-k $DIR -p $PORT -c listen_addresses=127.0.0.1 -c fsync=off -c max_connections=400" >/dev/null
    fi
    psql -h "$DIR" -p "$PORT" -U agent_auth -d postgres -tAc \
      "SELECT 1 FROM pg_database WHERE datname='agent_auth'" | grep -q 1 \
      || createdb -h "$DIR" -p "$PORT" -U agent_auth agent_auth
    echo "$URL"
    ;;
  stop) pg_ctl -D "$DIR/data" -w stop >/dev/null || true ;;
  url) echo "$URL" ;;
  *) echo "usage: $0 start|stop|url" >&2; exit 2 ;;
esac

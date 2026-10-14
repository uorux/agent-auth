#!/bin/bash
# Install or upgrade hostd on a Mac without nix (docs/hostd-macos.md).
#
#   sudo deploy/macos/install.sh /path/to/agent-auth-checkout
#
# Everything hostd runs from, and its config (which is the host's local
# policy), ends up owned by root and writable by no one else: hostd is root,
# so any file of it the user could change is a way for whatever runs as the
# user (the agents) to become root. That is also why Python comes from uv
# into /opt/agent-auth and not from Homebrew, whose files are the user's.
#
# It pairs nothing and enrolls nothing: that is `agent-auth-hostd pair` and
# `totp-enroll`, typed by you afterwards.
set -euo pipefail

PREFIX=/opt/agent-auth
CONFIG_DIR=/etc/agent-auth
LABEL=dev.agent-auth.hostd
HERE="$(cd "$(dirname "$0")" && pwd)"

die() { echo "install.sh: $*" >&2; exit 1; }

[ "$(uname -s)" = Darwin ] || die "this is for macOS"
[ "$(id -u)" = 0 ] || die "run it with sudo"
SRC="${1:-}"
[ -n "$SRC" ] && [ -f "$SRC/pyproject.toml" ] || die "usage: sudo $0 /path/to/agent-auth-checkout"
UV="$(command -v uv || true)"
[ -n "$UV" ] || die "uv not found (https://docs.astral.sh/uv/; brew install uv works)"

install -d -o root -g wheel -m 0755 "$PREFIX"

# uv's Python, cache and the venv all under the root-owned prefix.
export UV_PYTHON_INSTALL_DIR="$PREFIX/python"
export UV_CACHE_DIR="$PREFIX/.uv-cache"
export UV_PYTHON_PREFERENCE=only-managed
"$UV" venv --allow-existing --python 3.13 "$PREFIX/venv"
# Not editable: the venv must not run code from your checkout.
"$UV" pip install --python "$PREFIX/venv/bin/python" --reinstall-package agent-auth "$SRC"

chown -R root:wheel "$PREFIX"
chmod -R go-w "$PREFIX"
if [ -n "$(find "$PREFIX" ! -user root -print -quit)" ]; then
  die "something under $PREFIX is not root's"
fi

install -d -o root -g wheel -m 0755 "$CONFIG_DIR"
if [ ! -e "$CONFIG_DIR/hostd.json" ]; then
  install -o root -g wheel -m 0644 "$HERE/hostd.example.json" "$CONFIG_DIR/hostd.json"
  echo "Wrote $CONFIG_DIR/hostd.json from the example. Edit it (sudo), then run this again."
  exit 0
fi
chown root:wheel "$CONFIG_DIR/hostd.json"
chmod 0644 "$CONFIG_DIR/hostd.json"
if grep -q REPLACE_ "$CONFIG_DIR/hostd.json"; then
  die "$CONFIG_DIR/hostd.json still has REPLACE_ placeholders"
fi
# The config must load as hostd will load it.
"$PREFIX/venv/bin/python" -I -c 'import sys; from agent_auth.hostd.config import HostConfig; HostConfig.load(sys.argv[1])' \
  "$CONFIG_DIR/hostd.json" || die "$CONFIG_DIR/hostd.json does not load"

install -o root -g wheel -m 0644 "$HERE/$LABEL.plist" "/Library/LaunchDaemons/$LABEL.plist"
launchctl bootout "system/$LABEL" 2>/dev/null || true
launchctl bootstrap system "/Library/LaunchDaemons/$LABEL.plist"
echo "hostd: loaded (log: /var/log/agent-auth-hostd.log)"

desktop="$("$PREFIX/venv/bin/python" -I -c 'import json, sys; print(bool((json.load(open(sys.argv[1])).get("desktop") or {}).get("enable")))' "$CONFIG_DIR/hostd.json")"
if [ "$desktop" = True ]; then
  install -o root -g wheel -m 0644 "$HERE/$LABEL-user.plist" "/Library/LaunchAgents/$LABEL-user.plist"
  if [ -n "${SUDO_UID:-}" ] && launchctl print "gui/$SUDO_UID" >/dev/null 2>&1; then
    launchctl bootout "gui/$SUDO_UID/$LABEL-user" 2>/dev/null || true
    launchctl bootstrap "gui/$SUDO_UID" "/Library/LaunchAgents/$LABEL-user.plist"
    echo "hostd-user: loaded in your session"
  else
    echo "hostd-user: installed; it starts at your next login"
  fi
else
  rm -f "/Library/LaunchAgents/$LABEL-user.plist"
fi

if [ ! -e /var/db/agent-auth-hostd/paired.json ]; then
  cat <<EOF

Not paired yet. On the broker:   agent-auth admin daemon-pair <name in hostd.json>
Then here (it prompts for the code):
  sudo $PREFIX/venv/bin/agent-auth-hostd pair --config $CONFIG_DIR/hostd.json
  sudo $PREFIX/venv/bin/agent-auth-hostd totp-enroll --config $CONFIG_DIR/hostd.json
  sudo launchctl kickstart -k system/$LABEL
EOF
fi

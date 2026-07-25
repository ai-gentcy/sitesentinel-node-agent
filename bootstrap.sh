#!/bin/sh
# Site Sentinel node agent — one-command install, no git required:
#
#   wget -qO- https://raw.githubusercontent.com/ai-gentcy/sitesentinel-node-agent/main/bootstrap.sh | sudo sh
#
# Downloads the latest agent tarball (wget or curl, whichever is present),
# extracts it to a temp dir and runs install.sh, which prints the node's
# registration hash at the end.
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root — pipe into 'sudo sh'" >&2
  exit 1
fi

URL="https://github.com/ai-gentcy/sitesentinel-node-agent/archive/refs/heads/main.tar.gz"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if command -v wget >/dev/null 2>&1; then
  wget -qO "$TMP/agent.tar.gz" "$URL"
elif command -v curl >/dev/null 2>&1; then
  curl -fsSL -o "$TMP/agent.tar.gz" "$URL"
else
  echo "need wget or curl" >&2
  exit 1
fi

tar -xzf "$TMP/agent.tar.gz" -C "$TMP"
cd "$TMP"/sitesentinel-node-agent-*
sh ./install.sh

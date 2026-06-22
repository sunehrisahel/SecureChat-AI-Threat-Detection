#!/usr/bin/env bash
# Copy the detector package into this app for Vercel serverless (root dir = chatbot/).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/../prompt-injection-detector"
DEST="$ROOT/bundled_detector"

if [[ ! -d "$SRC/app" ]]; then
  echo "bundle_detector: prompt-injection-detector not found at $SRC" >&2
  exit 1
fi

rm -rf "$DEST"
mkdir -p "$DEST"
cp -R "$SRC/app" "$DEST/app"
if [[ -d "$SRC/models" ]]; then
  cp -R "$SRC/models" "$DEST/models"
fi
echo "bundle_detector: bundled $(du -sh "$DEST" | cut -f1) into $DEST"

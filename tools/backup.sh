#!/bin/bash
# Backup CES server snapshot files from Hetzner.
# Copies the latest .snapshot files from each store.
# Safe to run while the server is running — snapshots are
# written atomically (temp file + rename).

set -e

SERVER="root@65.21.135.25"
REMOTE_DATA="/opt/ces/data"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOCAL_BACKUP="$SCRIPT_DIR/../local/backups"

mkdir -p "$LOCAL_BACKUP"

TIMESTAMP=$(date -u +%Y%m%d_%H%M%S)
DEST="$LOCAL_BACKUP/$TIMESTAMP"
mkdir -p "$DEST/accounts" "$DEST/assets"

echo "Backing up CES snapshots to $DEST ..."

# Copy latest snapshot from each store
for store in accounts assets; do
  # Find the latest .snapshot file (by name, they're timestamp-ordered)
  LATEST=$(ssh "$SERVER" "ls -1 $REMOTE_DATA/$store/*.snapshot 2>/dev/null | tail -1")
  if [ -z "$LATEST" ]; then
    echo "  $store: no snapshot found, skipping"
    continue
  fi
  echo "  $store: $LATEST"
  rsync -az "$SERVER:$LATEST" "$DEST/$store/"
done

# Also grab the server config (no private key in the backup name, just the file)
rsync -az "$SERVER:/opt/ces/server.toml" "$DEST/"

echo "Done. Backup at: $DEST"
ls -lhR "$DEST"

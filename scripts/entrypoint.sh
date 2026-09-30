#!/bin/sh
# Seed bundled default data into the mounted volume on first run, then exec the
# server. The vortex_data volume mounts over /app/vortex_db and hides files
# baked into the image, so any bundled default (e.g. the offline blocklist)
# must be copied into the volume when absent. Never overwrites existing files.
set -e

SEED_DIR="/app/seed/lists"
DEST_DIR="/app/vortex_db/lists"

mkdir -p "$DEST_DIR"
if [ -d "$SEED_DIR" ]; then
    for f in "$SEED_DIR"/*; do
        [ -e "$f" ] || continue
        base=$(basename "$f")
        if [ ! -e "$DEST_DIR/$base" ]; then
            cp "$f" "$DEST_DIR/$base"
            echo "[Entrypoint] Seeded blocklist $base into volume"
        fi
    done
fi

exec ./vortexdns "$@"

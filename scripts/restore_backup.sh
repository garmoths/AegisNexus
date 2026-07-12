#!/usr/bin/env bash
set -euo pipefail

# Reassemble the split backup archive and import into SQLite.
# Usage: ./scripts/restore_backup.sh

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PARTS=("$REPO_ROOT"/backup.sql.gz.part.*)
COMBINED="/tmp/backup_combined.sql.gz"

echo "Reassembling backup parts..."
cat "${PARTS[@]}" > "$COMBINED"

echo "Importing into SQLite..."
python "$REPO_ROOT/scripts/import_pg_dump.py" "$COMBINED"

rm -f "$COMBINED"
echo "Done!"

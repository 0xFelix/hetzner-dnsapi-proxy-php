#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 <rclone-remote> <remote-path>"
    echo
    echo "  rclone-remote  Configured rclone remote name"
    echo "  remote-path    Absolute path on the remote server"
    echo
    echo "Example: $0 myhost /home/user/dnsapi"
    exit 1
}

if [ $# -ne 2 ]; then
    usage
fi

HOST="$1"
REMOTE_PATH="$2"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Verify prerequisites
if ! command -v rclone >/dev/null 2>&1; then
    echo "Error: rclone not found. Install from https://rclone.org/" >&2
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/vendor/autoload.php" ]; then
    echo "Error: vendor/ not found. Run 'composer install --no-dev' first." >&2
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/config.php" ]; then
    echo "Error: config.php not found. Copy config.sample.php and configure it." >&2
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/data/public_suffix_list.dat" ]; then
    echo "Error: data/public_suffix_list.dat not found. Run 'composer run update-psl'." >&2
    exit 1
fi

# Verify config.php does not contain sample values
if grep -q 'YOUR_HETZNER_CLOUD_API_TOKEN' "$SCRIPT_DIR/config.php"; then
    echo "Error: config.php still contains placeholder token." >&2
    exit 1
fi

REMOTE="$HOST:$REMOTE_PATH"

echo "Deploying to $REMOTE ..."

# Sync only the files needed for production
rclone sync "$SCRIPT_DIR/" "$REMOTE" \
    --filter="+ .htaccess" \
    --filter="+ config.php" \
    --filter="+ data/public_suffix_list.dat" \
    --filter="+ public/**" \
    --filter="+ src/**" \
    --filter="+ vendor/**" \
    --filter="- *" \
    --progress

echo "Done. Verify at your configured URL."

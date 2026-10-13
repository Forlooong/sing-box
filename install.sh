#!/bin/sh
# Install from an inspected checkout or checksum-verified explicit release.
set -eu
if [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' 'Run as root on Debian 12/13 or Ubuntu 24.04.' >&2
    exit 1
fi
SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ ! -f "$SOURCE/sbmanager/cli.py" ] || [ ! -f "$SOURCE/versions.json" ]; then
    printf '%s\n' 'Download and inspect the complete release package first.' >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Install the distribution python3 and python3-yaml packages first.' >&2
    exit 1
fi
python3 -c 'import sys; assert sys.version_info >= (3,11); import yaml' || {
    printf '%s\n' 'Python >=3.11 and python3-yaml are required.' >&2
    exit 1
}
cd "$SOURCE"
export PYTHONDONTWRITEBYTECODE=1
case "${1:-}" in
    migrate) shift; exec python3 -m sbmanager.cli migrate apply "$@" ;;
    --help|-h) exec python3 -m sbmanager.cli install --help ;;
    *) exec python3 -m sbmanager.cli install "$@" ;;
esac

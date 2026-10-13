#!/bin/sh
# Managed Forlooong stack; src/ is retained only for attribution/migration.
set -eu
cd /opt/sb/current
export PYTHONDONTWRITEBYTECODE=1
exec /usr/bin/python3 -m sbmanager.cli "$@"

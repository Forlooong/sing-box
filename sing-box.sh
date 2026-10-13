#!/bin/sh
# Managed Forlooong stack; src/ is retained only for attribution/migration.
set -eu
# Recovery must run before cd/imports: current may contain an interrupted update.
previous=
for argument do
    if [ "$previous" = transaction ] && [ "$argument" = recover ]; then
        exec "$(dirname "$0")/sb-recover" "$@"
    fi
    previous=$argument
done
cd /opt/sb/current
export PYTHONDONTWRITEBYTECODE=1
exec /usr/bin/python3 -m sbmanager.cli "$@"

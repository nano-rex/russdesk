#!/bin/sh
# Kept for older instructions: everything now lives in ../russdesk.sh.
#   sudo ./deploy/install.sh [options]        = sudo sh russdesk.sh install [options]
#   sudo ./deploy/install.sh --uninstall      = sudo sh russdesk.sh uninstall
set -eu
script="$(cd "$(dirname "$0")/.." && pwd)/russdesk.sh"
for arg in "$@"; do
    if [ "$arg" = "--uninstall" ]; then
        exec sh "$script" uninstall --yes
    fi
done
exec sh "$script" install --yes "$@"

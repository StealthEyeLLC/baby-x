#!/usr/bin/env bash
set -euo pipefail
prefix=${1:-bx-disposable-}
machinectl list --no-legend --no-pager | awk '{print $1}' | grep "^$prefix" | while read -r machine; do machinectl terminate "$machine" || true; machinectl remove "$machine" || true; done

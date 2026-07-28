#!/usr/bin/env bash
set -euo pipefail

lane=
arguments=()
while (($# > 0)); do
  if [[ "$1" == --lane ]]; then
    (($# >= 2)) || { echo '--lane requires a value' >&2; exit 64; }
    lane=$2
    shift 2
  else
    arguments+=("$1")
    shift
  fi
done

if [[ "$lane" != fast ]]; then
  echo 'DEEP_CERTIFICATION_REQUIRED: pass --lane fast only with explicit operator authorization' >&2
  exit 42
fi

exec "$(dirname "$0")/deploy-fast.sh" "${arguments[@]}" --allow-critical-fast 1

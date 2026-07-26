#!/bin/sh
set -eu

: "${CREDENTIALS_DIRECTORY:?CREDENTIALS_DIRECTORY is required}"
: "${BABYX_CREDENTIAL_MAP:?BABYX_CREDENTIAL_MAP is required}"

old_ifs=$IFS
IFS=,
for mapping in $BABYX_CREDENTIAL_MAP; do
  case "$mapping" in
    *:*) environment_name=${mapping%%:*}; credential_name=${mapping#*:} ;;
    *) exit 64 ;;
  esac
  case "$environment_name" in
    ''|*[!A-Z0-9_]*) exit 64 ;;
  esac
  case "$credential_name" in
    ''|*[!A-Za-z0-9_.-]*) exit 64 ;;
  esac
  credential_path=$CREDENTIALS_DIRECTORY/$credential_name
  [ -f "$credential_path" ] || exit 66
  [ ! -L "$credential_path" ] || exit 66
  credential_value=$(cat -- "$credential_path")
  export "$environment_name=$credential_value"
  unset credential_value
 done
IFS=$old_ifs
unset BABYX_CREDENTIAL_MAP environment_name credential_name credential_path mapping old_ifs
exec "$@"

#!/usr/bin/env bash
set -euo pipefail

exec "$(dirname "$0")/../ops/deploy-fast.sh" \
  --repository "${BABY_X_REPOSITORY:-StealthEyeLLC/baby-x}" \
  --ref "${BABY_X_REF:?BABY_X_REF is required}" \
  --commit "${BABY_X_EXPECTED_COMMIT:?BABY_X_EXPECTED_COMMIT is required}" \
  --tree "${BABY_X_EXPECTED_TREE:?BABY_X_EXPECTED_TREE is required}" \
  --expected-current "${BABY_X_EXPECTED_CURRENT_COMMIT:?BABY_X_EXPECTED_CURRENT_COMMIT is required}" \
  --expected-current-tree "${BABY_X_EXPECTED_CURRENT_TREE:?BABY_X_EXPECTED_CURRENT_TREE is required}" \
  --reason "${BABY_X_DEPLOYMENT_REASON:?BABY_X_DEPLOYMENT_REASON is required}"

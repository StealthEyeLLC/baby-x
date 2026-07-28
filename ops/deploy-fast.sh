#!/usr/bin/env bash
set -euo pipefail

node_bin=/opt/node-v24.18.0-linux-x64/bin/node
npm_bin=/opt/node-v24.18.0-linux-x64/bin/npm
git_bin=/usr/bin/git
repository=
ref=
commit=
tree=
expected_current=
expected_current_tree=
reason=
allow_critical_fast=0

while (($# > 0)); do
  case "$1" in
    --repository|--ref|--commit|--tree|--expected-current|--expected-current-tree|--reason|--allow-critical-fast)
      (($# >= 2)) || { echo "$1 requires a value" >&2; exit 64; }
      name=${1#--}
      name=${name//-/_}
      printf -v "$name" '%s' "$2"
      shift 2
      ;;
    *) echo "unsupported deployment argument: $1" >&2; exit 64 ;;
  esac
done

[[ $(id -u) == 0 ]] || { echo 'STATUS=BLOCKED ERROR=root_authority_required' >&2; exit 1; }
[[ "$repository" == StealthEyeLLC/baby-x ]] || { echo 'STATUS=BLOCKED ERROR=repository_identity_mismatch' >&2; exit 1; }
[[ "$ref" == build/baby-x-transactional-root-authority-k-deployment-v1 ]] || { echo 'STATUS=BLOCKED ERROR=ref_identity_mismatch' >&2; exit 1; }
[[ "$commit" =~ ^[a-f0-9]{40}$ && "$tree" =~ ^[a-f0-9]{40}$ ]] || { echo 'STATUS=BLOCKED ERROR=candidate_identity_invalid' >&2; exit 1; }
[[ "$expected_current" =~ ^[a-f0-9]{40}$ && "$expected_current_tree" =~ ^[a-f0-9]{40}$ ]] || { echo 'STATUS=BLOCKED ERROR=expected_current_identity_invalid' >&2; exit 1; }
[[ ${#reason} -ge 8 && ${#reason} -le 512 ]] || { echo 'STATUS=BLOCKED ERROR=deployment_reason_invalid' >&2; exit 1; }
[[ -x "$node_bin" && -x "$npm_bin" && -x "$git_bin" ]] || { echo 'STATUS=BLOCKED ERROR=toolchain_unavailable' >&2; exit 1; }
[[ "$("$node_bin" --version)" == v24.18.0 ]] || { echo 'STATUS=BLOCKED ERROR=node_identity_mismatch' >&2; exit 1; }
[[ "$("$npm_bin" --version)" == 11.16.0 ]] || { echo 'STATUS=BLOCKED ERROR=npm_identity_mismatch' >&2; exit 1; }

for credential_name in GITHUB_TOKEN GH_TOKEN GITLAB_TOKEN; do
  [[ ! ${!credential_name+x} ]] || { echo "STATUS=BLOCKED ERROR=credential_environment_present NAME=$credential_name" >&2; exit 1; }
done

source_root=$("$git_bin" rev-parse --show-toplevel)
[[ "$("$git_bin" -C "$source_root" remote get-url origin)" == https://github.com/StealthEyeLLC/baby-x.git ]] \
  || { echo 'STATUS=BLOCKED ERROR=credential_free_remote_required' >&2; exit 1; }
[[ -z "$("$git_bin" -C "$source_root" status --porcelain --untracked-files=all)" ]] \
  || { echo 'STATUS=BLOCKED ERROR=dirty_source_workspace' >&2; exit 1; }
[[ "$("$git_bin" -C "$source_root" rev-parse HEAD)" == "$commit" ]] \
  || { echo 'STATUS=BLOCKED ERROR=local_commit_mismatch' >&2; exit 1; }
[[ "$("$git_bin" -C "$source_root" rev-parse 'HEAD^{tree}')" == "$tree" ]] \
  || { echo 'STATUS=BLOCKED ERROR=local_tree_mismatch' >&2; exit 1; }
parent=$("$git_bin" -C "$source_root" rev-parse HEAD^)
[[ "$parent" == 09ed66a470d8430fc5a1db118ce24cb4913b5cc6 ]] \
  || { echo 'STATUS=BLOCKED ERROR=checkpoint_parent_mismatch' >&2; exit 1; }

remote_commit=$("$git_bin" ls-remote --exit-code git@github.com:StealthEyeLLC/baby-x.git "refs/heads/$ref" | /usr/bin/awk 'NR == 1 { print $1 }')
[[ "$remote_commit" == "$commit" ]] || { echo 'STATUS=BLOCKED ERROR=remote_ref_mismatch' >&2; exit 1; }
"$git_bin" -C "$source_root" diff --check "$parent" "$commit"
"$git_bin" -C "$source_root" diff --quiet "$parent" "$commit" -- package-lock.json \
  || { echo 'STATUS=BLOCKED ERROR=fast_lane_lockfile_change' >&2; exit 1; }

mapfile -t changed_paths < <("$git_bin" -C "$source_root" diff --name-only "$parent" "$commit")
set +e
critical_report=$("$node_bin" "$source_root/scripts/critical-paths.mjs" "$source_root/ops/fast-lane-critical-paths.json" "${changed_paths[@]}")
critical_status=$?
set -e
if ((critical_status != 0 && critical_status != 42)); then
  echo 'STATUS=BLOCKED ERROR=critical_path_routing_failed' >&2
  exit 1
fi
if ((critical_status == 42)) && [[ "$allow_critical_fast" != 1 ]]; then
  printf 'DEEP_CERTIFICATION_REQUIRED %s\n' "$critical_report" >&2
  exit 42
fi

exec 9>/run/lock/baby-x-deploy.lock
flock -n -x 9 || { echo 'STATUS=BLOCKED ERROR=deployment_lock_busy' >&2; exit 1; }

PATH=/opt/node-v24.18.0-linux-x64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
cd "$source_root"
"$npm_bin" run build
"$npm_bin" run lint
"$node_bin" --test \
  runtime/test/checkpoint-k-deployment.test.mjs \
  runtime/test/root-authority-h-observability.test.mjs \
  runtime/test/root-authority-i-credentials.test.mjs \
  runtime/test/root-authority-j-recovery.test.mjs \
  gateway/test/checkpoint-k-gateway.test.mjs
/usr/bin/systemd-analyze verify ops/systemd/baby-x-root.slice ops/systemd/baby-x-root-broker.socket ops/systemd/baby-x-root-broker.service ops/systemd/baby-x.socket ops/systemd/baby-x.service ops/systemd/baby-x-gateway.service
[[ -z "$("$git_bin" status --porcelain --untracked-files=all)" ]] || { echo 'STATUS=FAILED ERROR=validation_changed_source' >&2; exit 1; }

release_root=/opt/baby-x/releases
"$node_bin" scripts/build-release.mjs \
  --source "$source_root" \
  --release-root "$release_root" \
  --repository "$repository" \
  --branch "$ref" \
  --commit "$commit" \
  --tree "$tree" \
  --parent "$parent"
candidate="$release_root/$commit-$tree"
"$node_bin" "$candidate/scripts/verify-release.mjs" \
  --release "$candidate" \
  --release-root "$release_root" \
  --repository "$repository" \
  --branch "$ref" \
  --commit "$commit" \
  --tree "$tree" \
  --parent "$parent" \
  --releaseIdentity "$commit-$tree"

deployment_id="baby-x-fast-${commit:0:12}-${expected_current:0:12}"
set +e
activation=$("$node_bin" "$candidate/scripts/activate-release.mjs" \
  --deployment-id "$deployment_id" \
  --candidate "$candidate" \
  --commit "$commit" \
  --tree "$tree" \
  --expected-current "$expected_current" \
  --expected-current-tree "$expected_current_tree" \
  --reason "$reason" \
  --forbidden-roots "$source_root")
activation_status=$?
set -e
printf '%s\n' "$activation"
exit "$activation_status"

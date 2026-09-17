#!/usr/bin/env bash
# Fetch pinned upstream assets and generate the gateway certificate. Idempotent.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
set -a; source "$ROOT/deploy/versions.env"; set +a
UPSTREAM="$ROOT/upstream"
mkdir -p "$UPSTREAM"

checkout() { # <dir> <repo-url> <ref> [sparse paths...]
  # $ref is normally a pinned commit SHA (see deploy/versions.env), but a branch or tag
  # name works too: `git fetch origin <ref>` resolves any of the three the same way, so
  # pinning to a commit doesn't need `clone --branch`, which only accepts branch/tag names.
  local dir="$1" url="$2" ref="$3"; shift 3
  if [[ ! -d "$dir/.git" ]]; then
    echo "==> cloning $url ($ref)"
    git -c core.longpaths=true clone --quiet --filter=blob:none --sparse --no-checkout "$url" "$dir"
    git -C "$dir" sparse-checkout set "$@"
    git -C "$dir" fetch --quiet --depth 1 origin "$ref"
    git -C "$dir" checkout --quiet FETCH_HEAD
  else
    local current
    current="$(git -C "$dir" rev-parse HEAD)"
    if git -C "$dir" config --get core.sparseCheckout >/dev/null 2>&1; then
      git -C "$dir" sparse-checkout set "$@"
    fi
    git -C "$dir" fetch --quiet --depth 1 origin "$ref"
    local wanted
    wanted="$(git -C "$dir" rev-parse FETCH_HEAD)"
    if [[ "$current" != "$wanted" ]]; then
      echo "==> updating $dir to $ref ($wanted)"
      git -C "$dir" checkout --quiet FETCH_HEAD
    fi
  fi
}

checkout "$UPSTREAM/conformance-suite" https://gitlab.com/openid/conformance-suite.git "$CONFORMANCE_SUITE_VERSION" scripts
checkout "$UPSTREAM/inji-certify" https://github.com/inji/inji-certify.git "$INJI_CERTIFY_REF" docker-compose/docker-compose-injistack
checkout "$UPSTREAM/inji-verify" https://github.com/inji/inji-verify.git "$INJI_VERIFY_REF" db_scripts

for required in \
  "$UPSTREAM/conformance-suite/scripts/run-test-plan.py" \
  "$UPSTREAM/inji-certify/docker-compose/docker-compose-injistack/certify_init.sql" \
  "$UPSTREAM/inji-verify/db_scripts/inji_verify/ddl/verify-vp_submission.sql"; do
  [[ -f "$required" ]] || { echo "missing upstream file: $required" >&2; exit 1; }
done

"$ROOT/scripts/gen-certs.sh"
echo "==> bootstrap complete"

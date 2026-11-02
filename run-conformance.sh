#!/usr/bin/env bash
# One-command conformance run for Inji Certify and/or Inji Verify.
#
#   ./run-conformance.sh --component certify
#   ./run-conformance.sh --component verify
#   ./run-conformance.sh --combined [--parallel]
#
# Options:
#   --parallel          run the Certify and Verify plans concurrently (with --combined)
#   --readiness         also run HAIP plans whose required capabilities are all supported
#   --update-baseline   store this run as the diff baseline when the gate passes
#   --no-up             do not start containers (use an already running stack / remote env)
#   --down              stop and remove the stack (and its volumes) after the run
#   --out DIR           results directory (default: ./results)
#
# Exit codes: 0 gate passed, 1 gate failed (regression), 2 infrastructure error.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPONENTS=()
ICG_ARGS=()
START=1
DOWN=0
COMBINED=0

usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --component)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      case "$2" in certify|verify) COMPONENTS+=("$2") ;; *) echo "unknown component: $2" >&2; exit 2 ;; esac
      shift 2 ;;
    --combined) COMPONENTS=(certify verify); COMBINED=1; shift ;;
    --parallel|--readiness|--update-baseline) ICG_ARGS+=("$1"); shift ;;
    --out)
      [[ $# -ge 2 ]] || { echo "--out needs a directory" >&2; exit 2; }
      ICG_ARGS+=(--out "$2"); shift 2 ;;
    --no-up) START=0; shift ;;
    --down) DOWN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done
[[ ${#COMPONENTS[@]} -gt 0 ]] || { usage; exit 2; }
if [[ $COMBINED -eq 1 ]]; then
  ICG_ARGS+=(--combined)
else
  for c in "${COMPONENTS[@]}"; do ICG_ARGS+=(--component "$c"); done
fi

# `python3` can be the Microsoft Store stub on Windows (Git Bash), so probe each candidate.
pick_python() {
  local candidate
  for candidate in python3 python py; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 10))' >/dev/null 2>&1; then
      echo "$candidate"; return 0
    fi
  done
  return 1
}
PYTHON="${PYTHON:-$(pick_python)}" || { echo "Python 3.10+ not found (set PYTHON=...)" >&2; exit 2; }
"$ROOT/scripts/bootstrap.sh"

if ! "$PYTHON" -c "import httpx, pyparsing" 2>/dev/null; then
  echo "==> installing harness requirements"
  "$PYTHON" -m pip install --quiet -r "$ROOT/harness/requirements.txt"
fi

COMPOSE=(docker compose --project-directory "$ROOT/deploy" -f "$ROOT/deploy/docker-compose.yml" --env-file "$ROOT/deploy/versions.env")
PROFILES=()
for c in "${COMPONENTS[@]}"; do PROFILES+=(--profile "$c"); done

# shellcheck disable=SC2329 # invoked via trap below
cleanup() {
  if [[ $DOWN -eq 1 && $START -eq 1 ]]; then
    echo "==> stopping stack"
    "${COMPOSE[@]}" --profile certify --profile verify down --volumes --remove-orphans || true
  fi
}
trap cleanup EXIT

if [[ $START -eq 1 ]]; then
  echo "==> starting: suite + gateway + ${COMPONENTS[*]}"
  "${COMPOSE[@]}" "${PROFILES[@]}" up -d
fi

set +e
PYTHONPATH="$ROOT/harness${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON" -m icg run "${ICG_ARGS[@]}"
STATUS=$?
set -e

if [[ $STATUS -eq 2 && $START -eq 1 ]]; then
  echo "==> infrastructure error; recent container logs:" >&2
  "${COMPOSE[@]}" "${PROFILES[@]}" logs --tail 40 >&2 || true
fi
exit $STATUS

#!/usr/bin/env bash
# Live-demo helper: pre-warms everything so a conformance run is fast on camera.
#
#   scripts/demo-live.sh warm   # pre-pull images, start the stack, show the suite UI
#   scripts/demo-live.sh run    # run the combined parallel plan against the running stack, open the report
#   scripts/demo-live.sh down   # stop the stack and remove its volumes
#
# Recording recipe: `warm` before the camera, start recording, `run`, show the
# suite UI and the report, then `down` afterwards.
set -euo pipefail

MODE="${1:-run}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose --project-directory "$ROOT/deploy" -f "$ROOT/deploy/docker-compose.yml"
  --env-file "$ROOT/deploy/versions.env" --profile certify --profile verify)

if docker info >/dev/null 2>&1; then
  echo "==> docker daemon is up"
else
  echo "==! docker daemon is not running - start Docker Desktop first (Settings > Resources: >= 10 GB memory)" >&2
  exit 2
fi

prepull() {
  echo "==> pre-pulling pinned images (one-time, few GB)"
  "${COMPOSE[@]}" pull --quiet
}

# shellcheck disable=SC2329 # invoked via the MODE dispatch below
open_url() { # <url>
  ( explorer.exe "$1" 2>/dev/null || xdg-open "$1" 2>/dev/null ) >/dev/null 2>&1 || true
}

case "$MODE" in
  warm)
    prepull
    echo "==> starting stack"
    "${COMPOSE[@]}" up -d
    echo "==> suite UI:  https://localhost.emobix.co.uk:8443/"
    echo "==> (Certify/Verify health: starting for a while is normal)"
    ;;
  run)
    echo "==> running the combined parallel plan against the running stack (about 60 s on camera)"
    "$ROOT/run-conformance.sh" --combined --parallel --no-up
    latest="$(find results -maxdepth 1 -name '2*' -type d 2>/dev/null | sort | tail -1)"
    if [[ -f "$latest/conformance-report.html" ]]; then
      open_url "file://$(cygpath -m "$ROOT/$latest/conformance-report.html")"
      echo "==> report: $ROOT/$latest/conformance-report.html"
    fi
    echo "==> suite plan page with the live handoff: https://localhost.emobix.co.uk:8443/"
    ;;
  down)
    "${COMPOSE[@]}" down --volumes --remove-orphans
    ;;
  *)
    sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
    ;;
esac

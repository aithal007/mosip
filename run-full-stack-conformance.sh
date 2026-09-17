#!/usr/bin/env bash
# Combined run: Inji Certify issuer plan + Inji Verify verifier plan, one consolidated
# report and one gate. Extra options are passed through to run-conformance.sh.
set -euo pipefail
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/run-conformance.sh" --combined "$@"

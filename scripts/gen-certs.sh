#!/usr/bin/env bash
# Self-signed certificate for the *.inji.test gateway (test use only).
set -euo pipefail

CERTS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/deploy/gateway/certs"
mkdir -p "$CERTS"
if [[ -s "$CERTS/inji.test.crt" && -s "$CERTS/inji.test.key" ]]; then
  exit 0
fi

echo "==> generating gateway certificate"
OUT="$CERTS"
if command -v cygpath >/dev/null 2>&1; then
  OUT="$(cygpath -m "$CERTS")"  # Git Bash: native openssl.exe needs a Windows path
fi
# MSYS_NO_PATHCONV stops Git Bash on Windows from rewriting the -subj value into a path.
MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
  -keyout "$OUT/inji.test.key" -out "$OUT/inji.test.crt" \
  -subj "/CN=inji.test/O=Inji Conformance Gate (test only)" \
  -addext "subjectAltName=DNS:certify.inji.test,DNS:verify.inji.test,DNS:inji.test" >/dev/null 2>&1
chmod 644 "$CERTS/inji.test.key" "$CERTS/inji.test.crt"

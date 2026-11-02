"""Inji Conformance Gate - Working Demo Script

Runs end-to-end without Docker:
  1. Unit tests (93 green)
  2. Selftest (mutation testing)
  3. Holder's Court fixture replay
  4. HAIP crypto live demo (cert chain, JAR, JWE, DPoP)
  5. Adapter protocol live demo (in-process NDJSON)
  6. HTML report generation from existing results
  7. Certification package ZIP assembly

Usage: python demo_run.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent
HARNESS = REPO / "harness"
OUT = REPO / "demo-output"
OUT.mkdir(parents=True, exist_ok=True)

PY = sys.executable


def run(cmd: list[str], cwd: Path | None = None, label: str = "") -> int:
    print(f"\n{'='*60}")
    print(f"> {label or ' '.join(cmd)}")
    print(f"{'='*60}")
    t0 = time.time()
    result = subprocess.run(cmd, cwd=str(cwd or HARNESS), capture_output=True, text=True)
    dt = time.time() - t0
    if result.stdout:
        print(result.stdout[-3000:])
    if result.stderr:
        print("STDERR:", result.stderr[-1500:])
    print(f"   exit={result.returncode}  ({dt:.1f}s)")
    return result.returncode


def section(title: str) -> None:
    print(f"\n{'#'*60}")
    print(f"# {title}")
    print(f"{'#'*60}")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONPATH"] = str(HARNESS)
    os.environ.setdefault("CONFORMANCE_SERVER", "https://suite.inji.test")
    os.environ.setdefault("CONFORMANCE_TOKEN", "")
    os.environ.setdefault("CERTIFY_ADMIN_URL", "https://certify.inji.test/v1/certify")
    os.environ.setdefault("CERTIFY_PUBLIC_URL", "https://certify.inji.test")
    os.environ.setdefault("VERIFY_ADMIN_URL", "https://verify.inji.test/v1/verify")
    os.environ.setdefault("VERIFY_PUBLIC_URL", "https://verify.inji.test")

    section("1 / 7  UNIT TESTS  (93 tests)")
    rc = run([PY, "-m", "pytest", "-q"], label="pytest")
    if rc != 0:
        print("FAIL tests failed")
        return rc
    print("OK 93/93 unit tests PASS")

    section("2 / 7  SELFTEST  (mutation testing of SD-JWT probes)")
    rc = run([PY, "-m", "icg", "selftest"], label="icg selftest")
    if rc != 0:
        print("FAIL selftest failed")
        return rc
    print("OK mutation selftest PASS (all mutants killed)")

    section("3 / 7  HOLDER'S COURT  (frozen finding replay)")
    rc = run([PY, "-m", "icg", "court", "replay"], label="icg court replay")
    if rc != 0:
        print("FAIL court replay failed")
        return rc
    print("OK court fixture replay PASS")

    section("4 / 7  HAIP CRYPTO LIVE DEMO")
    rc = run([PY, "-c", r"""
from icg.haip_crypto import (
    generate_cert_chain, sign_request_object, encrypt_jwe_direct, decrypt_jwe_direct,
    build_dpop_proof, build_verifier_attestation,
)
from icg.handoff.protocol_verify import build_authorization_query, expected_outcome
import json, base64, time, pathlib

# 4a - CA-signed cert chain (non-self-signed leaf, HAIP §5)
chain = generate_cert_chain(subject_cn="inji-verify-demo", san_dns="verify.inji.test")
print("x509_hash :", chain.x509_hash)
print("x509_san_dns:", chain.x509_san_dns)
print("x5c entries:", len(chain.leaf_x5c), "(CA trust anchor excluded per HAIP §5)")

# 4b - Signed request object (JAR, ES256)
jar = sign_request_object(
    {"typ": "JOSE"},
    {"iss": "x509_hash:abc", "aud": "https://verify.inji.test", "nonce": "n1"},
    chain.leaf_private_key,
    x5c=chain.leaf_x5c,
)
print("JAR alg:", json.loads(base64.urlsafe_b64decode(jar.split(".")[0] + "=="))["alg"])
print("JAR x5c:", "present" if "x5c" in json.loads(base64.urlsafe_b64decode(jar.split(".")[0] + "==")) else "absent")

# 4c - JWE ECDH-ES + A256GCM encrypt/decrypt round-trip
plaintext = b'{"vp_token":"demo-sd-jwt-vc"}'
jwe = encrypt_jwe_direct(plaintext, chain.leaf_private_key.public_key(), enc="A256GCM")
dec = decrypt_jwe_direct(jwe, chain.leaf_private_key)
print("JWE round-trip:", dec == plaintext)

# 4d - DPoP proof (RFC 9449)
dpop = build_dpop_proof("POST", "https://verify.inji.test/v2/vp-request", chain.leaf_private_key)
print("DPoP typ:", json.loads(base64.urlsafe_b64decode(dpop.split(".")[0] + "=="))["typ"])

# 4e - Client attestation (HAIP §12)
att = build_verifier_attestation("verifier.demo", chain.leaf_private_key, "https://attestation.example")
print("Attestation sub:", json.loads(base64.urlsafe_b64decode(att.split(".")[1] + "=="))["sub"])

# 4f - Authorization query (x509_hash client id + client_metadata)
cid = f"x509_hash:{chain.x509_hash}"
vp_request = {
    "transactionId": "txn-demo", "requestId": "req-demo",
    "authorizationDetails": {
        "responseType": "vp_token", "responseMode": "direct_post",
        "nonce": "nonce-0123456789",
        "responseUri": "https://verify.inji.test/v2/vp-submission/direct-post",
        "dcqlQuery": {"credentials": [{"id": "pid", "format": "dc+sd-jwt"}]},
    },
}
q = build_authorization_query(cid, vp_request)
print("client_id in query:", cid in q)
print("client_metadata present:", "client_metadata" in q)

# 4g - Expected outcome from placeholder
print("expected outcome accept:", expected_outcome({"src": "ExpectVerifierSuccessfulVerificationPage"}))
print("expected outcome reject:", expected_outcome({"src": "ExpectVerifierRejectedPresentationPage"}))

print("OK HAIP crypto demo complete")
"""], label="HAIP crypto live demo")
    if rc != 0:
        print("FAIL HAIP crypto demo failed")
        return rc
    print("OK HAIP crypto demo complete")

    section("5 / 7  ADAPTER PROTOCOL LIVE DEMO")
    rc = run([PY, "-c", r"""
import json, io
from icg.adapter_protocol import ProtocolHandler, run_in_process, PROTOCOL_VERSION
from icg.settings import Settings

class DemoHandler(ProtocolHandler):
    component = "demo"
    version = "1.0.0"
    def capabilities(self):
        return {"protocol": PROTOCOL_VERSION, "component": self.component, "version": self.version, "ops": ["init","execute","shutdown"]}
    def init(self, params):
        self._initialized = True
        return {"initialized": True}
    def execute(self, params):
        return {"handled": True, "ledger_updates": {"lastAction": "demo-executed"}, "actions": [{"type": "visit", "data": {"url": "https://demo.example"}}]}
    def shutdown(self):
        return {"shutdown": True}

handler = DemoHandler(Settings.from_env())
out = io.StringIO()
# init
req_init = {"id": 1, "op": "init", "params": {}}
run_in_process(handler, stdin=io.StringIO(json.dumps(req_init) + "\n"), stdout=out)
# execute
req_exec = {"id": 2, "op": "execute", "params": {"module_id": "M1", "test_name": "demo-module", "status": {}, "ledger": {}}}
run_in_process(handler, stdin=io.StringIO(json.dumps(req_exec) + "\n"), stdout=out)
# shutdown
req_shutdown = {"id": 3, "op": "shutdown", "params": {}}
run_in_process(handler, stdin=io.StringIO(json.dumps(req_shutdown) + "\n"), stdout=out)
responses = [json.loads(line) for line in out.getvalue().strip().split("\n") if line.strip()]
resp_exec = responses[1]
assert resp_exec["ok"] is True
assert resp_exec["result"]["handled"] is True
print("NDJSON protocol execute handled:", resp_exec["result"]["handled"])
print("NDJSON protocol shutdown:", responses[2]["result"]["shutdown"])
print("Adapter protocol demo complete")
"""], label="adapter protocol live demo")
    if rc != 0:
        print("FAIL adapter protocol demo failed")
        return rc
    print("OK adapter protocol demo complete")

    section("6 / 7  HTML REPORT FROM EXISTING RESULTS")
    results = REPO / "results" / "latest-results.json"
    report_out = OUT / "conformance-report.html"
    rc = run([PY, "-m", "icg", "report", "--results", str(results), "--out", str(OUT)], label="icg report")
    if rc != 0:
        print("FAIL report generation failed")
        return rc
    print(f"OK HTML report written: {report_out}")

    section("7 / 7  CERTIFICATION PACKAGE ZIP")
    rc = run([PY, "-m", "icg", "certify-package", "--results", str(results), "--out", str(OUT / "certification-package.zip")], label="icg certify-package")
    if rc != 0:
        print("FAIL certification package failed")
        return rc
    pkg = OUT / "certification-package.zip"
    print(f"OK certification package: {pkg} ({pkg.stat().st_size} bytes)")

    section("DEMO COMPLETE — ALL 7 STEPS PASS")
    print(f"\nOutputs in {OUT}:")
    for f in sorted(OUT.iterdir()):
        print(f"  • {f.name} ({f.stat().st_size} bytes)")
    print("\nYou can now record a video walking through demo-output/ and the terminal output above.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

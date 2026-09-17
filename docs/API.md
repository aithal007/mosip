# API reference

## 1. Harness CLI (`python -m icg`, run with `PYTHONPATH=harness`)

| Command | Purpose | Exit code |
|---|---|---|
| `run --component certify\|verify [--component …] \| --combined [--parallel] [--readiness] [--out DIR] [--baseline FILE] [--update-baseline] [--skip-wait] [--no-seed]` | Run plans, resolve handoffs, collect, gate, report | 0 pass · 1 regression · 2 infrastructure |
| `wait --component … [--timeout S]` | Wait for suite and Inji health | 0 / 2 |
| `seed-certify` | Register the SD-JWT credential configuration in Inji Certify | 0 / 2 |
| `report --results FILE [--baseline FILE] --out DIR` | Regenerate HTML/Markdown/JUnit/badge | 0 |
| `diff BASE CURRENT [--markdown FILE] [--fail-on-regression]` | Semantic run diff | 0 / 1 |
| `readiness` | HAIP certification gap report (Markdown) | 0 |
| `benchmark-suggest --results FILE --component C` | Draft expected-failure entries from regressions | 0 |
| `attest --results FILE --subject name=sha256:<hex> … [--url U] [--out F]` | in-toto Test Result statement | 0 |

### Environment

| Variable | Default | Meaning |
|---|---|---|
| `CONFORMANCE_SERVER` | `https://localhost.emobix.co.uk:8443/` | Suite base URL |
| `CONFORMANCE_TOKEN` | *(empty: dev mode)* | Bearer token for a hosted or secured suite |
| `CONFORMANCE_SUITE_SCRIPTS` | `upstream/conformance-suite/scripts` | Location of `run-test-plan.py` |
| `CERTIFY_ADMIN_URL` / `CERTIFY_PUBLIC_URL` | `http://localhost:8090/v1/certify` / `https://certify.inji.test/v1/certify` | Where the harness / the suite reach Certify |
| `VERIFY_ADMIN_URL` / `VERIFY_PUBLIC_URL` | `http://localhost:8080/v1/verify` / `https://verify.inji.test/v1/verify` | Where the harness / the suite reach Verify |
| `ICG_REVIEW_POLICY` | `resolve` | `resolve`, `pass`, `fail` |
| `ICG_WARNING_POLICY` | `pass` | `pass`, `fail` |
| `ICG_HANDOFF_POLL_SECONDS` | `1.0` | Agent poll interval |

## 2. `results.json` (schemaVersion 1)

```jsonc
{
  "schemaVersion": 1,
  "run_id": "20260916190050",
  "mode": "combined",                    // per-module | combined
  "suite_version": "release-v5.2.4",
  "components": ["certify", "verify"],
  "environment": { "conformanceServer": "…", "reviewPolicy": "resolve", … },
  "plans": [{
    "component": "verify", "plan_name": "oid4vp-1final-verifier-test-plan", "plan_id": "XOxSy…",
    "variant": { "credential_format": "sd_jwt_vc", … }, "gating": true,
    "plan_url": "https://…/plan-detail.html?plan=…", "selected_modules": [], "runner_exit_code": 0
  }],
  "modules": [{
    "component": "verify", "plan_name": "…", "plan_id": "…",
    "module_name": "oid4vp-1final-verifier-invalid-sd-hash", "module_id": "EfFUS…",
    "variant": { … }, "status": "FINISHED", "suite_result": "REVIEW",
    "verdict": "PASS", "verdict_reason": "REVIEW resolved: Inji result FAILED matches expected FAILED",
    "issue": "", "duration_seconds": 3.7, "log_url": "https://…/log-detail.html?log=…",
    "findings": [{ "condition": "…", "result": "FAILURE", "message": "…", "block": "…", "requirements": ["OID4VP-1FINAL-8.2"] }],
    "requirements": ["OID4VP-1FINAL-5.1", …],
    "counts": { "SUCCESS": 31, "FAILURE": 0 },
    "review_evidence": { "expected": "FAILED", "actual": "FAILED", "matched": true, "transactionId": "txn_…" }
  }],
  "shims": [{ "component": "certify", "name": "…", "reason": "…", "issue": "…" }],
  "summary": { "PASS": 15, "FAIL": 0, "KNOWN_ISSUE": 5, "STALE_BENCHMARK": 0, "SKIP": 0, "INCOMPLETE": 0, "TOTAL": 20 },
  "gatingSummary": { … },
  "gatePassed": true
}
```

Module identity for diffs is `component|plan_name|module_name|k=v,…` with the variant sorted by key. It is implemented identically in Python (`ModuleResult.key`) and Java (`ConformanceResults.Module.key()`).

## 3. Conformance suite REST endpoints used

Authentication is `Authorization: Bearer <token>`. It is not needed when the suite runs in dev mode.

| Endpoint | Used by | Purpose |
|---|---|---|
| `POST /api/plan?planName=&variant=` (body: config) | run-test-plan.py | Create plan (201 `{id, modules}`) |
| `POST /api/runner?test=&plan=&variant=` | run-test-plan.py | Create and start a module (201 `{id}`) |
| `GET /api/runner/{id}/wait-state?states=` | run-test-plan.py | Long-poll module state |
| `GET /api/plan/export/{planId}` | run-test-plan.py | Signed JSON export zip |
| `GET /api/runner/available` | harness | Readiness probe |
| `GET /api/runner/running` | agent | Ids of in-memory modules |
| `GET /api/runner/{id}` | agent | `exposed` values (`authorization_endpoint`, `credential_offer_endpoint`, `tx_code_endpoint`), `browser.uriInputRequests`, `browser.uploadsRequired` |
| `GET /api/info/{id}` | agent, collector | `testName`, `status`, `result`, `variant` |
| `GET /api/log/{id}` | collector | Log entries: `src`, `result`, `msg`, `blockId`, `requirements`, `upload` |
| `GET /api/log/{id}/images` | agent | Pending REVIEW placeholders |
| `POST /api/log/{id}/images/{placeholder}` (text body `data:image/png;base64,…`) | agent | Fill a placeholder with review evidence |
| `GET /api/plan/{id}` | collector | Modules and their `instances` |

Module status values: `CREATED, CONFIGURED, RUNNING, WAITING, INTERRUPTED, FINISHED`. Result values: `PASSED, FAILED, WARNING, REVIEW, SKIPPED, UNKNOWN`.

## 4. Inji endpoints used

| Component | Endpoint | Request | Response used |
|---|---|---|---|
| Certify | `GET /v1/certify/.well-known/openid-credential-issuer` | — | `credential_issuer`, `credential_configurations_supported` |
| Certify | `POST /v1/certify/credential-configurations` | `CredentialConfigurationDTO` with base64 `vcTemplate` | `{id, status}` |
| Certify | `POST /v1/certify/pre-authorized-data` | `{credential_configuration_id, claims, expires_in, tx_code}` | `{credential_offer_uri: "openid-credential-offer://?credential_offer_uri=…"}` |
| Certify | `GET /v1/certify/actuator/health` | — | readiness |
| Verify | `POST /v1/verify/v2/vp-request` | `{clientId, nonce, dcqlQuery, responseCodeValidationRequired}` | `{transactionId, requestId, authorizationDetails{responseUri, nonce, dcqlQuery, responseMode, responseType}}` |
| Verify | `GET /v1/verify/vp-result/{transactionId}` | — | `vpResultStatus` (`SUCCESS` / `FAILED`), `vcResults` |
| Verify | `GET /v1/verify/actuator/health` | — | readiness |

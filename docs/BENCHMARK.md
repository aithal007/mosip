# Benchmark and gating

## Verdicts

| Verdict | When | Blocks the gate? | TestNG / EmailableReport |
|---|---|---|---|
| `PASS` | Suite PASSED; WARNING (policy `pass`); REVIEW resolved and matching | no | pass |
| `STALE_BENCHMARK` | Passed, but the benchmark still expects a failure. **Remove the entry** | no | pass, flagged in reports |
| `KNOWN_ISSUE` | Every failing condition matches a benchmark entry with an issue link | no | skip, counted in **KI** (message contains `known issue`) |
| `SKIP` | Suite skipped the module | no | skip, counted as **Ignored** |
| `FAIL` | Any unexpected FAILURE (or WARNING with policy `fail`); REVIEW mismatch | **yes** | fail |
| `INCOMPLETE` | No result: timeout, handoff failure, REVIEW without evidence | **yes** | fail |

A module that the suite **interrupted** because of a failing condition during setup (for example a server metadata check) is a conformance failure and is matched against the benchmark. An interruption without findings counts as an infrastructure problem.

The gate passes when every **gating** plan produced modules and none of them is blocking. HAIP readiness plans are report-only (`gating: false`).

## Benchmark files

`conformance/benchmark/<component>/expected-failures.json` uses the upstream `run-test-plan.py --expected-failures-file` format. It adds two fields that upstream ignores:

```json
{
  "test-name": "oid4vci-1_0-issuer-fail-unknown-credential-configuration",
  "variant": "*",
  "configuration-filename": "*issuer-sdjwt-preauth.json",
  "current-block": " Verify Credential Endpoint Response",
  "condition": "VCIValidateCredentialErrorResponse",
  "expected-result": "failure",
  "issue": "https://github.com/inji/inji-certify/issues/941",
  "comment": "Unknown credential_configuration_id rejected without the unknown_credential_configuration error code."
}
```

Matching works exactly as it does upstream:
- `test-name` and `configuration-filename` are fnmatch patterns.
- `variant` is `"*"` or a partial map.
- `condition` must match exactly.
- `current-block` must match exactly, or be `"*"`.

Harness pseudo-conditions:
- `icg:review-mismatch`: Inji's verification result differed from the expected one (only with `ICG_REVIEW_POLICY=resolve`).
- `icg:incomplete`: the module is expected not to complete. Use sparingly.

`expected-skips.json` lists modules that are expected to be skipped or to fail as a whole.

### Maintaining it

1. A run fails the gate with new regressions.
2. `python -m icg benchmark-suggest --results results/<run>/results.json --component certify` prints draft entries with `issue: "TODO"`.
3. File or link the Inji issue, replace the TODO and commit the entry with the same pull request.
4. When a fix lands, the module turns `STALE_BENCHMARK` and the report lists the entry to delete. The benchmark therefore only shrinks when a fix is real.

## Policies

| Env var | Values | Default |
|---|---|---|
| `ICG_REVIEW_POLICY` | `resolve` · `pass` · `fail` | `resolve` |
| `ICG_WARNING_POLICY` | `pass` · `fail` | `pass` |

## Run diff

Every run is compared with `results/baseline-results.json`, if present. The baseline is updated with `--update-baseline` when the gate passes, and CI keeps it in the Actions cache.

`python -m icg diff A.json B.json --fail-on-regression` reports:
- **Regressions:** a verdict became blocking, or new failing conditions appeared.
- **Fixes**
- **Changes** in failing conditions
- **Added or removed modules**, which catch new suite modules after an upgrade.

Module identity is `component | plan | module | sorted variant`.

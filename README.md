# Inji Conformance Gate

**MOSIP Decode 2026 — PS-01**: Automated Conformance Testing for Inji Certify and Inji Verify against the OpenID Suite.

Automated OpenID Foundation conformance testing for **Inji Certify** (OID4VCI issuer) and **Inji Verify** (OID4VP verifier), wired into MOSIP's api-testrig and CI.

One command starts the OpenID conformance suite and the Inji services. It runs the issuer and verifier test plans with no clicks, handles every step where the suite waits on Inji, and gates the release against a benchmark in which each expected failure links to an issue.

## Why this exists

The OpenID Foundation conformance suite is built to be driven by a human clicking through a wallet UI: it creates a plan, then **pauses and waits** whenever a real issuer or verifier interaction is needed, and several of its results (`REVIEW`) require a human to look at a screenshot and judge whether verification actually succeeded. That is workable once, by hand, for a certification submission — it does not survive being run on every PR.

This project turns that manual, one-off process into an unattended gate:

- **No clicks.** A handoff agent watches the suite's own state and answers each pause by calling Inji Certify's and Inji Verify's real APIs, the same way a wallet or verifier UI would.
- **No human judgment calls.** `REVIEW` placeholders are resolved by asking Inji Verify for its own verdict and cross-checking it against what the suite expected, with a PNG evidence card attached to the report as an audit trail.
- **No pass/fail cliff-edge.** Inji is pre-1.0 and does not pass every module yet. A benchmark of expected failures, each linked to a tracked issue, means the gate fails on *regressions*, not on every known gap — and flags entries that start passing so the benchmark doesn't go stale.
- **No silent workarounds.** Where the gateway papers over a spec gap in Inji's metadata (see `docs/FINDINGS.md`), that shim is declared in the plan manifest and printed in every report next to its issue link, not hidden.
- **No result living outside MOSIP's own reporting.** The same verdicts are surfaced inside each product's existing api-testrig, through the same `EmailableReport` that MOSIP QA already reads.

```bash
./run-conformance.sh --component certify      # OID4VCI issuer plan  -> Inji Certify
./run-conformance.sh --component verify       # OID4VP verifier plan -> Inji Verify
./run-conformance.sh --combined --parallel    # both, one consolidated report and gate
```

Real run against `1.0.0-alpha.1` images (full artifacts in [docs/sample-run/](docs/sample-run/)):

| Component | Modules | Pass | Known issue (issue-linked) | Regression |
|---|---|---|---|---|
| Inji Certify · `oid4vci-1_0-issuer-test-plan` (SD-JWT VC, pre-authorized code) | 9 | 4 | 5 | 0 |
| Inji Verify · `oid4vp-1final-verifier-test-plan` (SD-JWT VC, redirect_uri, direct_post) | 11 | 11 | 0 | 0 |

The Verify run included 7 suite **REVIEW** results. The harness resolved all of them automatically by checking Inji Verify's own verification result. MOSIP's manual run ([inji-verify#2013](https://github.com/inji/inji-verify/issues/2013)) had left 6 of these for a human.

---

## What it does

| Problem with manual conformance runs | What the gate does |
|---|---|
| Runs happen by hand in the suite web UI | Drives the suite over its REST API with the upstream `run-test-plan.py`, unmodified |
| The suite **waits** until the issuer or verifier acts | **Handoff adapters** call Inji's real APIs: Certify creates a credential offer, Verify creates the authorization request |
| **REVIEW** results need a human screenshot | The **REVIEW resolver** compares Inji Verify's own verdict with the verdict the test expects, then uploads a PNG evidence card |
| Some results are known to fail, so a single pass/fail result is not usable | **Benchmark**: expected failures in the upstream format plus an `issue` link. Only *new* failures fail the build. Entries that start passing are flagged as `STALE_BENCHMARK` |
| Results live apart from the MOSIP test reports | An `OpenIDConformanceTest` TestNG class in each api-testrig. Results land in the same EmailableReport, known-issue column and S3 upload |
| No view of what blocks certification | **Certification readiness** report for the HAIP profiles, one row per capability gap with its tracking issue |
| Nothing ties results to a build | `icg attest` writes an in-toto Test Result statement for the tested image digests. CI signs it with Sigstore |

Every verdict is one of `PASS`, `FAIL` (regression), `KNOWN_ISSUE`, `STALE_BENCHMARK`, `SKIP` or `INCOMPLETE`. See [docs/BENCHMARK.md](docs/BENCHMARK.md).

## Quick start

Prerequisites: Docker with Compose v2 (10 GB of memory for Docker), Python 3.10+, git and bash. Windows works with Git Bash.
`localhost.emobix.co.uk` resolves to `127.0.0.1` through public DNS, so no hosts file change is needed.

```bash
git clone <this repo> && cd inji-conformance-gate
./run-conformance.sh --combined --parallel
# open results/<run-id>/conformance-report.html
```

The script fetches pinned upstream assets, generates a test TLS certificate, starts the stack, waits for health, seeds Certify's SD-JWT credential configuration, runs the plans and writes the reports.
Options include `--readiness`, `--update-baseline`, `--no-up` (use a running or remote stack) and `--down`. Run `./run-conformance.sh --help` for the full list.

Exit codes: `0` gate passed · `1` regression against the benchmark · `2` infrastructure error.

## Outputs (per run, in `results/<run-id>/`)

| File | Purpose |
|---|---|
| `results.json` | Machine-readable contract (schemaVersion 1), consumed by the TestNG bridge |
| `conformance-report.html` | Self-contained consolidated report: gate, per-component verdicts, findings, spec-clause coverage, diff, shims, readiness |
| `summary.md` | GitHub job summary / PR comment |
| `junit.xml` | For CI test-result publishers |
| `badge.svg` | Status badge |
| `handoff-ledger.json` | Every handoff action and piece of review evidence, with Inji transaction ids |
| `exports/` | Upstream signed plan export zips, the input for certification packages |
| `logs/` | Raw `run-test-plan.py` output |

## Repository layout

```
run-conformance.sh              one-command runner (--component certify|verify | --combined)
run-full-stack-conformance.sh   combined run
deploy/                         docker-compose (suite + gateway + Certify + Verify), pinned versions
conformance/plans/              test plan manifests: variants, modules, readiness capabilities, shims
conformance/configs/            suite config templates, DCQL query, credential offer, SD-JWT credential config
conformance/benchmark/          expected failures / skips per component (issue-linked)
harness/icg/                    Python harness (runner, handoff agent, adapters, benchmark, reports)
testrig/conformance-bridge/     Java library: runs the harness, maps verdicts to TestNG
testrig/injicertify|injiverify/ OpenIDConformanceTest classes + TestNG suite files for the api-testrigs
.github/workflows/              full-stack-conformance.yml
docs/                           architecture, handoff, benchmark, API, integration, certification, troubleshooting
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md): components, data flow and design decisions
- [Handoff handling](docs/HANDOFF.md): how the suite and each Inji component are joined up without a human
- [Benchmark and gating](docs/BENCHMARK.md): verdicts, expected failures, REVIEW policy, run diffs
- [api-testrig integration](docs/TESTRIG_INTEGRATION.md): adding `OpenIDConformanceTest` to the Inji testrigs
- [API reference](docs/API.md): CLI, `results.json` schema, suite and Inji endpoints used
- [Self-certification](docs/SELF_CERTIFICATION.md): from a green gate to an OpenID certification submission
- [Findings](docs/FINDINGS.md): conformance gaps found in Inji 1.0.0-alpha.1
- [Troubleshooting](docs/TROUBLESHOOTING.md)

## Tests

```bash
cd harness && python -m pytest -q                         # 31 unit tests, no Docker needed
cd testrig/conformance-bridge && mvn -q verify             # Java bridge tests (JDK 21)
```

## PS-01 requirement mapping

| PS-01 asks for | Where it is |
|---|---|
| docker-compose bringing up Certify, Verify and the suite | `deploy/docker-compose.yml`, profiles `certify`/`verify`, started by `run-conformance.sh` |
| Programmatic runner built on `run-test-plan.py` | `harness/icg/runner.py` invokes the unmodified upstream script; nothing about plan execution is reimplemented |
| `OpenIDConformanceTest` TestNG class in each api-testrig | `testrig/injicertify/…/OpenIDConformanceTest.java`, `testrig/injiverify/…/OpenIDConformanceTest.java` — compiled against real `release-1.0.x` api-test modules |
| Combined run | `--combined` / `run-full-stack-conformance.sh`, one consolidated report and gate |
| `run-conformance.sh --component certify\|verify\|--combined` | present, plus `--parallel`, `--readiness`, `--update-baseline`, `--no-up`, `--down` |
| GitHub Actions (good-to-have) | `.github/workflows/full-stack-conformance.yml`: unit tests, matrix run per component, baseline cache, attestation |
| Expected failures / result diff (good-to-have) | `conformance/benchmark/`, `icg diff`, `docs/BENCHMARK.md` |
| Docs (good-to-have) | `docs/` — architecture, handoff, benchmark, testrig integration, API, self-certification, findings, troubleshooting |
| Parallel execution (bonus) | `--parallel`: Certify and Verify plans run concurrently, ~35 s combined for 20 modules (see [docs/sample-run/](docs/sample-run/)) |

## Limitations / not done

- The eSignet-backed authorization-code flow for Certify is out of scope; only the pre-authorized-code SD-JWT VC flow is exercised.
- The GitHub Actions workflow has not been run on `github.com` yet (no remote CI history); it is exercised locally via the same `run-conformance.sh` it calls.
- `testrig/Dockerfile.conformance-layer` has not been built and pushed as an image; the api-test modules were compiled and verified locally instead (see `docs/TESTRIG_INTEGRATION.md`).

## License

[MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/), consistent with MOSIP and Inji. The upstream conformance suite scripts are downloaded at run time and are not vendored.

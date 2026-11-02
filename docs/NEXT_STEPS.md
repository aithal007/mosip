# Handoff report: state of the project and what is left

Written 2 Nov 2026 for continuing on another machine. Branch: `gate-hardening-and-probes` (3 commits on top of `main` at `8e05eb5`). **Nothing in this branch has been pushed yet**: the laptop it was built on was signed in to GitHub as an account without write access to `aithal007/mosip`.

## 1. Get going (15 minutes)

```bash
git checkout gate-hardening-and-probes      # already checked out if you unzipped the project folder
git remote -v                               # must point to a repo you can push to
git push -u origin gate-hardening-and-probes
# then open a pull request: the workflow runs on pull_request and will produce the first CI evidence
```

Machine needs: Docker Desktop (>= 10 GB memory in Settings > Resources, >= 15 GB free disk), Python 3.10+, git, Git Bash, JDK 21 + Maven (only for the Java bridge).

```bash
pip install -r harness/requirements.txt pytest
cd harness && python -m pytest -q           # expect 47 passed
python -m icg selftest                      # expect 12/12 mutants caught, exit 0
cd .. && ./run-conformance.sh --combined --parallel --down
```

## 2. What was verified, and where

| Claim | Verified? | How |
|---|---|---|
| Inji Verify 1.0.0-alpha.1: 11/11 modules PASS, 7 REVIEW results auto-resolved | **Yes, live** | Real Docker run on Windows 11, 2 Nov 2026 (`./run-conformance.sh --component verify --down`, exit 0) |
| 47 unit tests pass | **Yes** | `python -m pytest -q` |
| Probe self-test: 12/12 mutants caught | **Yes** | `python -m icg selftest` (no Docker). Its first run found a bug in its own reference verifier, which was fixed |
| Java bridge builds, 7 tests pass | **Yes** | JDK 21.0.13 + Maven 3.9.9, `mvn verify` in `testrig/conformance-bridge` |
| docker-compose file valid | **Yes** | `docker compose config` with both profiles |
| Inji Certify: 4 pass / 5 known issue | **Partly — live 2 Nov 2026** | Two live runs on Windows 11. Run 1 hit a stale `certify-db` volume (Certify crash-loop on keymanager init); run 2 after `down --volumes`: clean exit, `metadata-test`/`happy-flow*`/`metadata-test-signed` verdicts matched CI, but all 5 `fail-*` modules INTERRUPTed with a handoff timing race that does not occur in CI (tracked intrarepo as `aithal007/mosip#2`) |
| `icg probe` against a live Inji | **Pending** | Only tested against mocked servers; live probe run scheduled after the combined run |
| GitHub Actions workflow | **Yes** | Nightly scheduled runs on `main` green since 24 Oct 2026 (unit + Certify + Verify + Combined + attestation); PR #1 runs the hardened branch, green after fixing shellcheck 0.11 (`SC2329`/`SC1091`) |
| Java `OpenIDConformanceTest` classes in `testrig/injicertify` and `testrig/injiverify` | **No** | Not compiled; they need MOSIP `apitest-commons` |

## 3. What changed in this branch

Gate correctness (`harness/icg/`)
- `handoff/verify.py`: only HTTP 400/409/410/422 from `/vp-result` count as "rejected". Before, any 4xx/5xx except 404 did, which could pass the tamper tests falsely. **The status list is an assumption: confirm it against a real rejected submission.**
- `handoff/base.py`, `certify.py`, `verify.py`: a WAITING state is marked handled only after the action succeeds; adapters return `False` when the suite has not exposed what they need yet, so the next poll retries.
- `cli.py`: unexpected exceptions exit 2 (infrastructure) so exit 1 stays "regression". Per-component baselines (`baseline-<components>.json`), microsecond run ids, `icg probe`, `icg selftest`.
- `benchmark.py`: an expected skip no longer hides a new failing condition; `Benchmark.validate()` flags entries without an issue link.
- `runner.py`: process-tree kill on timeout; opt-in `ICG_SHOW_UNTESTED_MODULES=<family>` passes `--show-untested-test-modules` to the upstream runner (**flag syntax unconfirmed**).
- `coverage.py` / `report.py`: new "review-resolved" clause state (striped cell).

New modules
- `probe.py`: negative probes. Certify: unknown credential configuration, pre-authorized code replay, wrong `tx_code`, path-inserted metadata (inji-certify#967). Verify: garbage `vp_token`, plus the SD-JWT corpus.
- `sdjwt_corpus.py`: 15 tampered SD-JWT presentations plus a control, each tied to an RFC/CVE.
- `refverifier.py`, `selftest.py`: strict reference verifier with 12 switchable rules, a mock Inji Verify, and the mutation score.

Infrastructure
- `deploy/docker-compose.yml`: published ports bound to `127.0.0.1`.
- `.github/workflows/full-stack-conformance.yml`: workflow inputs go through `env:` (no shell injection); shellcheck and `docker compose config` step; selftest step; baseline cache path is `results/baseline-*.json`.
- `run-conformance.sh`: probes for a real Python (the Windows Store `python3` stub breaks), `--out` validation, no duplicate `--combined` args, `--down` only tears down what it started.
- `scripts/bootstrap.sh`: works offline when the pinned commits are cached.
- Java: `ConformanceRunConfig` defaults to `python` on Windows.

## 4. To do, in priority order

### A. Must do before submitting
1. **Push and open the PR.** Fix the GitHub permission problem first (collaborator access, or sign in as the repo owner).
2. **Get the CI run green on github.com.** Expect to debug: the workflow has never run. Known weak spots: the attest job resolves image digests in a different job from the one that ran the tests (resolve once, pass as an output); `cosign sign-blob` signs the file, not an in-toto attestation, which contradicts the docs wording; actions are pinned by tag, not SHA; `--update-baseline` runs on pull requests.
3. **Run Certify live** (`./run-conformance.sh --component certify --down`) and compare with the documented 4 pass / 5 known issue. Then run the combined parallel run.
4. **Run `python -m icg probe` against the live stack** (`--no-up`). Expect the SD-JWT corpus to report `inconclusive` (Verify does not trust the generated issuer key). To make it conclusive, register the corpus issuer key (or did:jwk / x5c variant) as trusted in Inji Verify, or expose a trusted-issuer setting. This is the main open design question for the probes.
5. **Confirm the `/vp-result` rejection statuses** (item above) and the `direct-post` form shape (`vp_token` as a JSON object keyed by the DCQL credential id, plus `state`). Both are inferred from the handoff adapter, not from Inji documentation.
6. **Ask the organisers for the real PS-01 text and judging criteria.** They could not be retrieved (the Unstop page is JavaScript-rendered).

### B. Should do
7. **Distinct issue links for the 5 Certify known issues.** All five point at inji-certify#941 (the conformance setup issue). Find or file one issue per gap (C1 to C5 in `docs/FINDINGS.md`; C8 is #967). `Benchmark.validate()` already warns on missing links but cannot tell a wrong one.
8. **Compile the Java testrig classes** in CI against MOSIP `apitest-commons` (Maven Central `io.mosip.testrig.apitest.commons:apitest-commons`; also see the `mosip-functional-tests` repo). Add a `--combined` mode to `ConformanceRunner`; it only supports one component today.
9. **Harness hygiene:** `verify=False` on every HTTP client, including calls that carry `CONFORMANCE_TOKEN` to a hosted suite; `render_config` edits JSON by regex (parse and substitute instead); markdown/JUnit output is not escaped; untested: `HandoffAgent.poll_once` with a fake SuiteApi, `run_component`, `cli.command_run` exit codes. The suite is not cancelled on timeout (only the local process tree is killed).
10. Fix doc inaccuracies in `docs/ARCHITECTURE.md` (an empty `selected_modules` means all modules, not exit 2; not every unexpected failure exits 1).

### C. Ideas from the research (all unimplemented, ordered by value)
11. **`clauses.yaml` traceability:** extract every MUST/SHOULD from OID4VCI 1.0, OID4VP 1.0, HAIP into a frozen file with clause ids, map each to a suite test or probe, and show clause coverage and gaps in the report. Keep any LLM use offline and freeze its output so the gate stays deterministic.
12. **CNCF-style evidence bundle:** `inji-conformance/<version>/<product>/` with README, PRODUCT.yaml, raw OpenID export, JUnit, suite version, config hash, SBOM, attestation over a manifest of file hashes, plus an offline `verify-bundle` command. Also emit OSCAL assessment results and a SLSA-VSA-style verdict. Test the zero-control case.
13. **Failure-to-issue bot** with a stable fingerprint (condition + normalised error), searched before filing, nightly/default-branch only. On nightly, comment when a benchmarked issue now passes.
14. **Trend history** (one `results.json` per nightly run on a data branch, per-clause pass rate over time, endpoint badge) and a **record/replay mode** (WireMock cassettes) so PR CI does not need Docker.
15. **Stateful testing** with Hypothesis `RuleBasedStateMachine` over the issuer lifecycle (single-use pre-authorized code, `c_nonce` replay, DPoP key binding), and **grammar-based JWT fuzzing** with a differential oracle (cf. JWTeemo, NDSS 2026).
16. **Differential run** against a second implementation (walt.id, `oid4vcgo`, EUDI reference) and flag "Inji-only" deviations. Novel but needs more stacks.
17. **More negative cases from the research** (issuer side: proof-JWT abuse, DPoP replay, PKCE/redirect mix-ups, `tx_code` brute force with no lockout, code used for another credential configuration; metadata whose `credential_issuer` differs from its URL. Verifier side: Token Status List abuse, `mso_mdoc` digest and session-transcript errors, JSON-LD context swap).
18. **Flaky-test triage:** rerun failures to label stable / flaky / environmental; keep flaky ones out of the benchmark.

### D. Blocked on Inji itself
19. `mso_mdoc`, `x509_hash` signed requests and `direct_post.jwt` for Verify; DPoP, client attestation, PAR and the authorization-code flow for Certify. The HAIP plans can only run once these exist; `python -m icg readiness` tracks them. Note that the OpenID HAIP issuer plan does not support the pre-authorized code flow, so the current green Certify runs show conformance progress, not certification readiness.

## 5. Things to be careful about
- Do not claim OpenID certification anywhere. This is a pre-certification harness; certification has fees and OpenID review.
- Inji 1.0.0 is not GA (latest tag was `1.0.0-alpha.1` as of this work). Keep image tags and the suite version pinned (`deploy/versions.env`); bump them in their own PR.
- The research findings in this repo came from web searches that were mostly snippet-level. Citations (CVE-2026-62374, CVE-2026-34240, the NDSS 2026 JWTeemo paper, the arXiv ids) were not independently verified: check each before quoting it.
- Windows specifics: Docker's CLI is not on PATH in Git Bash (add `.../DockerDesktop/resources/bin`). The suite config path passed to `run-test-plan.py` must be on the same drive as `upstream/`. If a pull fills the disk, Docker's VM can go read-only and needs a restart.

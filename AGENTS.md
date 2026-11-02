# Kilo Agent Guidance — Inji Conformance Gate

This repo is the Inji Conformance Gate: automated OpenID conformance testing for Inji Certify (OID4VCI issuer) and Inji Verify (OID4VP verifier), gated against an issue-linked benchmark.

## Repository layout

```
run-conformance.sh              one-command runner (--component certify|verify | --combined)
run-full-stack-conformance.sh   combined run
deploy/                         docker-compose (suite + gateway + Certify + Verify), pinned versions
conformance/plans/              test plan manifests: variants, modules, readiness capabilities, shims
conformance/configs/            suite config templates, DCQL query, credential offer, SD-JWT credential config
conformance/benchmark/          expected failures / skips per component (issue-linked)
harness/icg/                    Python harness (runner, handoff agent, adapters, benchmark, reports)
harness/tests/                  Python unit tests (pytest)
testrig/conformance-bridge/     Java library: runs the harness, maps verdicts to TestNG (JDK 21, Maven)
testrig/injicertify|injiverify/ OpenIDConformanceTest classes + TestNG suite files for the api-testrigs
.github/workflows/              full-stack-conformance.yml
docs/                           architecture, handoff, benchmark, API, integration, certification, troubleshooting
```

## Commands

All commands run from `inji-conformance-gate/` unless noted.

### Python harness tests
```
cd harness
python -m pytest -q              # 47 unit tests, no Docker needed
python -m icg selftest           # probe mutation self-test (no Docker)
python -m icg court replay       # Holder's Court fixture replay (pure Python)
```

### Python install
```
cd harness
python -m pip install -r requirements.txt pytest
# dev: python -m pip install -e ".[dev]"
```

### Java bridge tests
```
cd testrig/conformance-bridge
mvn -q verify                    # JDK 21
```

### End-to-end conformance run
```
./run-conformance.sh --component certify      # OID4VCI issuer plan
./run-conformance.sh --component verify       # OID4VP verifier plan
./run-conformance.sh --combined --parallel    # both, one consolidated report and gate
# Prerequisites: Docker with Compose v2, Python 3.10+, git, bash
```

### Static checks
```
shellcheck run-conformance.sh run-full-stack-conformance.sh scripts/*.sh
docker compose --project-directory deploy -f deploy/docker-compose.yml --env-file deploy/versions.env --profile certify --profile verify config -q
```

## Code conventions

- Python: type hints (`from __future__ import annotations`), dataclasses for models, `logging` with `log = logging.getLogger(__name__)`, httpx with `verify=False` for local self-signed TLS, no third-party imaging libraries (PNG rendered manually in `evidence.py`).
- Shell: `set -euo pipefail`, bash scripts, PowerShell-compatible where noted (Windows Git Bash supported).
- Java: JDK 21, Maven, TestNG.
- Do NOT commit secrets or keys. Environment variables only for tokens/credentials.
- `results.json` schema (schemaVersion 1) is a public contract parsed by the Java TestNG bridge — field names must stay stable.

## Architecture principles

1. Run the upstream `run-test-plan.py` unmodified — never reimplement plan execution.
2. Handoff agent runs alongside the script, polling the suite for WAITING modules and dispatching to component adapters.
3. Use Inji's real APIs for every handoff (credential offer, VP request, review evidence).
4. Benchmark uses upstream expected-failures format extended with `issue` links — only regressions fail the gate.
5. Disclose all compatibility shims in reports; never hide workarounds.
6. Fail closed: a gating plan with no modules or a blocking verdict fails the build.

## When adding features

- Add unit tests under `harness/tests/` for new Python modules.
- Update `AGENTS.md` if commands or lint setup change.
- Keep `results.json` schema backward compatible.
- Document new subcommands in `harness/icg/cli.py` and this file.

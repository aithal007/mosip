"""Conformance benchmark: turn raw suite results into gate verdicts.

The benchmark files use the *upstream* ``run-test-plan.py`` expected-failures format
(so the same file is passed to ``--expected-failures-file``), extended with two
fields the upstream script ignores:

* ``issue``   - URL of the tracked Inji issue that explains the failure (required here)
* ``comment`` - free text

Matching semantics are identical to ``run-test-plan.py``: fnmatch on ``test-name`` and
``configuration-filename``, partial match on ``variant`` (or ``"*"``), exact
``condition`` and ``current-block`` (or ``"*"``).

Harness-specific pseudo-conditions (never emitted by the suite):
* ``icg:review-mismatch`` - Inji's own verification outcome differed from what the test expected
* ``icg:incomplete``      - module cannot complete (e.g. an unsupported handoff)
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .model import ModuleResult, SuiteResult, Verdict

REVIEW_MISMATCH = "icg:review-mismatch"
INCOMPLETE = "icg:incomplete"


@dataclass
class Benchmark:
    expected_failures: list[dict[str, Any]] = field(default_factory=list)
    expected_skips: list[dict[str, Any]] = field(default_factory=list)

    @staticmethod
    def load(failures_file: Path | None, skips_file: Path | None) -> "Benchmark":
        def read(path: Path | None) -> list[dict[str, Any]]:
            if path is None or not path.exists():
                return []
            text = path.read_text(encoding="utf-8").strip()
            return json.loads(text) if text else []

        return Benchmark(read(failures_file), read(skips_file))

    def entries_for(self, entries: list[dict[str, Any]], module: ModuleResult, config_file: str) -> list[dict[str, Any]]:
        return [e for e in entries if _matches(e, module.module_name, config_file, module.variant)]


def _matches(entry: dict[str, Any], test_name: str, config_file: str, variant: dict[str, str]) -> bool:
    if not fnmatch.fnmatch(test_name, entry.get("test-name", "")):
        return False
    if not fnmatch.fnmatch(config_file.replace("\\", "/"), entry.get("configuration-filename", "*")):
        return False
    expected_variant = entry.get("variant", "*")
    if expected_variant == "*":
        return True
    return all(variant.get(k) == v for k, v in expected_variant.items())


def _finding_matches(entry: dict[str, Any], finding_condition: str, finding_block: str, finding_result: str) -> bool:
    expected_result = {"failure": "FAILURE", "warning": "WARNING"}.get(entry.get("expected-result", ""), "")
    block = entry.get("current-block", "*")
    return (
        entry.get("condition") == finding_condition
        and (block == "*" or block == finding_block)
        and expected_result == finding_result
    )


def _issues(entries: list[dict[str, Any]]) -> str:
    return ", ".join(sorted({e["issue"] for e in entries if e.get("issue")}))


def classify(
    module: ModuleResult,
    config_file: str,
    benchmark: Benchmark,
    *,
    review_policy: str = "resolve",
    warning_policy: str = "pass",
) -> ModuleResult:
    """Set ``verdict``, ``verdict_reason`` and ``issue`` on the module (in place)."""
    expected = benchmark.entries_for(benchmark.expected_failures, module, config_file)
    expected_skips = benchmark.entries_for(benchmark.expected_skips, module, config_file)

    unexpected: list[str] = []
    matched: list[dict[str, Any]] = []
    for finding in module.findings:
        hit = next((e for e in expected if _finding_matches(e, finding.condition, finding.block, finding.result)), None)
        if hit is not None:
            matched.append(hit)
        elif finding.result == "FAILURE" or (finding.result == "WARNING" and warning_policy == "fail"):
            unexpected.append(f"{finding.result}: {finding.condition}")
    stale = [e for e in expected if e not in matched and not e.get("condition", "").startswith("icg:")]

    result = module.suite_result

    def set_verdict(verdict: Verdict, reason: str, issue_entries: list[dict[str, Any]] | None = None) -> ModuleResult:
        module.verdict = verdict.value
        module.verdict_reason = reason
        module.issue = _issues(issue_entries or [])
        return module

    # A module INTERRUPTED by a failing condition during setup is a conformance failure
    # (it has FAILURE findings); only modules without a result are infrastructure problems.
    interrupted_by_failure = module.status == "INTERRUPTED" and result == SuiteResult.FAILED.value and bool(module.findings)
    if (module.status != "FINISHED" and not interrupted_by_failure) or result in ("", SuiteResult.UNKNOWN.value):
        incomplete_entries = [e for e in expected if e.get("condition") == INCOMPLETE] + expected_skips
        if incomplete_entries:
            return set_verdict(Verdict.KNOWN_ISSUE, f"did not complete ({module.status}); expected by benchmark", incomplete_entries)
        return set_verdict(Verdict.INCOMPLETE, f"module did not finish (status={module.status}, result={result or 'none'})")

    if result == SuiteResult.SKIPPED.value:
        reason = "skipped by suite" + (" (expected)" if expected_skips else "")
        return set_verdict(Verdict.SKIP, reason, expected_skips)

    if result == SuiteResult.FAILED.value:
        if expected_skips:
            return set_verdict(Verdict.KNOWN_ISSUE, "failed; module listed in expected skips", expected_skips)
        if unexpected:
            return set_verdict(Verdict.FAIL, "unexpected " + "; ".join(unexpected))
        if matched:
            return set_verdict(Verdict.KNOWN_ISSUE, f"{len(matched)} failure(s) match the benchmark", matched)
        return set_verdict(Verdict.FAIL, "suite result FAILED without a matching benchmark entry")

    if unexpected:
        # WARNING result with warning_policy=fail, or failures logged on a non-failed module.
        return set_verdict(Verdict.FAIL, "unexpected " + "; ".join(unexpected))

    if result == SuiteResult.REVIEW.value:
        evidence = module.review_evidence
        if review_policy == "pass":
            return set_verdict(Verdict.PASS, "REVIEW accepted by policy")
        if review_policy == "fail":
            return set_verdict(Verdict.FAIL, "REVIEW rejected by strict policy")
        if not evidence:
            return set_verdict(Verdict.INCOMPLETE, "REVIEW result has no automated evidence (needs human review)")
        mismatch_entries = [e for e in expected if e.get("condition") == REVIEW_MISMATCH]
        if evidence.get("matched"):
            if mismatch_entries:
                return set_verdict(
                    Verdict.STALE_BENCHMARK,
                    "REVIEW now resolves correctly, but the benchmark still expects a mismatch - remove it",
                    mismatch_entries,
                )
            return set_verdict(
                Verdict.PASS,
                f"REVIEW resolved: Inji result {evidence.get('actual')} matches expected {evidence.get('expected')}",
            )
        reason = f"REVIEW resolved: Inji result {evidence.get('actual')} but test expected {evidence.get('expected')}"
        if mismatch_entries:
            return set_verdict(Verdict.KNOWN_ISSUE, reason, mismatch_entries)
        return set_verdict(Verdict.FAIL, reason)

    # PASSED or WARNING
    if stale:
        return set_verdict(
            Verdict.STALE_BENCHMARK,
            f"passed, but the benchmark still expects {len(stale)} failure(s) - remove them",
            stale,
        )
    if result == SuiteResult.WARNING.value:
        return set_verdict(Verdict.PASS, "passed with warnings (warning policy: pass)")
    return set_verdict(Verdict.PASS, "passed")

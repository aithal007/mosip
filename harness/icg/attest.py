"""in-toto Test Result attestation for a harness run.

The statement binds the gate outcome to the exact artifacts that were tested (for
example container image digests). CI signs it with ``cosign attest-blob`` so anyone can
verify which Inji build passed which conformance plans.
Predicate spec: https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md
"""

from __future__ import annotations

from typing import Any

from .model import RunResult, Verdict

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://in-toto.io/attestation/test-result/v0.1"


def parse_subjects(values: list[str]) -> list[dict[str, Any]]:
    """``name=sha256:<hex>`` -> in-toto ResourceDescriptor."""
    subjects = []
    for value in values:
        name, _, digest = value.partition("=")
        algorithm, _, hex_value = digest.partition(":")
        if not (name and algorithm and hex_value):
            raise ValueError(f"Subject must look like name=sha256:<hex>, got {value!r}")
        subjects.append({"name": name, "digest": {algorithm: hex_value}})
    return subjects


def build_statement(run: RunResult, subjects: list[dict[str, Any]], results_uri: str = "") -> dict[str, Any]:
    gating_plans = {p.plan_id for p in run.plans if p.gating}
    passed, warned, failed = [], [], []
    for module in run.modules:
        if module.plan_id not in gating_plans:
            continue
        name = f"{module.component}/{module.plan_name}/{module.module_name}"
        if module.verdict in (Verdict.PASS.value, Verdict.STALE_BENCHMARK.value):
            (warned if module.suite_result in ("WARNING", "REVIEW") else passed).append(name)
        elif module.verdict in (Verdict.FAIL.value, Verdict.INCOMPLETE.value):
            failed.append(name)
        else:  # KNOWN_ISSUE / SKIP are accepted by the benchmark
            warned.append(name)

    predicate: dict[str, Any] = {
        "result": "PASSED" if run.is_gate_passing() else "FAILED",
        "configuration": [
            {"name": f"{p.component}:{p.plan_name}", "annotations": {"variant": p.variant, "planId": p.plan_id, "gating": p.gating}}
            for p in run.plans
        ],
        "passedTests": sorted(passed),
        "warnedTests": sorted(warned),
        "failedTests": sorted(failed),
    }
    if results_uri:
        predicate["url"] = results_uri
    return {"_type": STATEMENT_TYPE, "subject": subjects, "predicateType": PREDICATE_TYPE, "predicate": predicate}

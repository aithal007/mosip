"""Result model shared by the runner, the benchmark gate, reports and the Java bridge.

The JSON produced by :func:`RunResult.to_dict` is a public contract: the TestNG
``OpenIDConformanceTest`` classes parse it, so field names must stay stable.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


class SuiteResult(str, Enum):
    """Result values reported by the conformance suite (TestModule.Result)."""

    PASSED = "PASSED"
    FAILED = "FAILED"
    WARNING = "WARNING"
    REVIEW = "REVIEW"
    SKIPPED = "SKIPPED"
    UNKNOWN = "UNKNOWN"


class Verdict(str, Enum):
    """Harness verdict after applying the benchmark. This is what gates CI.

    PASS             - conformant (suite PASSED, or WARNING/REVIEW accepted by policy)
    FAIL             - regression: a failure that is not in the benchmark
    KNOWN_ISSUE      - failure that the benchmark expects (linked to a tracked issue)
    STALE_BENCHMARK  - benchmark expected a failure but the module now passes
    SKIP             - suite skipped the module, or it did not apply to the variant
    INCOMPLETE       - module never reached FINISHED (timeout, interrupted, handoff failed)
    """

    PASS = "PASS"
    FAIL = "FAIL"
    KNOWN_ISSUE = "KNOWN_ISSUE"
    STALE_BENCHMARK = "STALE_BENCHMARK"
    SKIP = "SKIP"
    INCOMPLETE = "INCOMPLETE"

    @property
    def is_blocking(self) -> bool:
        return self in (Verdict.FAIL, Verdict.INCOMPLETE)


@dataclass
class Finding:
    """A single FAILURE or WARNING log entry from a module."""

    condition: str
    result: str
    message: str
    block: str = ""
    requirements: list[str] = field(default_factory=list)


@dataclass
class ModuleResult:
    component: str
    plan_name: str
    plan_id: str
    module_name: str
    module_id: str
    variant: dict[str, str]
    status: str
    suite_result: str
    verdict: str = Verdict.INCOMPLETE.value
    verdict_reason: str = ""
    issue: str = ""
    duration_seconds: float = 0.0
    log_url: str = ""
    findings: list[Finding] = field(default_factory=list)
    requirements: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    review_evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        """Stable identity used for diffs: component + plan + module + variant."""
        variant = ",".join(f"{k}={v}" for k, v in sorted(self.variant.items()))
        return f"{self.component}|{self.plan_name}|{self.module_name}|{variant}"

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "ModuleResult":
        data = dict(data)
        data["findings"] = [Finding(**f) for f in data.get("findings", [])]
        return ModuleResult(**data)


@dataclass
class PlanRun:
    component: str
    plan_name: str
    plan_id: str
    variant: dict[str, str]
    config_file: str
    gating: bool
    plan_url: str = ""
    export_file: str = ""
    runner_exit_code: int | None = None
    selected_modules: list[str] = field(default_factory=list)


@dataclass
class RunResult:
    run_id: str
    started_at: str
    finished_at: str
    mode: str
    components: list[str]
    suite_version: str
    environment: dict[str, str]
    plans: list[PlanRun] = field(default_factory=list)
    modules: list[ModuleResult] = field(default_factory=list)
    shims: list[dict[str, str]] = field(default_factory=list)

    def summary(self, gating_only: bool = False) -> dict[str, int]:
        counts = {v.value: 0 for v in Verdict}
        gating_plans = {p.plan_id for p in self.plans if p.gating}
        for module in self.modules:
            if gating_only and module.plan_id not in gating_plans:
                continue
            counts[module.verdict] = counts.get(module.verdict, 0) + 1
        counts["TOTAL"] = sum(counts[v.value] for v in Verdict)
        return counts

    def is_gate_passing(self) -> bool:
        """The gate only considers plans marked gating (the certification-readiness
        HAIP plans are report-only by design)."""
        gating = [p for p in self.plans if p.gating]
        if not gating:
            return False
        for plan in gating:
            # A gating plan that was never created, or produced no modules, is never a pass.
            if not plan.plan_id or not any(m.plan_id == plan.plan_id for m in self.modules):
                return False
        gating_ids = {p.plan_id for p in gating}
        return not any(
            Verdict(m.verdict).is_blocking for m in self.modules if m.plan_id in gating_ids
        )

    def missing_plans(self) -> list[PlanRun]:
        """Gating plans that did not run or yielded no module results (infrastructure problem)."""
        return [
            p for p in self.plans
            if p.gating and (not p.plan_id or not any(m.plan_id == p.plan_id for m in self.modules))
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": SCHEMA_VERSION,
            **asdict(self),
            "summary": self.summary(),
            "gatingSummary": self.summary(gating_only=True),
            "gatePassed": self.is_gate_passing(),
        }

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @staticmethod
    def load(path: Path) -> "RunResult":
        data = json.loads(path.read_text(encoding="utf-8"))
        for derived in ("schemaVersion", "summary", "gatingSummary", "gatePassed"):
            data.pop(derived, None)
        data["plans"] = [PlanRun(**p) for p in data.get("plans", [])]
        data["modules"] = [ModuleResult.from_dict(m) for m in data.get("modules", [])]
        return RunResult(**data)

"""Specification coverage map built from the suite's own requirement tags.

Every condition the suite evaluates is annotated with spec references such as
``OID4VP-1FINAL-8.2`` or ``OID4VCI-1FINAL-4.1``. Aggregating those tags across a run
shows which clauses were exercised, which of them failed, and (when a clause index is
supplied) which normative clauses no test touched at all.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from .model import RunResult

_REQ = re.compile(r"^(?P<spec>[A-Z0-9]+(?:-[A-Z0-9]+)*?)-(?P<section>\d+(?:\.\d+)*)$")


@dataclass
class ClauseCoverage:
    requirement: str
    spec: str
    section: str
    components: set[str] = field(default_factory=set)
    modules: set[str] = field(default_factory=set)
    failing_modules: set[str] = field(default_factory=set)
    warning_modules: set[str] = field(default_factory=set)

    @property
    def state(self) -> str:
        if self.failing_modules:
            return "failing"
        if self.warning_modules:
            return "warning"
        return "passing"


def split_requirement(requirement: str) -> tuple[str, str]:
    match = _REQ.match(requirement)
    if not match:
        return requirement, ""
    return match.group("spec"), match.group("section")


def _section_key(section: str) -> tuple[int, ...]:
    return tuple(int(p) for p in section.split(".") if p.isdigit())


def build_coverage(run: RunResult) -> list[ClauseCoverage]:
    clauses: dict[str, ClauseCoverage] = {}
    for module in run.modules:
        label = f"{module.component}:{module.module_name}"
        failing = {r for f in module.findings if f.result == "FAILURE" for r in f.requirements}
        warning = {r for f in module.findings if f.result == "WARNING" for r in f.requirements}
        for requirement in module.requirements:
            spec, section = split_requirement(requirement)
            clause = clauses.setdefault(requirement, ClauseCoverage(requirement, spec, section))
            clause.components.add(module.component)
            clause.modules.add(label)
            if requirement in failing:
                clause.failing_modules.add(label)
            elif requirement in warning:
                clause.warning_modules.add(label)
    return sorted(clauses.values(), key=lambda c: (c.spec, _section_key(c.section), c.requirement))


def coverage_by_spec(clauses: list[ClauseCoverage]) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = defaultdict(lambda: {"passing": 0, "warning": 0, "failing": 0})
    for clause in clauses:
        summary[clause.spec][clause.state] += 1
    return dict(sorted(summary.items()))

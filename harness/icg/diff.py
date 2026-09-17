"""Semantic diff between two harness runs (results.json files).

Unlike upstream ``compare-results.py`` (which diffs condition sequences), this diff is
about gate-relevant changes: regressions, fixes, new/removed modules, and changes in
the set of failing conditions of modules that are still failing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import ModuleResult, RunResult, Verdict

_GOOD = {Verdict.PASS.value, Verdict.STALE_BENCHMARK.value, Verdict.SKIP.value}
_BAD = {Verdict.FAIL.value, Verdict.INCOMPLETE.value}


@dataclass
class Change:
    key: str
    component: str
    module: str
    before: str
    after: str
    detail: str = ""


@dataclass
class RunDiff:
    baseline_run: str
    current_run: str
    regressions: list[Change] = field(default_factory=list)
    fixes: list[Change] = field(default_factory=list)
    changed: list[Change] = field(default_factory=list)
    added: list[Change] = field(default_factory=list)
    removed: list[Change] = field(default_factory=list)
    unchanged: int = 0

    @property
    def has_regressions(self) -> bool:
        return bool(self.regressions)

    def to_markdown(self) -> str:
        lines = [
            f"### Conformance diff `{self.baseline_run}` → `{self.current_run}`",
            "",
            f"| Regressions | Fixes | Changed | Added | Removed | Unchanged |",
            f"|---|---|---|---|---|---|",
            f"| {len(self.regressions)} | {len(self.fixes)} | {len(self.changed)} | {len(self.added)} | {len(self.removed)} | {self.unchanged} |",
        ]
        for title, items in (
            ("🔴 Regressions", self.regressions),
            ("🟢 Fixes", self.fixes),
            ("🟡 Changed", self.changed),
            ("➕ Added", self.added),
            ("➖ Removed", self.removed),
        ):
            if not items:
                continue
            lines += ["", f"**{title}**", "", "| Component | Module | Before | After | Detail |", "|---|---|---|---|---|"]
            lines += [f"| {c.component} | `{c.module}` | {c.before} | {c.after} | {c.detail} |" for c in items]
        return "\n".join(lines) + "\n"


def _failing_conditions(module: ModuleResult) -> set[str]:
    return {f.condition for f in module.findings if f.result == "FAILURE"}


def diff_runs(baseline: RunResult, current: RunResult) -> RunDiff:
    before = {m.key: m for m in baseline.modules}
    after = {m.key: m for m in current.modules}
    result = RunDiff(baseline.run_id, current.run_id)

    for key, new in after.items():
        old = before.get(key)
        if old is None:
            result.added.append(Change(key, new.component, new.module_name, "-", new.verdict))
            continue
        if old.verdict != new.verdict:
            change = Change(key, new.component, new.module_name, old.verdict, new.verdict, new.verdict_reason)
            if new.verdict in _BAD and old.verdict not in _BAD:
                result.regressions.append(change)
            elif old.verdict in _BAD and new.verdict in _GOOD | {Verdict.KNOWN_ISSUE.value}:
                result.fixes.append(change)
            else:
                result.changed.append(change)
            continue
        gained = _failing_conditions(new) - _failing_conditions(old)
        lost = _failing_conditions(old) - _failing_conditions(new)
        if gained or lost:
            detail = "; ".join(filter(None, [
                ("new failures: " + ", ".join(sorted(gained))) if gained else "",
                ("no longer failing: " + ", ".join(sorted(lost))) if lost else "",
            ]))
            target = result.regressions if gained and new.verdict in _BAD | {Verdict.KNOWN_ISSUE.value} else result.changed
            target.append(Change(key, new.component, new.module_name, old.verdict, new.verdict, detail))
            continue
        result.unchanged += 1

    for key, old in before.items():
        if key not in after:
            result.removed.append(Change(key, old.component, old.module_name, old.verdict, "-"))
    return result

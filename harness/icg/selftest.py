"""Measure the negative probes with mutation testing.

A reference verifier rejects every tampered presentation. For each of its rules we build a
*mutant* with that one rule switched off and run the same probe set against it. A probe set
that still reports all-PASS against a mutant could not detect that bug - a blind spot.

    kill rate = mutants caught / mutants built

The strict verifier itself must produce no FAIL and no SKIP, otherwise the probes disagree
with the reference and the score means nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx
from cryptography.hazmat.primitives.asymmetric import ec

from .court.fixtures import Fixture, FixtureResult, load_fixtures, replay
from .probe import probe_sdjwt_corpus
from .refverifier import RULES, MockInjiVerify, ReferenceVerifier
from .settings import Settings


@dataclass
class MutantResult:
    rule: str
    killed: bool
    caught_by: list[str]


@dataclass
class SelfTestReport:
    baseline_clean: bool
    baseline_detail: str
    mutants: list[MutantResult]
    fixture_results: list[FixtureResult] = field(default_factory=list)

    @property
    def kill_rate(self) -> float:
        return sum(m.killed for m in self.mutants) / len(self.mutants) if self.mutants else 0.0

    @property
    def survivors(self) -> list[str]:
        return [m.rule for m in self.mutants if not m.killed]


def _run(settings: Settings, disabled: frozenset[str]):
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    from .handoff.verify import VerifyHandoff

    audience = VerifyHandoff(settings).client_id
    verifier = ReferenceVerifier(issuer_key.public_key(), disabled)
    transport = httpx.MockTransport(MockInjiVerify(verifier, audience))
    with httpx.Client(transport=transport) as client:
        return probe_sdjwt_corpus(client, settings, issuer_key)


def run_selftest(settings: Settings) -> SelfTestReport:
    """Mutation score = mutants killed by the probe corpus + by the Court's frozen fixtures.

    A fixture with ``rule == R`` kills mutant R by definition: it freezes, byte-exactly,
    a presentation the strict reference rejects and every other mutant accepts. A fixture
    that no longer replays (operator or verifier drift) makes the whole selftest fail,
    because only deterministic, reproduced findings count.
    """
    fixture_results = replay(load_fixtures())
    fixture_killers: dict[str, list[str]] = {}
    for fix, result in zip(load_fixtures(), fixture_results):
        if result.ok and fix.rule:
            fixture_killers.setdefault(fix.rule, []).append(f"fixture:{fix.id}")

    baseline = _run(settings, frozenset())
    clean = bool(baseline) and all(r.status == "PASS" for r in baseline) and all(fr.ok for fr in fixture_results)
    detail = f"{len(baseline)} probes + {len(fixture_results)} fixtures"
    mutants = []
    for rule in RULES:
        caught = [r.name for r in _run(settings, frozenset({rule})) if r.status == "FAIL"]
        by_fixture = fixture_killers.get(rule, [])
        mutants.append(MutantResult(rule, bool(caught or by_fixture), caught + by_fixture))
    return SelfTestReport(clean, detail, mutants, fixture_results)


def to_markdown(report: SelfTestReport) -> str:
    lines = [
        "## Probe self-test (mutation score)",
        "",
        f"Strict reference verifier: {'all probes PASS, all fixtures replay' if report.baseline_clean else 'PROBES/FIXTURES DISAGREE WITH REFERENCE'} ({report.baseline_detail}).",
        f"**Mutants caught: {sum(m.killed for m in report.mutants)}/{len(report.mutants)} ({report.kill_rate:.0%})**"
        + ("" if report.baseline_clean else " - score meaningless until baseline is clean"),
        "",
        "| Rule disabled | Caught | By probe(s) |",
        "|---|---|---|",
    ]
    for m in report.mutants:
        lines.append(f"| `{m.rule}` | {'yes' if m.killed else '**NO - blind spot**'} | {', '.join(m.caught_by) or '-'} |")
    failed_fixtures = [fr.id for fr in report.fixture_results if not fr.ok]
    if failed_fixtures:
        lines.append("")
        lines.append(f"**Frozen fixtures that no longer replay: {', '.join(failed_fixtures)}**")
    return "\n".join(lines)

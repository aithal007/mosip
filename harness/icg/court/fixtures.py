"""Replay of frozen Holder's Court findings: pure Python, no AI in the loop.

A fixture freezes one accepted finding: the operator chain + seed + context that rebuilds
the presentation byte-for-byte, the reference-verifier rule that catches it, and the full
expected verdict matrix (strict verifier plus every single-rule-disabled mutant). Replay
rebuilds the presentation, re-derives every verdict with :class:`ReferenceVerifier` and
accepts the fixture only when the frozen matrix reproduces exactly.

Files live in ``conformance/court/fixtures/*.json``. Agent-proposed findings land in
``conformance/court/pending/`` and reach ``fixtures/`` only through a human
(``icg court promote``); only promoted fixtures run in CI and pytest.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from ..refverifier import ReferenceVerifier, RULES
from ..sdjwt_corpus import Context, Case
from ..settings import REPO_ROOT
from .operators import build_attack, derive_keys, OPERATORS

FIXTURE_DIR = REPO_ROOT / "conformance" / "court" / "fixtures"
PENDING_DIR = REPO_ROOT / "conformance" / "court" / "pending"

REQUIRED_FIELDS = ("id", "clause", "operator_chain", "seed", "context", "expected", "source", "confirmed_by")


@dataclass
class Fixture:
    id: str
    clause: str
    operator_chain: list[str]
    seed: int
    context: dict
    expected: dict[str, str]      # rule that would be disabled -> expected verdict ("accept"/"reject")
    source: str                   # "human" or "agent:<role>@<model>"
    confirmed_by: str             # who promoted it, e.g. "human:2026-11-02"
    referee_opinion: str = ""
    # sha256 of the frozen presentation bytes. Replay rebuilds from chain + seed + context
    # and must reproduce this digest, so verifier/operator drift cannot pass silently.
    presentation_sha256: str = ""
    path: Path | None = None

    @property
    def rule(self) -> str | None:
        """The reference rule this fixture exists to keep killed."""
        rules = [r for r, verdict in self.expected.items() if verdict == "accept"]
        return rules[0] if len(rules) == 1 else None

    def case(self) -> Case:
        return build_attack(
            self.operator_chain, Context(**self.context), self.seed,
            name=self.id, description=self.clause, source=self.clause,
        )

    def to_json(self) -> dict:
        data = {
            "id": self.id, "clause": self.clause, "operator_chain": self.operator_chain,
            "seed": self.seed, "context": self.context, "expected": dict(self.expected),
            "source": self.source, "confirmed_by": self.confirmed_by,
        }
        if self.referee_opinion:
            data["referee_opinion"] = self.referee_opinion
        if self.presentation_sha256:
            data["presentation_sha256"] = self.presentation_sha256
        return data


def load_dir(directory: Path = FIXTURE_DIR) -> list[Fixture]:
    fixtures = []
    for path in sorted(directory.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        missing = [name for name in REQUIRED_FIELDS if name not in data]
        if missing:
            raise ValueError(f"{path.name}: missing fields {', '.join(missing)}")
        fixtures.append(Fixture(
            id=data["id"], clause=data["clause"], operator_chain=data["operator_chain"],
            seed=data["seed"], context=data["context"], expected=data["expected"],
            source=data["source"], confirmed_by=data["confirmed_by"],
            referee_opinion=data.get("referee_opinion", ""),
            presentation_sha256=data.get("presentation_sha256", ""), path=path,
        ))
    return fixtures


def compute_matrix(chain: list[str], seed: int, context: dict, *, issuer_key: ec.EllipticCurvePrivateKey | None = None) -> dict[str, str]:
    """Verdict of the rebuilt presentation against the strict verifier and every mutant."""
    case = build_attack(chain, Context(**context), seed, issuer_key=issuer_key)
    public = (issuer_key or derive_keys(seed)[0]).public_key()
    matrix: dict[str, str] = {}
    for rule in RULES:
        try:
            ReferenceVerifier(public, frozenset({rule})).verify(
                case.presentation, nonce=context["nonce"], audience=context["audience"], now=context["now"])
            matrix[rule] = "accept"
        except Exception:
            matrix[rule] = "reject"
    return matrix


@dataclass
class FixtureResult:
    id: str
    ok: bool
    rule: str | None
    problems: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        return "PASS" if self.ok else "FAIL"


def replay(fixtures: list[Fixture]) -> list[FixtureResult]:
    """Rebuild every fixture's bytes and re-derive every verdict. Deterministic code decides."""
    results = []
    for fix in fixtures:
        problems: list[str] = []
        rule = fix.rule
        try:
            case = fix.case()
        except Exception as exc:  # unknown operator, bad context, ...
            results.append(FixtureResult(fix.id, False, rule, [f"cannot rebuild: {exc}"]))
            continue
        rebuilt = build_attack(fix.operator_chain, Context(**fix.context), fix.seed)
        if rebuilt.presentation != case.presentation:
            problems.append("presentation not reproducible from chain + seed + context")
        if fix.presentation_sha256:
            digest_ = hashlib.sha256(case.presentation.encode("ascii")).hexdigest()
            if digest_ != fix.presentation_sha256:
                problems.append(f"frozen presentation changed (sha256 {digest_[:12]} != {fix.presentation_sha256[:12]})")
        matrix = compute_matrix(fix.operator_chain, fix.seed, fix.context)
        if matrix != fix.expected:
            differ = [r for r in matrix if matrix.get(r) != fix.expected.get(r)]
            problems.append(f"frozen matrix disagrees with recomputation: {', '.join(differ)}")
        if rule is None:
            problems.append(f"expected matrix must flip exactly one rule (got {[r for r, v in fix.expected.items() if v == 'accept']})")
        results.append(FixtureResult(fix.id, not problems, rule, problems))
    return results


def load_fixtures() -> list[Fixture]:
    return load_dir(FIXTURE_DIR)


def write_fixture(fix: Fixture, directory: Path = PENDING_DIR) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{fix.id}.json"
    path.write_text(json.dumps(fix.to_json(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path

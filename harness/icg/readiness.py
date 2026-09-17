"""Certification-readiness gap report.

OpenID self-certification for OID4VCI / OID4VP only counts the HAIP profile plans.
Each manifest lists those plans with the capabilities they require and whether Inji
supports them today (with the tracking issue). This module turns that into a report
that tells maintainers exactly what blocks certification.
"""

from __future__ import annotations

from dataclasses import dataclass

from .manifest import ComponentManifest


@dataclass
class GapRow:
    component: str
    plan_id: str
    plan_name: str
    capability: str
    supported: bool
    issue: str
    note: str


def gap_rows(manifests: list[ComponentManifest]) -> list[GapRow]:
    rows: list[GapRow] = []
    for manifest in manifests:
        for spec in manifest.readiness:
            for capability in spec.requires:
                rows.append(
                    GapRow(
                        component=manifest.component,
                        plan_id=spec.id,
                        plan_name=spec.plan_name,
                        capability=capability.name,
                        supported=capability.supported,
                        issue=capability.issue,
                        note=capability.note,
                    )
                )
    return rows


def readiness_markdown(manifests: list[ComponentManifest]) -> str:
    lines = ["## Certification readiness (HAIP profile plans)", ""]
    for manifest in manifests:
        for spec in manifest.readiness:
            missing = spec.missing
            status = "✅ ready to run" if not missing else f"⛔ blocked by {len(missing)} capability gap(s)"
            lines += [f"### {manifest.display_name} — `{spec.plan_name}`", "", f"{spec.description}", "", f"**Status:** {status}", ""]
            lines += ["| Capability | Supported | Tracking issue | Note |", "|---|---|---|---|"]
            for c in spec.requires:
                lines.append(f"| {c.name} | {'✅' if c.supported else '❌'} | {c.issue or '—'} | {c.note} |")
            lines.append("")
    return "\n".join(lines)

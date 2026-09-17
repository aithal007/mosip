"""Plan manifests (``conformance/plans/<component>.json``) and config templating."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .settings import REPO_ROOT

PLANS_DIR = REPO_ROOT / "conformance" / "plans"
_VAR = re.compile(r"\$\{([A-Z0-9_]+)\}")


@dataclass
class PlanSpec:
    id: str
    plan_name: str
    variant: dict[str, str]
    config: Path
    gating: bool = True
    modules: list[str] = field(default_factory=list)
    description: str = ""

    def cli_selector(self) -> str:
        """``plan[k=v][k=v]:mod1,mod2`` as understood by run-test-plan.py's parser."""
        selector = self.plan_name + "".join(f"[{k}={v}]" for k, v in self.variant.items())
        if self.modules:
            selector += ":" + ",".join(self.modules)
        return selector


@dataclass
class Capability:
    name: str
    supported: bool
    issue: str = ""
    note: str = ""


@dataclass
class ReadinessSpec:
    """A certification-profile plan (e.g. HAIP) that is only run once every required
    capability is supported. Until then it feeds the certification gap report."""

    id: str
    plan_name: str
    variant: dict[str, str]
    requires: list[Capability]
    description: str = ""
    config: Path | None = None

    @property
    def missing(self) -> list[Capability]:
        return [c for c in self.requires if not c.supported]

    def as_plan(self) -> PlanSpec | None:
        if self.missing or self.config is None:
            return None
        return PlanSpec(self.id, self.plan_name, self.variant, self.config, gating=False, description=self.description)


@dataclass
class ComponentManifest:
    component: str
    display_name: str
    plans: list[PlanSpec]
    readiness: list[ReadinessSpec]
    expected_failures: Path
    expected_skips: Path
    # Environment workarounds that let the rest of a plan run despite a known gap.
    # They are always surfaced in reports so a passing gate never hides them.
    shims: list[dict[str, str]] = field(default_factory=list)

    @staticmethod
    def load(component: str, plans_dir: Path = PLANS_DIR) -> "ComponentManifest":
        path = plans_dir / f"{component}.json"
        if not path.exists():
            raise FileNotFoundError(f"No plan manifest for component '{component}' at {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        plans = [
            PlanSpec(
                id=p["id"],
                plan_name=p["planName"],
                variant=p.get("variant", {}),
                config=REPO_ROOT / p["config"],
                gating=p.get("gating", True),
                modules=p.get("modules", []),
                description=p.get("description", ""),
            )
            for p in data["plans"]
        ]
        readiness = [
            ReadinessSpec(
                id=r["id"],
                plan_name=r["planName"],
                variant=r.get("variant", {}),
                requires=[Capability(**c) for c in r.get("requires", [])],
                description=r.get("description", ""),
                config=(REPO_ROOT / r["config"]) if r.get("config") else None,
            )
            for r in data.get("readiness", [])
        ]
        return ComponentManifest(
            component=data["component"],
            display_name=data.get("displayName", component),
            plans=plans,
            readiness=readiness,
            expected_failures=REPO_ROOT / data["benchmark"]["expectedFailures"],
            expected_skips=REPO_ROOT / data["benchmark"]["expectedSkips"],
            shims=list(data.get("shims", [])),
        )


def render_config(template: Path, variables: dict[str, str], alias: str, description: str, out_dir: Path) -> Path:
    """Substitute ``${VAR}`` placeholders and stamp a run-unique alias.

    ``{BASEURL}``-style placeholders are left for run-test-plan.py to substitute.
    A unique alias per plan keeps callback URLs (``/test/a/<alias>/...``) distinct, so
    plans of different components can run in parallel without colliding.
    """

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in variables:
            raise KeyError(f"{template.name}: no value for ${{{name}}}")
        return variables[name]

    text = _VAR.sub(replace, template.read_text(encoding="utf-8"))
    # The template may contain run-test-plan placeholders such as {vp-signing-jwk.json}
    # that are not valid JSON yet, so the alias is injected textually.
    alias_line = f'"alias": {json.dumps(alias)},\n    "description": {json.dumps(description)},'
    text = re.sub(r'"alias"\s*:\s*"[^"]*"\s*,', "", text, count=1)
    text = re.sub(r'"description"\s*:\s*"[^"]*"\s*,', "", text, count=1)
    text = text.replace("{", "{\n    " + alias_line, 1)

    out_dir.mkdir(parents=True, exist_ok=True)
    rendered = out_dir / template.name
    rendered.write_text(text, encoding="utf-8")
    return rendered


def load_json_config(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))

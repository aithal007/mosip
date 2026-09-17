"""Collect per-module results from the suite and apply the benchmark."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from .benchmark import Benchmark, classify
from .handoff import Ledger
from .model import Finding, ModuleResult, PlanRun
from .settings import Settings
from .suite_api import SuiteApi

log = logging.getLogger(__name__)


def _variant_dict(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    return {}


def _log_duration(entries: list[dict[str, Any]]) -> float:
    times = [e["time"] for e in entries if isinstance(e.get("time"), (int, float))]
    return round((max(times) - min(times)) / 1000.0, 1) if len(times) > 1 else 0.0


def summarise_log(entries: list[dict[str, Any]]) -> tuple[list[Finding], list[str], dict[str, int]]:
    """Extract FAILURE/WARNING findings, all referenced requirements, and result counts.

    Block names are resolved the same way run-test-plan.py does it, so benchmark
    ``current-block`` values match.
    """
    block_names: dict[str, str] = {}
    findings: list[Finding] = []
    requirements: set[str] = set()
    counts: dict[str, int] = {}
    for entry in entries:
        if entry.get("startBlock") and entry.get("src") == "-START-BLOCK-":
            block_names[str(entry.get("blockId"))] = str(entry.get("msg", ""))
            continue
        result = entry.get("result")
        if not result:
            continue
        counts[result] = counts.get(result, 0) + 1
        reqs = [str(r) for r in (entry.get("requirements") or [])]
        requirements.update(reqs)
        if result in ("FAILURE", "WARNING"):
            findings.append(
                Finding(
                    condition=str(entry.get("src", "")),
                    result=result,
                    message=str(entry.get("msg", ""))[:500],
                    block=block_names.get(str(entry.get("blockId")), "") if entry.get("blockId") else "",
                    requirements=reqs,
                )
            )
    return findings, sorted(requirements), counts


def collect_plan(
    api: SuiteApi,
    plan: PlanRun,
    benchmark: Benchmark,
    ledger: Ledger,
    settings: Settings,
) -> list[ModuleResult]:
    if not plan.plan_id:
        return []
    plan.plan_url = api.plan_detail_url(plan.plan_id)
    details = api.plan(plan.plan_id)
    ledger_state = ledger.snapshot()
    modules: list[ModuleResult] = []

    for module in details.get("modules", []):
        name = str(module.get("testModule", ""))
        if plan.selected_modules and name not in plan.selected_modules:
            continue  # not part of this run's module selection
        variant = {**plan.variant, **_variant_dict(module.get("variant"))}
        instances = module.get("instances") or []
        if not instances:
            result = ModuleResult(
                component=plan.component, plan_name=plan.plan_name, plan_id=plan.plan_id,
                module_name=name, module_id="", variant=variant, status="NOT_RUN", suite_result="",
            )
        else:
            module_id = str(instances[-1])
            info = api.module_info(module_id) or {}
            entries = api.module_log(module_id)
            findings, requirements, counts = summarise_log(entries)
            result = ModuleResult(
                component=plan.component,
                plan_name=plan.plan_name,
                plan_id=plan.plan_id,
                module_name=name,
                module_id=module_id,
                variant={**variant, **_variant_dict(info.get("variant"))},
                status=str(info.get("status", "")),
                suite_result=str(info.get("result") or ""),
                duration_seconds=_log_duration(entries),
                log_url=api.log_detail_url(module_id),
                findings=findings,
                requirements=requirements,
                counts=counts,
                review_evidence=dict(ledger_state.get(module_id, {}).get("reviewEvidence", {})),
            )
        classify(result, plan.config_file, benchmark, review_policy=settings.review_policy, warning_policy=settings.warning_policy)
        modules.append(result)
    return modules


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

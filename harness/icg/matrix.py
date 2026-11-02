"""Multi-version conformance test matrix.

Runs the same plan manifest against multiple OpenID specification versions
(e.g. OID4VP Draft 23, Draft 24, 1.0 Final) side by side. Cross-version
regression detection catches migration regressions: a pass on 1.0 Final +
fail on Draft 23 means behaviour changed between versions, which is a
regression even if each individual run passes its own benchmark.

Each spec version maps to different suite plan names and variant overrides.
The matrix runs each version independently and compares results using
the existing diff machinery.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .benchmark import Benchmark
from .cli import command_run, wait_until_ready
from .collect import collect_plan
from .diff import diff_runs, RunDiff
from .manifest import ComponentManifest, PlanSpec
from .model import ModuleResult, PlanRun, RunResult, Verdict
from .runner import ComponentRun
from .settings import Settings
from .suite_api import SuiteApi

log = logging.getLogger(__name__)

# Mapping of spec version -> plan name overrides and variant overrides per component.
# These are the plan names the upstream conformance suite offers for each version.
SPEC_VERSION_PLANS: dict[str, dict[str, dict[str, Any]]] = {
    "oid4vp-draft23": {
        "verify": {
            "plan_name": "oid4vp-draft23-verifier-test-plan",
            "variant_overrides": {
                "vp_profile": "plain_vp",
                "credential_format": "sd_jwt_vc",
                "client_id_prefix": "redirect_uri",
                "request_method": "url_query",
                "response_mode": "direct_post",
            },
        }
    },
    "oid4vp-draft24": {
        "verify": {
            "plan_name": "oid4vp-draft24-verifier-test-plan",
            "variant_overrides": {
                "vp_profile": "plain_vp",
                "credential_format": "sd_jwt_vc",
                "client_id_prefix": "redirect_uri",
                "request_method": "url_query",
                "response_mode": "direct_post",
            },
        }
    },
    "oid4vp-1final": {
        "verify": {
            "plan_name": "oid4vp-1final-verifier-test-plan",
            "variant_overrides": {
                "vp_profile": "plain_vp",
                "credential_format": "sd_jwt_vc",
                "client_id_prefix": "redirect_uri",
                "request_method": "url_query",
                "response_mode": "direct_post",
            },
        }
    },
    "oid4vci-1final": {
        "certify": {
            "plan_name": "oid4vci-1_0-issuer-test-plan",
            "variant_overrides": {
                "authorization_request_type": "simple",
                "client_auth_type": "private_key_jwt",
                "fapi_request_method": "unsigned",
                "sender_constrain": "dpop",
                "vci_authorization_code_flow_variant": "issuer_initiated",
                "vci_grant_type": "pre_authorization_code",
                "fapi_profile": "vci",
                "credential_format": "sd_jwt_vc",
                "vci_credential_encryption": "plain",
                "openid": "plain_oauth",
                "fapi_response_mode": "plain_response",
            },
        }
    },
}


@dataclass
class MatrixRunResult:
    """Result of one matrix version run."""

    version: str
    component: str
    run_id: str
    run_dir: Path
    result: RunResult
    exit_code: int


@dataclass
class MatrixResult:
    """Complete matrix result across all versions."""

    versions: list[str]
    component: str
    run_results: list[MatrixRunResult] = field(default_factory=list)
    diffs: list[RunDiff] = field(default_factory=list)
    migrations_regressions: list[Any] = field(default_factory=list)

    @property
    def all_passing(self) -> bool:
        return all(r.result.is_gate_passing() for r in self.run_results)

    @property
    def has_migration_regressions(self) -> bool:
        return bool(self.migrations_regressions)


def build_version_manifest(
    component: str, version: str, base_manifest: ComponentManifest
) -> ComponentManifest:
    """Create a manifest for a specific spec version by overriding plan names and variants."""
    version_config = SPEC_VERSION_PLANS.get(version, {}).get(component)
    if version_config is None:
        # No version-specific config; use base manifest as-is
        return base_manifest

    plan_name = version_config["plan_name"]
    variant_overrides = version_config["variant_overrides"]

    plans = []
    for plan in base_manifest.plans:
        variant = {**plan.variant, **variant_overrides}
        plans.append(
            PlanSpec(
                id=plan.id,
                plan_name=plan_name,
                variant=variant,
                config=plan.config,
                gating=plan.gating,
                modules=list(plan.modules),
                description=f"{plan.description} (spec version: {version})",
            )
        )

    return ComponentManifest(
        component=base_manifest.component,
        display_name=f"{base_manifest.display_name} ({version})",
        plans=plans,
        readiness=list(base_manifest.readiness),
        expected_failures=base_manifest.expected_failures,
        expected_skips=base_manifest.expected_skips,
        shims=list(base_manifest.shims),
    )


def run_matrix(
    settings: Settings,
    components: list[str],
    versions: list[str],
    run_dir: Path,
    args: Any,
) -> dict[str, MatrixResult]:
    """Run the conformance matrix: same plans against multiple spec versions.

    Returns {component: MatrixResult}.
    """
    results: dict[str, MatrixResult] = {}

    for component in components:
        base_manifest = ComponentManifest.load(component)
        matrix_result = MatrixResult(versions=versions, component=component)

        for version in versions:
            version_manifest = build_version_manifest(component, version, base_manifest)
            version_run_dir = run_dir / "matrix" / version / component
            version_run_dir.mkdir(parents=True, exist_ok=True)

            # Temporarily override args to point at this version's output
            class VersionArgs:
                pass

            vargs = VersionArgs()
            for attr in ("skip_wait", "no_seed", "wait_timeout", "plan_timeout", "readiness",
                         "parallel", "out", "baseline", "update_baseline", "combined"):
                setattr(vargs, attr, getattr(args, attr, False))
            vargs.component = component
            vargs.combined = False

            # Run via command_run would exit the process; instead we inline the logic
            # by calling run_component directly and building RunResult.
            from .cli import _components
            from .seed import seed_certify

            if not args.skip_wait and not wait_until_ready(settings, [component], args.wait_timeout):
                log.error("Services not ready for matrix run %s/%s", version, component)
                continue

            if component == "certify" and not args.no_seed and not seed_certify(settings):
                log.error("Certify seed failed for matrix run %s", version)
                continue

            from datetime import datetime, timezone
            from .collect import utc_now

            started = utc_now()
            from .handoff import Ledger
            from .adapter_protocol import ProtocolClient, SubprocessAdapter, PROTOCOL_HANDLERS
            from .handoff import ProtocolHandoffAdapter
            from .agent import HandoffAgent

            ledger = Ledger(version_run_dir / "handoff-ledger.json")
            handler_cls = PROTOCOL_HANDLERS[component]
            handler = handler_cls(settings, haip=args.haip)
            client = ProtocolClient(
                SubprocessAdapter(
                    command=["python", "-m", "icg.adapter_protocol_server", component, "--haip"] if args.haip else ["python", "-m", "icg.adapter_protocol_server", component],
                )
            )
            client.init_component(settings)
            adapter = ProtocolHandoffAdapter(settings, client)

            with HandoffAgent(settings, [adapter], ledger):
                component_runs: list[ComponentRun] = []
                for manifest_plan in version_manifest.plans:
                    # We need to adapt run_component to accept a manifest
                    run_component_result = run_component(
                        version_manifest, settings, version_run_dir, f"{version}-{component}",
                        include_readiness=args.readiness, timeout_seconds=args.plan_timeout,
                    )
                    component_runs.append(run_component_result)

            from .report import write_reports, markdown_summary
            from .diff import diff_runs as _diff_runs

            run = RunResult(
                run_id=f"{version}-{component}-{started}",
                started_at=started,
                finished_at=utc_now(),
                mode="matrix",
                components=[component],
                suite_version=settings.suite_version,
                environment={
                    "conformanceServer": settings.conformance_server,
                    "certifyPublicUrl": settings.certify_public_url if component == "certify" else "",
                    "verifyPublicUrl": settings.verify_public_url if component == "verify" else "",
                    "reviewPolicy": settings.review_policy,
                    "warningPolicy": settings.warning_policy,
                    "harnessVersion": settings.__class__.__name__,
                    "specVersion": version,
                },
                shims=[{"component": component, **s} for s in version_manifest.shims],
            )
            by_component = {component: version_manifest}
            with SuiteApi(settings.conformance_server, settings.conformance_token) as api:
                for component_run in component_runs:
                    manifest = version_manifest
                    benchmark = Benchmark.load(manifest.expected_failures, manifest.expected_skips)
                    for problem in benchmark.validate():
                        log.warning("benchmark: %s", problem)
                    for plan in component_run.plans:
                        run.plans.append(plan)
                        try:
                            run.modules.extend(
                                collect_plan(api, plan, benchmark, ledger, settings)
                            )
                        except Exception as exc:
                            log.error("Collecting plan %s failed: %s", plan.plan_id, exc)

            matrix_result.run_results.append(
                MatrixRunResult(
                    version=version,
                    component=component,
                    run_id=run.run_id,
                    run_dir=version_run_dir,
                    result=run,
                    exit_code=0 if run.is_gate_passing() else 1,
                )
            )
            client.shutdown()

        # Cross-version diff: compare each version against the first (baseline)
        if len(matrix_result.run_results) > 1:
            baseline = matrix_result.run_results[0].result
            for other in matrix_result.run_results[1:]:
                diff = diff_runs(baseline, other.result)
                matrix_result.diffs.append(diff)
                # Migration regression: baseline passes, other fails (or new blocking verdicts)
                for change in diff.regressions:
                    matrix_result.migrations_regressions.append(
                        {
                            "from_version": baseline.environment.get("specVersion", "baseline"),
                            "to_version": other.version,
                            "component": change.component,
                            "module": change.module,
                            "before": change.before,
                            "after": change.after,
                            "detail": change.detail,
                        }
                    )

        results[component] = matrix_result

    return results


def matrix_to_markdown(results: dict[str, MatrixResult]) -> str:
    """Render matrix results as Markdown."""
    lines = ["# Multi-Version Conformance Matrix", ""]
    for component, matrix_result in results.items():
        lines.append(f"## {component.title()}")
        lines.append("")
        lines.append("| Spec Version | Gate | Modules | Regressions | Known Issues | Stale |")
        lines.append("|---|---|---|---|---|---|")
        for run_result in matrix_result.run_results:
            summary = run_result.result.summary()
            gate = "PASS" if run_result.result.is_gate_passing() else "FAIL"
            lines.append(
                f"| {run_result.version} | {gate} | {summary['TOTAL']} | "
                f"{summary[Verdict.FAIL.value]} | {summary[Verdict.KNOWN_ISSUE.value]} | "
                f"{summary[Verdict.STALE_BENCHMARK.value]} |"
            )
        lines.append("")

        if matrix_result.migrations_regressions:
            lines.append("### Migration Regressions")
            lines.append("")
            lines.append("| From | To | Component | Module | Before | After | Detail |")
            lines.append("|---|---|---|---|---|---|---|")
            for r in matrix_result.migrations_regressions:
                lines.append(
                    f"| {r['from_version']} | {r['to_version']} | {r['component']} | "
                    f"{r['module']} | {r['before']} | {r['after']} | {r['detail']} |"
                )
            lines.append("")

    return "\n".join(lines) + "\n"


def matrix_to_json(results: dict[str, MatrixResult]) -> str:
    """Render matrix results as JSON."""
    output: dict[str, Any] = {}
    for component, matrix_result in results.items():
        output[component] = {
            "versions": matrix_result.versions,
            "all_passing": matrix_result.all_passing,
            "has_migration_regressions": matrix_result.has_migration_regressions,
            "run_results": [
                {
                    "version": r.version,
                    "run_id": r.run_id,
                    "gate_passed": r.result.is_gate_passing(),
                    "summary": r.result.summary(),
                }
                for r in matrix_result.run_results
            ],
            "migration_regressions": matrix_result.migrations_regressions,
        }
    return json.dumps(output, indent=2)

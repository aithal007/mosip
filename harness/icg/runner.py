"""Invoke the upstream ``run-test-plan.py`` for one component and map plan ids back."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from .manifest import ComponentManifest, PlanSpec, render_config
from .model import PlanRun
from .settings import Settings

log = logging.getLogger(__name__)

# Printed by run-test-plan.py for every plan whose config contains an alias. Recent
# versions prefix every line with a "YYYY-MM-DD HH:MM:SS " timestamp.
_TIMESTAMP = r"^(?:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} )?"
_ALIAS_LINE = re.compile(_TIMESTAMP + r"(?P<plan_id>[A-Za-z0-9]+): Config '(?P<config>.+)' contains alias '(?P<alias>[^']+)'")
_CREATED_LINE = re.compile(_TIMESTAMP + r"Created test plan, new id: (?P<plan_id>[A-Za-z0-9]+)")


@dataclass
class ComponentRun:
    component: str
    plans: list[PlanRun] = field(default_factory=list)
    exit_code: int | None = None
    log_file: Path | None = None


def parse_plan_ids(output_lines: list[str], config_files: list[str]) -> dict[str, str]:
    """Return {rendered config path: plan id} from run-test-plan.py output."""
    mapping: dict[str, str] = {}
    for line in output_lines:
        match = _ALIAS_LINE.match(line.strip())
        if match:
            mapping[os.path.normpath(match.group("config"))] = match.group("plan_id")
    if len(mapping) < len(config_files):
        # Fallback for configs without alias: plans are created in command-line order
        # when they share a queue, which is the case for a single component.
        created = [m.group("plan_id") for m in map(_CREATED_LINE.match, (l.strip() for l in output_lines)) if m]
        for config, plan_id in zip(config_files, created):
            mapping.setdefault(os.path.normpath(config), plan_id)
    return mapping


def discover_variables(settings: Settings, component: str) -> dict[str, str]:
    """Template variables read from the running component rather than configured.

    ``CERTIFY_ISSUER`` is the ``credential_issuer`` identifier Inji Certify advertises. It is
    deployment dependent (the docker-compose stack uses the bare origin, other deployments
    include a path), and the suite derives the metadata URL from it, so it must match exactly.
    """
    if component != "certify":
        return {}
    fallback = settings.certify_public_url
    try:
        response = httpx.get(f"{settings.certify_admin_url}/.well-known/openid-credential-issuer", timeout=15, verify=False)
        issuer = response.json().get("credential_issuer") if response.status_code == 200 else None
    except (httpx.HTTPError, ValueError):
        issuer = None
    if not issuer:
        log.warning("[certify] could not read credential_issuer from metadata; using %s", fallback)
    return {"CERTIFY_ISSUER": issuer or fallback}


def script_relative_path(path: Path, scripts_dir: Path) -> str:
    """Config path as passed to run-test-plan.py.

    Its command-line grammar uses ':' to introduce a module list, so an absolute Windows
    path such as ``C:\\runs\\cfg.json`` is mis-parsed. A path relative to the scripts
    directory (the subprocess cwd) with forward slashes contains no colon on any OS.
    """
    try:
        relative = os.path.relpath(path, scripts_dir)
    except ValueError as exc:  # different drive on Windows
        raise ValueError(
            f"Results directory {path} must be on the same drive as {scripts_dir} (run-test-plan.py cannot parse drive letters)"
        ) from exc
    return relative.replace("\\", "/")


def _benchmark_for_upstream(source: Path, target: Path) -> Path:
    """Copy a benchmark file without harness-only pseudo conditions (icg:*), which the
    upstream script would otherwise report as 'expected failure did not happen'."""
    entries = json.loads(source.read_text(encoding="utf-8") or "[]") if source.exists() else []
    upstream = [e for e in entries if not str(e.get("condition", "")).startswith("icg:")]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(upstream, indent=2), encoding="utf-8")
    return target


def run_component(
    manifest: ComponentManifest,
    settings: Settings,
    run_dir: Path,
    run_id: str,
    *,
    include_readiness: bool = False,
    timeout_seconds: int = 3600,
) -> ComponentRun:
    component = manifest.component
    plans: list[PlanSpec] = list(manifest.plans)
    if include_readiness:
        plans.extend(p for p in (r.as_plan() for r in manifest.readiness) if p is not None)

    scripts = settings.suite_scripts_dir
    script = scripts / "run-test-plan.py"
    if not script.exists():
        raise FileNotFoundError(
            f"{script} not found. Run scripts/bootstrap.sh (or set CONFORMANCE_SUITE_SCRIPTS) first."
        )

    variables = {**settings.template_variables(), **discover_variables(settings, component)}
    args: list[str] = []
    rendered: dict[str, PlanSpec] = {}
    for plan in plans:
        alias = f"icg-{run_id}-{plan.id}"[:60]
        config = render_config(
            plan.config,
            variables,
            alias=alias,
            description=f"Inji Conformance Gate {run_id}: {plan.id}",
            out_dir=run_dir / "configs" / plan.id,
        )
        config_arg = script_relative_path(config, scripts)
        args.extend([plan.cli_selector(), config_arg])
        rendered[os.path.normpath(config_arg)] = plan

    export_dir = run_dir / "exports" / component
    export_dir.mkdir(parents=True, exist_ok=True)
    failures = _benchmark_for_upstream(manifest.expected_failures, run_dir / "benchmark" / f"{component}-expected-failures.json")
    skips = _benchmark_for_upstream(manifest.expected_skips, run_dir / "benchmark" / f"{component}-expected-skips.json")

    command = [
        settings.python_executable or sys.executable,
        str(script),
        "--export-dir", str(export_dir),
        "--expected-failures-file", str(failures),
        "--expected-skips-file", str(skips),
        "--verbose",
        *args,
    ]
    env = dict(os.environ)
    env.update(
        {
            "CONFORMANCE_SERVER": settings.conformance_server,
            "CONFORMANCE_SERVER_MTLS": settings.conformance_server_mtls,
            "PYTHONUNBUFFERED": "1",
            "PYTHONIOENCODING": "utf-8",
        }
    )
    # run-test-plan.py aborts a plan after 3 consecutive modules fail to complete, assuming an
    # unhealthy suite. Against an implementation with setup-time gaps that hides every later
    # module, so allow a whole plan's worth unless the caller set it explicitly.
    env.setdefault("CONFORMANCE_MAX_CONSECUTIVE_FAILURES", "100")
    if settings.dev_mode:
        env["CONFORMANCE_DEV_MODE"] = "1"
    else:
        env["CONFORMANCE_TOKEN"] = settings.conformance_token

    log_file = run_dir / "logs" / f"{component}-run-test-plan.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    log.info("[%s] %s", component, " ".join(command))

    lines: list[str] = []
    with log_file.open("w", encoding="utf-8") as sink:
        process = subprocess.Popen(
            command, cwd=scripts, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
        )

        def pump() -> None:
            assert process.stdout is not None
            for line in process.stdout:
                lines.append(line.rstrip("\n"))
                sink.write(line)
                sink.flush()
                print(f"[{component}] {line}", end="", flush=True)

        reader = threading.Thread(target=pump, daemon=True)
        reader.start()
        try:
            exit_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            exit_code = -1
            log.error("[%s] run-test-plan.py exceeded %ss and was killed", component, timeout_seconds)
        reader.join(timeout=10)

    plan_ids = parse_plan_ids(lines, list(rendered))
    result = ComponentRun(component=component, exit_code=exit_code, log_file=log_file)
    for config_path, plan in rendered.items():
        plan_id = plan_ids.get(config_path, "")
        if not plan_id:
            log.error("[%s] could not determine plan id for %s", component, plan.id)
        result.plans.append(
            PlanRun(
                component=component,
                plan_name=plan.plan_name,
                plan_id=plan_id,
                variant=plan.variant,
                config_file=config_path,
                gating=plan.gating,
                runner_exit_code=exit_code,
                selected_modules=list(plan.modules),
            )
        )
    return result

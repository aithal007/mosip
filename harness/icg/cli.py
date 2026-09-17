"""Command line entry point: ``python -m icg <command>``.

Exit codes for ``run``: 0 gate passed, 1 gate failed, 2 harness/infrastructure error.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from . import __version__
from .agent import HandoffAgent
from .attest import build_statement, parse_subjects
from .benchmark import Benchmark
from .collect import collect_plan, utc_now
from .diff import diff_runs
from .handoff import ADAPTERS, Ledger
from .manifest import ComponentManifest
from .model import RunResult
from .readiness import readiness_markdown
from .report import markdown_summary, write_reports
from .runner import ComponentRun, run_component
from .seed import seed_certify, suggest_benchmark
from .settings import REPO_ROOT, Settings
from .suite_api import SuiteApi

log = logging.getLogger("icg")
COMPONENTS = ("certify", "verify")


def _components(args: argparse.Namespace) -> list[str]:
    if args.combined:
        return list(COMPONENTS)
    selected = args.component or []
    if not selected:
        raise SystemExit("Choose --component certify|verify (repeatable) or --combined")
    return list(dict.fromkeys(selected))


# -- wait ------------------------------------------------------------------------------

def wait_until_ready(settings: Settings, components: list[str], timeout: int) -> bool:
    deadline = time.time() + timeout
    targets = {"conformance suite": None}
    if "certify" in components:
        targets["Inji Certify"] = f"{settings.certify_admin_url}/actuator/health"
    if "verify" in components:
        targets["Inji Verify"] = f"{settings.verify_admin_url}/actuator/health"
    pending = dict(targets)
    with SuiteApi(settings.conformance_server, settings.conformance_token) as api, httpx.Client(timeout=10, verify=False) as http:
        while pending and time.time() < deadline:
            for name, url in list(pending.items()):
                try:
                    ok = api.is_ready() if url is None else http.get(url).status_code == 200
                except httpx.HTTPError:
                    ok = False
                if ok:
                    log.info("%s is ready", name)
                    pending.pop(name)
            if pending:
                time.sleep(5)
    for name in pending:
        log.error("%s did not become ready within %ss", name, timeout)
    return not pending


# -- run -------------------------------------------------------------------------------

def command_run(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    components = _components(args)
    manifests = [ComponentManifest.load(c) for c in components]
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    out_root = Path(args.out).resolve()
    run_dir = out_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    mode = "combined" if args.combined or len(components) > 1 else "per-module"

    if not args.skip_wait and not wait_until_ready(settings, components, args.wait_timeout):
        return 2
    if "certify" in components and not args.no_seed and not seed_certify(settings):
        return 2

    started = utc_now()
    ledger = Ledger(run_dir / "handoff-ledger.json")
    adapters = [ADAPTERS[c](settings) for c in components]
    component_runs: list[ComponentRun] = []

    with HandoffAgent(settings, adapters, ledger):
        if args.parallel and len(manifests) > 1:
            lock = threading.Lock()

            def worker(manifest: ComponentManifest) -> None:
                result = run_component(manifest, settings, run_dir, run_id, include_readiness=args.readiness, timeout_seconds=args.plan_timeout)
                with lock:
                    component_runs.append(result)

            threads = [threading.Thread(target=worker, args=(m,), name=f"icg-{m.component}") for m in manifests]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        else:
            for manifest in manifests:
                component_runs.append(
                    run_component(manifest, settings, run_dir, run_id, include_readiness=args.readiness, timeout_seconds=args.plan_timeout)
                )

    run = RunResult(
        run_id=run_id,
        started_at=started,
        finished_at=utc_now(),
        mode=mode,
        components=components,
        suite_version=settings.suite_version,
        environment={
            "conformanceServer": settings.conformance_server,
            "certifyPublicUrl": settings.certify_public_url if "certify" in components else "",
            "verifyPublicUrl": settings.verify_public_url if "verify" in components else "",
            "reviewPolicy": settings.review_policy,
            "warningPolicy": settings.warning_policy,
            "harnessVersion": __version__,
        },
        shims=[{"component": m.component, **s} for m in manifests for s in m.shims],
    )
    by_component = {m.component: m for m in manifests}
    with SuiteApi(settings.conformance_server, settings.conformance_token) as api:
        for component_run in sorted(component_runs, key=lambda r: components.index(r.component)):
            manifest = by_component[component_run.component]
            benchmark = Benchmark.load(manifest.expected_failures, manifest.expected_skips)
            for plan in component_run.plans:
                run.plans.append(plan)
                try:
                    run.modules.extend(collect_plan(api, plan, benchmark, ledger, settings))
                except Exception as exc:  # a broken plan must not hide the others
                    log.error("Collecting plan %s failed: %s", plan.plan_id, exc)

    results_path = run_dir / "results.json"
    run.write(results_path)

    baseline_path = Path(args.baseline) if args.baseline else out_root / "baseline-results.json"
    diff = diff_runs(RunResult.load(baseline_path), run) if baseline_path.exists() else None
    reports = write_reports(run_dir, run, diff, manifests)
    shutil.copyfile(results_path, out_root / "latest-results.json")
    if args.update_baseline and run.is_gate_passing():
        shutil.copyfile(results_path, out_root / "baseline-results.json")

    print(markdown_summary(run, diff))
    print(f"results : {results_path}\nreport  : {reports['html']}\njunit   : {reports['junit']}")
    if diff is not None and diff.has_regressions:
        log.warning("%d regression(s) compared with %s", len(diff.regressions), baseline_path)
    missing = run.missing_plans()
    if missing:
        for plan in missing:
            log.error("Gating plan %s (%s) produced no results - see %s", plan.plan_name, plan.component, run_dir / "logs")
        return 2
    return 0 if run.is_gate_passing() else 1


# -- other commands --------------------------------------------------------------------

def command_wait(args: argparse.Namespace) -> int:
    return 0 if wait_until_ready(Settings.from_env(), _components(args), args.timeout) else 2


def command_report(args: argparse.Namespace) -> int:
    run = RunResult.load(Path(args.results))
    diff = diff_runs(RunResult.load(Path(args.baseline)), run) if args.baseline else None
    manifests = [ComponentManifest.load(c) for c in run.components]
    paths = write_reports(Path(args.out), run, diff, manifests)
    print("\n".join(f"{k}: {v}" for k, v in paths.items()))
    return 0


def command_diff(args: argparse.Namespace) -> int:
    diff = diff_runs(RunResult.load(Path(args.baseline)), RunResult.load(Path(args.current)))
    markdown = diff.to_markdown()
    if args.markdown:
        Path(args.markdown).write_text(markdown, encoding="utf-8")
    print(markdown)
    return 1 if args.fail_on_regression and diff.has_regressions else 0


def command_readiness(args: argparse.Namespace) -> int:
    print(readiness_markdown([ComponentManifest.load(c) for c in COMPONENTS]))
    return 0


def command_seed(args: argparse.Namespace) -> int:
    return 0 if seed_certify(Settings.from_env()) else 2


def command_suggest(args: argparse.Namespace) -> int:
    entries = suggest_benchmark(RunResult.load(Path(args.results)), args.component)
    print(json.dumps(entries, indent=2))
    return 0


def command_attest(args: argparse.Namespace) -> int:
    statement = build_statement(RunResult.load(Path(args.results)), parse_subjects(args.subject), args.url)
    text = json.dumps(statement, indent=2)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="icg", description="Inji Conformance Gate")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_selection(p: argparse.ArgumentParser) -> None:
        p.add_argument("--component", action="append", choices=COMPONENTS, help="component to test (repeatable)")
        p.add_argument("--combined", action="store_true", help="run Certify and Verify together")

    run = sub.add_parser("run", help="run conformance plans and gate on the benchmark")
    add_selection(run)
    run.add_argument("--parallel", action="store_true", help="run components concurrently")
    run.add_argument("--readiness", action="store_true", help="also run HAIP plans whose capabilities are all supported")
    run.add_argument("--out", default=str(REPO_ROOT / "results"))
    run.add_argument("--baseline", help="results.json to diff against (default: <out>/baseline-results.json)")
    run.add_argument("--update-baseline", action="store_true", help="store this run as the baseline when the gate passes")
    run.add_argument("--skip-wait", action="store_true")
    run.add_argument("--no-seed", action="store_true", help="do not register the SD-JWT credential config in Certify")
    run.add_argument("--wait-timeout", type=int, default=900)
    run.add_argument("--plan-timeout", type=int, default=3600)
    run.set_defaults(func=command_run)

    wait = sub.add_parser("wait", help="wait for the suite and Inji services to be healthy")
    add_selection(wait)
    wait.add_argument("--timeout", type=int, default=900)
    wait.set_defaults(func=command_wait)

    report = sub.add_parser("report", help="regenerate reports from results.json")
    report.add_argument("--results", required=True)
    report.add_argument("--baseline")
    report.add_argument("--out", required=True)
    report.set_defaults(func=command_report)

    diff = sub.add_parser("diff", help="compare two results.json files")
    diff.add_argument("baseline")
    diff.add_argument("current")
    diff.add_argument("--markdown")
    diff.add_argument("--fail-on-regression", action="store_true")
    diff.set_defaults(func=command_diff)

    readiness = sub.add_parser("readiness", help="print the HAIP certification gap report")
    readiness.set_defaults(func=command_readiness)

    seed = sub.add_parser("seed-certify", help="register the SD-JWT credential configuration in Inji Certify")
    seed.set_defaults(func=command_seed)

    suggest = sub.add_parser("benchmark-suggest", help="draft expected-failure entries from a run's regressions")
    suggest.add_argument("--results", required=True)
    suggest.add_argument("--component", required=True, choices=COMPONENTS)
    suggest.set_defaults(func=command_suggest)

    attest = sub.add_parser("attest", help="emit an in-toto Test Result statement")
    attest.add_argument("--results", required=True)
    attest.add_argument("--subject", action="append", default=[], help="name=sha256:<hex> (repeatable)")
    attest.add_argument("--url", default="")
    attest.add_argument("--out")
    attest.set_defaults(func=command_attest)
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        # Windows consoles default to cp1252; reports contain status emoji.
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        return int(args.func(args))
    except FileNotFoundError as exc:
        log.error("%s", exc)
        return 2

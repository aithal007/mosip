"""Certification package assembly.

Produces a ZIP archive containing everything needed for an OpenID certification
submission:

* results.json - full run results (module verdicts, findings, evidence references)
* conformance-report.html - human-readable HTML report
* junit.xml - JUnit test results for CI/CD integration
* handoff-ledger.json - every handoff action performed by the agent
* evidence/ - per-module protocol evidence bundles (request/response + SHA-256)
* suite-export/ - exported suite plans, logs, and configuration snapshots
* certification-manifest.json - machine-readable manifest of package contents

The package is produced from a previous run directory and does not require
re-running the conformance suite. It is meant for certification submissions
to the OpenID Foundation.
"""

from __future__ import annotations

import json
import logging
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .model import RunResult
from .settings import REPO_ROOT

log = logging.getLogger(__name__)


def build_manifest(
    run_dir: Path,
    run: RunResult,
    include_dirs: list[str],
) -> dict[str, Any]:
    """Build the certification-manifest.json describing package contents."""
    files: list[dict[str, str]] = []
    for rel in include_dirs:
        abs_path = run_dir / rel
        if abs_path.is_file():
            files.append({"path": rel, "type": "file"})
        elif abs_path.is_dir():
            for f in sorted(abs_path.rglob("*")):
                if f.is_file():
                    files.append({"path": str(f.relative_to(run_dir)), "type": "file"})

    return {
        "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "runId": run.run_id,
        "startedAt": run.started_at,
        "finishedAt": run.finished_at,
        "components": run.components,
        "suiteVersion": run.suite_version,
        "gatePassing": run.is_gate_passing(),
        "moduleCount": len(run.modules),
        "blockingVerdicts": [
            {"module": m.module_name, "plan": m.plan_name, "verdict": m.verdict, "reason": m.verdict_reason}
            for m in run.modules
            if __import__("icg.model", fromlist=["Verdict"]).Verdict(m.verdict).is_blocking
        ],
        "files": files,
    }


def certify_package(results_path: Path, out_zip: Path | None = None, include_suite_export: bool = True) -> Path:
    """Assemble a certification package ZIP from a run directory.

    Args:
        results_path: Path to results.json (the run directory is its parent).
        out_zip: Output ZIP path (default: <run_dir>/certification-package.zip).
        include_suite_export: Whether to include suite exports if present.

    Returns the path to the created ZIP file.
    """
    results_path = results_path.resolve()
    run_dir = results_path.parent
    run = RunResult.load(results_path)

    if out_zip is None:
        out_zip = run_dir / "certification-package.zip"

    out_zip.parent.mkdir(parents=True, exist_ok=True)

    # Determine files to include
    include_dirs = [
        "results.json",
        "conformance-report.html",
        "junit.xml",
        "handoff-ledger.json",
        "evidence",
    ]
    if include_suite_export and (run_dir / "exports").exists():
        include_dirs.append("suite-export")

    manifest = build_manifest(run_dir, run, include_dirs)

    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        # Add manifest first
        zf.writestr("certification-manifest.json", json.dumps(manifest, indent=2))

        for rel in include_dirs:
            abs_path = run_dir / rel
            if abs_path.is_file():
                zf.write(abs_path, arcname=rel)
            elif abs_path.is_dir():
                for f in sorted(abs_path.rglob("*")):
                    if f.is_file():
                        zf.write(f, arcname=str(f.relative_to(run_dir)))

    log.info("certification package written to %s (%d files)", out_zip, len(manifest["files"]) + 1)
    return out_zip


def command_certify_package(args: Any) -> int:
    """CLI entry point for `icg certify-package`."""
    results_path = Path(args.results)
    if not results_path.exists():
        log.error("results.json not found: %s", results_path)
        return 2

    out_zip = Path(args.out) if args.out else None
    certify_package(results_path, out_zip, include_suite_export=not args.no_suite_export)
    return 0

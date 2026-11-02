"""Tests for certify_package module."""

import json
import tempfile
import zipfile
from pathlib import Path

import pytest

from icg.certify_package import build_manifest, certify_package
from icg.model import RunResult, ModuleResult, PlanRun, Verdict
from icg.manifest import PlanSpec


def _make_run_result(tmp_path: Path, component: str = "verify") -> RunResult:
    plan = PlanSpec(
        id="plan-1",
        plan_name="oid4vp-1final-verifier-test-plan",
        variant={"vp_profile": "plain_vp"},
        config="config.json",
        gating=True,
        modules=[],
        description="test plan",
    )
    plan_run = PlanRun(
        plan_id="plan-1",
        plan_name="oid4vp-1final-verifier-test-plan",
        component=component,
        gating=True,
        variant={"vp_profile": "plain_vp"},
        config_file="config.json",
    )
    module = ModuleResult(
        component=component,
        plan_name="oid4vp-1final-verifier-test-plan",
        plan_id="plan-1",
        module_name="oid4vp-1final-verifier-happy-flow",
        module_id="M1",
        variant={"vp_profile": "plain_vp"},
        status="FINISHED",
        suite_result="PASS",
        verdict=Verdict.PASS.value,
        duration_seconds=10.0,
        log_url="https://suite.example/log/M1",
    )
    return RunResult(
        run_id="run-20260101",
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:05:00Z",
        mode="per-module",
        components=[component],
        suite_version="release-v5.2.4",
        environment={},
        shims=[],
        plans=[plan_run],
        modules=[module],
    )


def test_build_manifest(tmp_path):
    run_dir = tmp_path / "run-20260101"
    run_dir.mkdir(parents=True)
    (run_dir / "results.json").write_text("{}")
    (run_dir / "conformance-report.html").write_text("<html></html>")
    ev_dir = run_dir / "evidence"
    ev_dir.mkdir()
    (ev_dir / "M1.json").write_text('{"moduleId":"M1"}')

    run = _make_run_result(tmp_path)
    manifest = build_manifest(run_dir, run, ["results.json", "evidence"])

    assert manifest["runId"] == "run-20260101"
    assert manifest["gatePassing"] is True
    assert manifest["suiteVersion"] == "release-v5.2.4"
    assert len(manifest["files"]) == 2  # results.json + evidence/M1.json


def test_build_manifest_with_blocking_verdicts(tmp_path):
    run = _make_run_result(tmp_path)
    from icg.model import Verdict as V
    run.modules = [
        ModuleResult(
            component="verify",
            plan_name="plan",
            plan_id="plan-1",
            module_name="mod1",
            module_id="M1",
            variant={},
            status="FINISHED",
            suite_result="FAIL",
            verdict=V.FAIL.value,
            verdict_reason="something failed",
        )
    ]
    manifest = build_manifest(tmp_path, run, [])
    assert len(manifest["blockingVerdicts"]) == 1
    assert manifest["blockingVerdicts"][0]["module"] == "mod1"
    assert manifest["gatePassing"] is False


def test_certify_package_creates_zip(tmp_path):
    run_dir = tmp_path / "run-20260101"
    run_dir.mkdir(parents=True)
    run = _make_run_result(tmp_path)
    run.write(run_dir / "results.json")
    (run_dir / "conformance-report.html").write_text("<html></html>")
    (run_dir / "junit.xml").write_text("<testsuite></testsuite>")
    (run_dir / "handoff-ledger.json").write_text("{}")

    zip_path = certify_package(run_dir / "results.json")
    assert zip_path.exists()
    assert zip_path.suffix == ".zip"

    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        assert "certification-manifest.json" in names
        assert "results.json" in names
        assert "conformance-report.html" in names
        assert "junit.xml" in names
        assert "handoff-ledger.json" in names

        manifest = json.loads(zf.read("certification-manifest.json"))
        assert manifest["runId"] == "run-20260101"
        assert manifest["gatePassing"] is True


def test_certify_package_custom_output(tmp_path):
    run_dir = tmp_path / "run-20260101"
    run_dir.mkdir(parents=True)
    run = _make_run_result(tmp_path)
    run.write(run_dir / "results.json")
    (run_dir / "conformance-report.html").write_text("<html></html>")

    custom_zip = tmp_path / "custom-package.zip"
    certify_package(run_dir / "results.json", out_zip=custom_zip)
    assert custom_zip.exists()

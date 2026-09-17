import json
import struct
import urllib.parse
import zlib
from pathlib import Path

import pytest

from icg.attest import build_statement, parse_subjects
from icg.benchmark import Benchmark, classify
from icg.collect import summarise_log
from icg.coverage import build_coverage, split_requirement
from icg.diff import diff_runs
from icg.evidence import _FONT_ROWS, render_card, to_data_url
from icg.handoff.certify import extract_offer_uri
from icg.handoff.verify import build_authorization_query, expected_outcome
from icg.manifest import ComponentManifest, render_config
from icg.model import Finding, ModuleResult, PlanRun, RunResult, Verdict
from icg.runner import parse_plan_ids, script_relative_path
from icg.seed import suggest_benchmark

CONFIG = "/runs/1/configs/vp/verifier-sdjwt-redirect-uri.json"


def module(result="PASSED", status="FINISHED", findings=(), name="oid4vp-1final-verifier-happy-flow", **extra):
    return ModuleResult(
        component="verify", plan_name="oid4vp-1final-verifier-test-plan", plan_id="P1", module_name=name,
        module_id="M1", variant={"credential_format": "sd_jwt_vc"}, status=status, suite_result=result,
        findings=list(findings), **extra,
    )


def entry(condition, test_name="oid4vp-1final-verifier-happy-flow", block="*", result="failure", issue="https://example/1"):
    return {
        "test-name": test_name, "variant": "*", "configuration-filename": "*verifier-sdjwt-redirect-uri.json",
        "current-block": block, "condition": condition, "expected-result": result, "issue": issue,
    }


# -- benchmark -----------------------------------------------------------------------

def test_passed_module_is_pass():
    assert classify(module(), CONFIG, Benchmark()).verdict == Verdict.PASS.value


def test_unexpected_failure_is_regression():
    m = classify(module("FAILED", findings=[Finding("CheckX", "FAILURE", "boom")]), CONFIG, Benchmark())
    assert m.verdict == Verdict.FAIL.value
    assert "CheckX" in m.verdict_reason


def test_failure_matching_benchmark_is_known_issue_with_issue_link():
    bench = Benchmark(expected_failures=[entry("CheckX")])
    m = classify(module("FAILED", findings=[Finding("CheckX", "FAILURE", "boom", block="Token")]), CONFIG, bench)
    assert m.verdict == Verdict.KNOWN_ISSUE.value
    assert m.issue == "https://example/1"


def test_block_must_match_when_specified():
    bench = Benchmark(expected_failures=[entry("CheckX", block="Credential endpoint")])
    m = classify(module("FAILED", findings=[Finding("CheckX", "FAILURE", "boom", block="Token")]), CONFIG, bench)
    assert m.verdict == Verdict.FAIL.value


def test_benchmark_entry_for_passing_module_is_stale():
    bench = Benchmark(expected_failures=[entry("CheckX")])
    m = classify(module("PASSED"), CONFIG, bench)
    assert m.verdict == Verdict.STALE_BENCHMARK.value
    assert not Verdict(m.verdict).is_blocking


def test_variant_filter_limits_entries():
    e = entry("CheckX")
    e["variant"] = {"credential_format": "iso_mdl"}
    m = classify(module("FAILED", findings=[Finding("CheckX", "FAILURE", "boom")]), CONFIG, Benchmark([e]))
    assert m.verdict == Verdict.FAIL.value


def test_review_resolved_by_evidence():
    ok = classify(module("REVIEW", review_evidence={"matched": True, "actual": "FAILED", "expected": "FAILED"}), CONFIG, Benchmark())
    bad = classify(module("REVIEW", review_evidence={"matched": False, "actual": "SUCCESS", "expected": "FAILED"}), CONFIG, Benchmark())
    missing = classify(module("REVIEW"), CONFIG, Benchmark())
    assert (ok.verdict, bad.verdict, missing.verdict) == ("PASS", "FAIL", "INCOMPLETE")


def test_review_mismatch_can_be_a_known_issue_and_goes_stale_when_fixed():
    bench = Benchmark([entry("icg:review-mismatch")])
    mismatch = classify(module("REVIEW", review_evidence={"matched": False, "actual": "SUCCESS", "expected": "FAILED"}), CONFIG, bench)
    fixed = classify(module("REVIEW", review_evidence={"matched": True, "actual": "FAILED", "expected": "FAILED"}), CONFIG, bench)
    assert mismatch.verdict == Verdict.KNOWN_ISSUE.value
    assert fixed.verdict == Verdict.STALE_BENCHMARK.value


def test_review_policies():
    assert classify(module("REVIEW"), CONFIG, Benchmark(), review_policy="pass").verdict == "PASS"
    assert classify(module("REVIEW"), CONFIG, Benchmark(), review_policy="fail").verdict == "FAIL"


def test_warning_policy():
    warn = [Finding("CheckW", "WARNING", "meh")]
    assert classify(module("WARNING", findings=warn), CONFIG, Benchmark()).verdict == "PASS"
    assert classify(module("WARNING", findings=warn), CONFIG, Benchmark(), warning_policy="fail").verdict == "FAIL"


def test_unfinished_module_is_incomplete_unless_expected():
    assert classify(module("", status="WAITING"), CONFIG, Benchmark()).verdict == "INCOMPLETE"
    bench = Benchmark(expected_skips=[{**entry("x"), "issue": "https://example/skip"}])
    assert classify(module("", status="INTERRUPTED"), CONFIG, bench).verdict == "KNOWN_ISSUE"


def test_interrupted_by_failing_condition_is_matched_against_benchmark():
    findings = [Finding("EnsureHttpStatusCodeIsAnyOf", "FAILURE", "resource endpoint returned 500", block="Credential")]
    assert classify(module("FAILED", status="INTERRUPTED", findings=findings), CONFIG, Benchmark()).verdict == "FAIL"
    bench = Benchmark([entry("EnsureHttpStatusCodeIsAnyOf")])
    assert classify(module("FAILED", status="INTERRUPTED", findings=findings), CONFIG, bench).verdict == "KNOWN_ISSUE"
    # interrupted without findings (e.g. suite crash) stays an infrastructure problem
    assert classify(module("FAILED", status="INTERRUPTED"), CONFIG, Benchmark()).verdict == "INCOMPLETE"


def test_skipped_is_skip():
    assert classify(module("SKIPPED"), CONFIG, Benchmark()).verdict == "SKIP"


# -- run model / gate ----------------------------------------------------------------

def make_run(run_id, modules, gating=True):
    return RunResult(
        run_id=run_id, started_at="t0", finished_at="t1", mode="per-module", components=["verify"], suite_version="v",
        environment={}, plans=[PlanRun("verify", "plan", "P1", {}, CONFIG, gating)], modules=modules,
    )


def test_gate_ignores_non_gating_plans_and_round_trips(tmp_path):
    failing = classify(module("FAILED", findings=[Finding("CheckX", "FAILURE", "boom")]), CONFIG, Benchmark())
    assert not make_run("r1", [failing]).is_gate_passing()
    assert not make_run("r1", [failing], gating=False).is_gate_passing()  # no gating plans at all -> not passing
    run = make_run("r2", [classify(module(), CONFIG, Benchmark())])
    assert run.is_gate_passing()
    path = tmp_path / "results.json"
    run.write(path)
    data = json.loads(path.read_text())
    assert data["gatePassed"] is True and data["schemaVersion"] == 1
    assert RunResult.load(path).modules[0].verdict == "PASS"


def test_gate_fails_when_gating_plan_produced_nothing():
    run = make_run("r", [])
    assert not run.is_gate_passing()
    assert [p.plan_name for p in run.missing_plans()] == ["plan"]
    run.plans[0].plan_id = ""
    assert run.missing_plans()


def test_config_path_passed_to_run_test_plan_has_no_colon(tmp_path):
    scripts = tmp_path / "upstream" / "conformance-suite" / "scripts"
    config = tmp_path / "results" / "123" / "configs" / "p" / "cfg.json"
    arg = script_relative_path(config, scripts)
    assert ":" not in arg and "\\" not in arg
    assert (scripts / arg).resolve() == config.resolve()


def test_diff_detects_regressions_and_fixes():
    base = make_run("a", [classify(module(), CONFIG, Benchmark()), classify(module(name="neg", result="FAILED", findings=[Finding("C", "FAILURE", "x")]), CONFIG, Benchmark())])
    cur = make_run("b", [classify(module(result="FAILED", findings=[Finding("C", "FAILURE", "x")]), CONFIG, Benchmark()), classify(module(name="neg"), CONFIG, Benchmark())])
    diff = diff_runs(base, cur)
    assert [c.module for c in diff.regressions] == ["oid4vp-1final-verifier-happy-flow"]
    assert [c.module for c in diff.fixes] == ["neg"]
    assert "Regressions" in diff.to_markdown()


def test_suggest_benchmark_drafts_entries():
    failing = classify(module("FAILED", findings=[Finding("CheckX", "FAILURE", "boom", block="Token")]), CONFIG, Benchmark())
    entries = suggest_benchmark(make_run("r", [failing]), "verify")
    assert entries[0]["condition"] == "CheckX" and entries[0]["configuration-filename"] == "*verifier-sdjwt-redirect-uri.json"


# -- log parsing / coverage ----------------------------------------------------------

def test_summarise_log_resolves_blocks_and_requirements():
    entries = [
        {"src": "-START-BLOCK-", "startBlock": True, "blockId": "b1", "msg": "Authorization endpoint", "time": 1000},
        {"src": "CheckA", "result": "SUCCESS", "requirements": ["OID4VP-1FINAL-5.1"], "blockId": "b1", "time": 1500},
        {"src": "CheckB", "result": "FAILURE", "msg": "bad", "requirements": ["OID4VP-1FINAL-8.2"], "blockId": "b1", "time": 3000},
        {"src": "CheckC", "result": "INFO", "time": 3100},
    ]
    findings, requirements, counts = summarise_log(entries)
    assert findings[0].block == "Authorization endpoint" and findings[0].condition == "CheckB"
    assert requirements == ["OID4VP-1FINAL-5.1", "OID4VP-1FINAL-8.2"]
    assert counts == {"SUCCESS": 1, "FAILURE": 1, "INFO": 1}


def test_coverage_states():
    assert split_requirement("OID4VP-1FINAL-8.2") == ("OID4VP-1FINAL", "8.2")
    assert split_requirement("RFC6749-4.1.2") == ("RFC6749", "4.1.2")
    m = module("FAILED", findings=[Finding("C", "FAILURE", "x", requirements=["HAIP-5.1"])], requirements=["HAIP-5.1", "OIDCC-6.1"])
    states = {c.requirement: c.state for c in build_coverage(make_run("r", [m]))}
    assert states == {"HAIP-5.1": "failing", "OIDCC-6.1": "passing"}


# -- handoff helpers -----------------------------------------------------------------

def test_authorization_query_matches_sdk_for_by_value_request():
    vp_request = {
        "transactionId": "txn_1", "requestId": "req_1",
        "authorizationDetails": {
            "responseType": "vp_token", "responseMode": "direct_post", "nonce": "n0nce-0123456789",
            "responseUri": "https://verify.inji.test/v1/verify/v2/vp-submission/direct-post",
            "dcqlQuery": {"credentials": [{"id": "pid", "format": "dc+sd-jwt"}]},
        },
    }
    client_id = "redirect_uri:https://verify.inji.test/v1/verify/v2/vp-submission/direct-post"
    params = dict(urllib.parse.parse_qsl(build_authorization_query(client_id, vp_request)))
    assert params["client_id"] == client_id
    assert params["state"] == "req_1"
    assert params["response_uri"].endswith("/v2/vp-submission/direct-post")
    assert json.loads(params["dcql_query"])["credentials"][0]["format"] == "dc+sd-jwt"
    assert "dc+sd-jwt" in json.loads(params["client_metadata"])["vp_formats_supported"]


def test_authorization_query_by_reference():
    params = dict(urllib.parse.parse_qsl(build_authorization_query("decentralized_identifier:did:web:x", {"requestUri": "https://v/r/1"})))
    assert params == {"client_id": "decentralized_identifier:did:web:x", "request_uri": "https://v/r/1"}


def test_expected_outcome_from_placeholder_condition():
    assert expected_outcome({"src": "ExpectVerifierSuccessfulVerificationPage"}) == "SUCCESS"
    assert expected_outcome({"src": "ExpectVerifierRejectedPresentationPage"}) == "FAILED"
    assert expected_outcome({"src": "Other"}) == "UNKNOWN"


def test_extract_offer_uri():
    inner = "https://certify.inji.test/v1/certify/credential-offer-data/abc"
    offer = "openid-credential-offer://?credential_offer_uri=" + urllib.parse.quote(inner, safe="")
    assert extract_offer_uri(offer) == inner
    with pytest.raises(ValueError):
        extract_offer_uri("openid-credential-offer://?credential_offer=%7B%7D")


def test_parse_plan_ids_from_run_test_plan_output():
    lines = [
        "Running plan 'oid4vp-1final-verifier-test-plan' with configuration file '/r/configs/a/x.json'",
        "abc123XYZ: Config '/r/configs/a/x.json' contains alias 'icg-1-a' - not running tests within this plan in parallel.",
        "Created test plan, new id: abc123XYZ",
    ]
    assert parse_plan_ids(lines, ["/r/configs/a/x.json"]) == {str(Path("/r/configs/a/x.json")): "abc123XYZ"}
    # run-test-plan.py 5.2.x prefixes lines with a timestamp (observed in a real run)
    stamped = ["2026-09-17 00:21:51 XOxSybKvXXvOV: Config '../../../results/1/configs/p/c.json' contains alias 'icg-1-p' - not running"]
    assert parse_plan_ids(stamped, ["../../../results/1/configs/p/c.json"]) == {
        str(Path("../../../results/1/configs/p/c.json")): "XOxSybKvXXvOV"
    }


# -- evidence image ------------------------------------------------------------------

def test_font_glyphs_are_5x7():
    assert all(len(rows) == 35 for rows in _FONT_ROWS.values())


def test_render_card_is_valid_png():
    png = render_card(["HELLO WORLD", "expected: FAILED"], accent=(0, 128, 0))
    assert png.startswith(b"\x89PNG\r\n\x1a\n")
    length, kind = struct.unpack(">I4s", png[8:16])
    width, height = struct.unpack(">II", png[16:24])
    assert kind == b"IHDR" and width > 0 and height > 0
    idat_len = struct.unpack(">I", png[33:37])[0]
    raw = zlib.decompress(png[41:41 + idat_len])
    assert len(raw) == height * (1 + 3 * width)
    assert to_data_url(png).startswith("data:image/png;base64,")


# -- manifests / templates / attestation ---------------------------------------------

def test_render_config_substitutes_and_stamps_alias(tmp_path):
    template = tmp_path / "cfg.json"
    template.write_text('{\n "alias": "set-by-harness",\n "description": "x",\n "vci": {"credential_issuer_url": "${CERTIFY_PUBLIC_URL}"},\n "credential": {"signing_jwk": {vp-signing-jwk.json}}\n}')
    rendered = render_config(template, {"CERTIFY_PUBLIC_URL": "https://c/v1/certify"}, "icg-1-p", "desc", tmp_path / "out")
    text = rendered.read_text()
    assert '"alias": "icg-1-p"' in text and "set-by-harness" not in text
    assert "https://c/v1/certify" in text and "{vp-signing-jwk.json}" in text
    parsed = json.loads(text.replace("{vp-signing-jwk.json}", "{}"))
    assert parsed["alias"] == "icg-1-p"
    with pytest.raises(KeyError):
        render_config(template, {}, "a", "d", tmp_path / "out2")


@pytest.mark.parametrize("component", ["certify", "verify"])
def test_shipped_manifests_load(component):
    manifest = ComponentManifest.load(component)
    assert manifest.plans and all(p.config.exists() for p in manifest.plans)
    assert manifest.expected_failures.exists() and manifest.expected_skips.exists()
    for plan in manifest.plans:
        assert plan.cli_selector().startswith(plan.plan_name + "[")
    assert all(r.missing for r in manifest.readiness)  # HAIP not yet supported


def test_attestation_statement():
    run = make_run("r", [classify(module(), CONFIG, Benchmark())])
    statement = build_statement(run, parse_subjects(["injistack/inji-verify-service=sha256:abc"]))
    assert statement["predicate"]["result"] == "PASSED"
    assert statement["subject"][0]["digest"] == {"sha256": "abc"}
    with pytest.raises(ValueError):
        parse_subjects(["no-digest"])

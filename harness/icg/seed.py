"""Environment preparation that the conformance plans depend on."""

from __future__ import annotations

import base64
import json
import logging
from pathlib import Path

import httpx

from .model import RunResult, Verdict
from .settings import REPO_ROOT, Settings

log = logging.getLogger(__name__)

CREDENTIAL_CONFIG = REPO_ROOT / "conformance" / "configs" / "certify" / "sd-jwt-credential-config.json"


def seed_certify(settings: Settings, config_file: Path = CREDENTIAL_CONFIG) -> bool:
    """Register the SD-JWT VC credential configuration the issuer plan requests.

    The docker-compose Certify database only ships an ``ldp_vc`` configuration, but the
    OID4VCI conformance plans test ``dc+sd-jwt`` or ``mso_mdoc``. The request mirrors the
    api-testrig ``AddCredentialConfigSd_Jwt`` cases: ``vcTemplate`` is sent base64 encoded.
    """
    body = json.loads(config_file.read_text(encoding="utf-8"))
    config_id = body["credentialConfigKeyId"]
    with httpx.Client(timeout=30, verify=False) as http:
        metadata = http.get(f"{settings.certify_admin_url}/.well-known/openid-credential-issuer")
        if metadata.status_code == 200 and config_id in (metadata.json().get("credential_configurations_supported") or {}):
            log.info("Certify already advertises credential configuration %s", config_id)
            return True

        body["vcTemplate"] = base64.b64encode(json.dumps(body["vcTemplate"]).encode("utf-8")).decode("ascii")
        response = http.post(f"{settings.certify_admin_url}/credential-configurations", json=body)
        if response.status_code in (200, 201):
            log.info("Registered credential configuration %s: %s", config_id, response.text[:200])
            return True
        log.error("Registering %s failed: HTTP %s %s", config_id, response.status_code, response.text[:500])
        return False


def suggest_benchmark(run: RunResult, component: str) -> list[dict[str, object]]:
    """Draft expected-failure entries for every unexpected FAILURE in a run.

    Output uses the run-test-plan.py format so it can be pasted into
    conformance/benchmark/<component>/expected-failures.json. The ``issue`` field is left
    as TODO on purpose: an entry without a tracked issue should not be merged.
    """
    config_by_plan = {p.plan_id: Path(p.config_file).name for p in run.plans}
    entries: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    for module in run.modules:
        if module.component != component or module.verdict not in (Verdict.FAIL.value, Verdict.INCOMPLETE.value):
            continue
        for finding in module.findings:
            if finding.result != "FAILURE":
                continue
            key = (module.module_name, finding.block, finding.condition)
            if key in seen:
                continue
            seen.add(key)
            entries.append(
                {
                    "test-name": module.module_name,
                    "variant": "*",
                    "configuration-filename": "*" + config_by_plan.get(module.plan_id, ""),
                    "current-block": finding.block or "*",
                    "condition": finding.condition,
                    "expected-result": "failure",
                    "issue": "TODO: link the tracking issue",
                    "comment": finding.message[:200],
                }
            )
        if module.suite_result == "REVIEW" and module.review_evidence and not module.review_evidence.get("matched"):
            entries.append(
                {
                    "test-name": module.module_name,
                    "variant": "*",
                    "configuration-filename": "*" + config_by_plan.get(module.plan_id, ""),
                    "current-block": "*",
                    "condition": "icg:review-mismatch",
                    "expected-result": "failure",
                    "issue": "TODO: link the tracking issue",
                    "comment": f"Inji result {module.review_evidence.get('actual')} but the test expected {module.review_evidence.get('expected')}",
                }
            )
    return entries

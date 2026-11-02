"""Black-box negative probes that complement the OpenID suite.

The suite does not (yet) cover every abuse case Inji must reject: replayed pre-authorized
codes, wrong ``tx_code``, garbage presentations. Each probe sends one bad request and
asserts the component refuses it. Probes only use endpoints the handoff adapters already
use, plus OID4VCI/RFC 8414 discovery. They are reported separately and never feed the
OpenID gate, so a probe that cannot run (unreachable URL, unexpected shape) is ``SKIP``.
"""

from __future__ import annotations

import json
import secrets
import urllib.parse
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

import httpx

from .handoff.certify import DEFAULT_OFFER_FILE, extract_offer_uri
from .settings import Settings

PRE_AUTH_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"


@dataclass
class ProbeResult:
    name: str
    component: str
    spec: str
    status: str  # PASS | FAIL | SKIP
    detail: str = ""


def _rejected(response: httpx.Response) -> bool:
    return 400 <= response.status_code < 500


def _offer(client: httpx.Client, settings: Settings, **overrides: Any) -> dict[str, Any]:
    body = json.loads(Path(DEFAULT_OFFER_FILE).read_text(encoding="utf-8"))
    body = {k: v for k, v in {**body, **overrides}.items() if v not in ("", None)}
    response = client.post(f"{settings.certify_admin_url}/pre-authorized-data", json=body)
    return {"response": response, "payload": response.json() if response.content else {}}


def _grant(client: httpx.Client, offer_uri: str) -> str:
    """The pre-authorized_code inside the offer behind ``credential_offer_uri``."""
    offer = client.get(extract_offer_uri(offer_uri)).json()
    return offer["grants"][PRE_AUTH_GRANT]["pre-authorized_code"]


def _token_endpoint(client: httpx.Client, settings: Settings) -> str:
    meta = client.get(f"{settings.certify_admin_url}/.well-known/oauth-authorization-server")
    if meta.status_code == 200 and meta.json().get("token_endpoint"):
        return meta.json()["token_endpoint"]
    issuer = client.get(f"{settings.certify_admin_url}/.well-known/openid-credential-issuer").json()
    return f"{issuer['credential_issuer'].rstrip('/')}/oauth/token"


def probe_unknown_configuration(client: httpx.Client, settings: Settings) -> ProbeResult:
    spec = "OID4VCI 1.0 §8.3.1.2"
    r = _offer(client, settings, credential_configuration_id=f"does-not-exist-{secrets.token_hex(4)}")["response"]
    ok = _rejected(r)
    return ProbeResult("offer-for-unknown-configuration-rejected", "certify", spec, "PASS" if ok else "FAIL", f"HTTP {r.status_code}")


def probe_preauth_replay(client: httpx.Client, settings: Settings) -> ProbeResult:
    spec = "OID4VCI 1.0 §6.1 / RFC 6749 §4.1.2 (single-use grants)"
    name = "preauthorized-code-single-use"
    created = _offer(client, settings, tx_code="")
    if created["response"].status_code not in (200, 201):
        return ProbeResult(name, "certify", spec, "SKIP", f"offer creation HTTP {created['response'].status_code}")
    payload = created["payload"].get("response", created["payload"])
    code = _grant(client, payload["credential_offer_uri"])
    token_url = _token_endpoint(client, settings)
    form = {"grant_type": PRE_AUTH_GRANT, "pre-authorized_code": code}
    first = client.post(token_url, data=form)
    second = client.post(token_url, data=form)
    if first.status_code != 200:
        return ProbeResult(name, "certify", spec, "SKIP", f"first redemption HTTP {first.status_code}")
    ok = _rejected(second)
    return ProbeResult(name, "certify", spec, "PASS" if ok else "FAIL", f"second redemption HTTP {second.status_code}")


def probe_wrong_tx_code(client: httpx.Client, settings: Settings) -> ProbeResult:
    spec = "OID4VCI 1.0 §6.1 (tx_code)"
    name = "wrong-tx-code-rejected"
    created = _offer(client, settings)
    if created["response"].status_code not in (200, 201):
        return ProbeResult(name, "certify", spec, "SKIP", f"offer creation HTTP {created['response'].status_code}")
    payload = created["payload"].get("response", created["payload"])
    code = _grant(client, payload["credential_offer_uri"])
    r = client.post(_token_endpoint(client, settings), data={"grant_type": PRE_AUTH_GRANT, "pre-authorized_code": code, "tx_code": "000000"})
    return ProbeResult(name, "certify", spec, "PASS" if _rejected(r) else "FAIL", f"HTTP {r.status_code}")


def probe_path_inserted_metadata(client: httpx.Client, settings: Settings) -> ProbeResult:
    spec = "OID4VCI 1.0 §12.2.2 (inji-certify#967)"
    name = "path-inserted-issuer-metadata"
    issuer = client.get(f"{settings.certify_admin_url}/.well-known/openid-credential-issuer").json().get("credential_issuer", "")
    parts = urllib.parse.urlsplit(issuer)
    if not parts.path.strip("/"):
        return ProbeResult(name, "certify", spec, "SKIP", "issuer identifier has no path component")
    admin = urllib.parse.urlsplit(settings.certify_admin_url)
    inserted = f"{admin.scheme}://{admin.netloc}/.well-known/openid-credential-issuer{parts.path.rstrip('/')}"
    r = client.get(inserted)
    return ProbeResult(name, "certify", spec, "PASS" if r.status_code == 200 else "FAIL", f"GET {inserted} -> HTTP {r.status_code}")


def probe_garbage_presentation(client: httpx.Client, settings: Settings) -> ProbeResult:
    spec = "OID4VP 1.0 §8 (response validation)"
    name = "garbage-vp-token-not-accepted"
    from .handoff.verify import VerifyHandoff

    adapter = VerifyHandoff(settings)
    request = adapter._create_vp_request()
    transaction_id = request.get("transactionId")
    client.post(
        f"{settings.verify_admin_url}/v2/vp-submission/direct-post",
        data={"vp_token": "not-a-credential", "state": request.get("requestId", "")},
    )
    status, detail = adapter._fetch_vp_result(transaction_id, attempts=3, delay=0.5)
    ok = status != "SUCCESS"
    return ProbeResult(name, "verify", spec, "PASS" if ok else "FAIL", f"vp-result status {status}")


PROBES: dict[str, list[Callable[[httpx.Client, Settings], ProbeResult]]] = {
    "certify": [probe_unknown_configuration, probe_preauth_replay, probe_wrong_tx_code, probe_path_inserted_metadata],
    "verify": [probe_garbage_presentation],
}


def run_probes(settings: Settings, components: list[str]) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    with httpx.Client(timeout=30, verify=False) as client:
        for component in components:
            for probe in PROBES[component]:
                try:
                    results.append(probe(client, settings))
                except Exception as exc:  # an unrunnable probe is a SKIP, never a gate decision
                    results.append(ProbeResult(probe.__name__.removeprefix("probe_").replace("_", "-"), component, "", "SKIP", f"{type(exc).__name__}: {exc}"))
    return results


def to_json(results: list[ProbeResult]) -> str:
    return json.dumps([asdict(r) for r in results], indent=2)

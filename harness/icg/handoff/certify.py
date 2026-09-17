"""Inji Certify <-> OID4VCI issuer test handoff.

For ``vci_authorization_code_flow_variant=issuer_initiated`` the suite (acting as the
wallet) exposes ``credential_offer_endpoint`` and waits for the issuer to send a
credential offer, just like a real wallet waiting for a QR scan. This adapter asks
Inji Certify to mint a pre-authorized credential offer
(``POST /pre-authorized-data``) and delivers the resulting ``credential_offer_uri``
to the suite. If the suite also waits for a transaction code, the adapter delivers
the code it asked Certify to bind to the offer.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.parse
from pathlib import Path
from typing import Any

import httpx

from ..settings import REPO_ROOT, Settings
from .base import HandoffAdapter, HandoffContext

log = logging.getLogger(__name__)

DEFAULT_OFFER_FILE = REPO_ROOT / "conformance" / "configs" / "certify" / "pre-authorized-offer.json"


def extract_offer_uri(offer: str) -> str:
    """Certify returns ``openid-credential-offer://?credential_offer_uri=<encoded>``;
    the suite's offer endpoint takes the bare ``credential_offer_uri``."""
    parsed = urllib.parse.urlsplit(offer)
    values = urllib.parse.parse_qs(parsed.query).get("credential_offer_uri")
    if values:
        return values[0]
    if offer.startswith("https://"):
        return offer
    raise ValueError(f"Unrecognised credential offer from Inji Certify: {offer[:200]}")


class CertifyHandoff(HandoffAdapter):
    component = "certify"
    test_name_prefixes = ("oid4vci-",)

    def __init__(self, settings: Settings, offer_file: Path | None = None):
        super().__init__(settings)
        self._http = httpx.Client(timeout=30, verify=False)
        self._offer_template: dict[str, Any] = json.loads((offer_file or DEFAULT_OFFER_FILE).read_text(encoding="utf-8"))

    def handle_waiting(self, ctx: HandoffContext) -> None:
        offer_endpoint = ctx.exposed.get("credential_offer_endpoint")
        tx_code_endpoint = ctx.exposed.get("tx_code_endpoint")

        if tx_code_endpoint:
            self._deliver_tx_code(ctx, tx_code_endpoint)
        elif offer_endpoint:
            self._deliver_offer(ctx, offer_endpoint)

    def _deliver_offer(self, ctx: HandoffContext, offer_endpoint: str) -> None:
        offer = self._create_offer()
        offer_uri = extract_offer_uri(offer["credential_offer_uri"])
        response = ctx.api.visit(f"{offer_endpoint}?{urllib.parse.urlencode({'credential_offer_uri': offer_uri})}")
        offers = ctx.ledger.get(ctx.module_id).get("offersDelivered", 0) + 1
        ctx.ledger.update(ctx.module_id, offersDelivered=offers, lastOfferUri=offer_uri)
        ctx.ledger.append_event(
            ctx.module_id,
            {"action": "credential-offer-delivered", "offerUri": offer_uri, "suiteHttpStatus": response.status_code, "at": time.time()},
        )
        log.info("[certify] %s: delivered credential offer #%d (suite HTTP %s)", ctx.test_name, offers, response.status_code)

    def _deliver_tx_code(self, ctx: HandoffContext, tx_code_endpoint: str) -> None:
        code = self._offer_template.get("tx_code", "")
        url = tx_code_endpoint.replace("your_tx_code", urllib.parse.quote(code))
        response = ctx.api.visit(url)
        ctx.ledger.append_event(ctx.module_id, {"action": "tx-code-delivered", "suiteHttpStatus": response.status_code, "at": time.time()})

    def _create_offer(self) -> dict[str, Any]:
        body = {key: value for key, value in self._offer_template.items() if value not in ("", None)}
        response = self._http.post(f"{self.settings.certify_admin_url}/pre-authorized-data", json=body)
        if response.status_code not in (200, 201):
            raise RuntimeError(f"Inji Certify pre-authorized-data failed: HTTP {response.status_code} {response.text[:300]}")
        payload = response.json()
        # Certify wraps some responses in {"response": ...}; accept both shapes.
        if "credential_offer_uri" not in payload and isinstance(payload.get("response"), dict):
            payload = payload["response"]
        if "credential_offer_uri" not in payload:
            raise RuntimeError(f"Inji Certify response has no credential_offer_uri: {json.dumps(payload)[:300]}")
        return payload

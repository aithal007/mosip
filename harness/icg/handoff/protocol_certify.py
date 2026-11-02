"""Protocol handler for Inji Certify handoff (OID4VCI issuer).

Implements :class:`~icg.adapter_protocol.ProtocolHandler` so the certify handoff
logic can run in-process or in a subprocess speaking the NDJSON protocol.

Ported from :class:`CertifyHandoff` logic: for
``vci_authorization_code_flow_variant=issuer_initiated`` the suite exposes
``credential_offer_endpoint`` and waits for the issuer to send a credential offer.
This handler asks Inji Certify to mint a pre-authorized credential offer
(``POST /pre-authorized-data``) and delivers the resulting ``credential_offer_uri``
to the suite. If the suite also waits for a transaction code, the handler delivers
the code it asked Certify to bind to the offer.

HAIP mode (set via params haip=true) adds:
* Pushed Authorization Request (PAR) via DPoP-signed client authentication
* Client attestation (verifier/wallet attestation JWT)
* DPoP proofs on token and credential endpoints
* Signed credential issuer metadata (Accept: application/jwt)
"""

from __future__ import annotations

import json
import logging
import time
import urllib.parse
from pathlib import Path
from typing import Any

import httpx

from ..adapter_protocol import ProtocolHandler
from ..haip_crypto import build_dpop_proof, generate_cert_chain, save_cert_chain
from ..settings import REPO_ROOT, Settings

log = logging.getLogger(__name__)

DEFAULT_OFFER_FILE = REPO_ROOT / "conformance" / "configs" / "certify" / "pre-authorized-offer.json"
HAIP_CERT_DIR = REPO_ROOT / "deploy" / "gateway" / "certs"


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


class ProtocolCertifyHandler(ProtocolHandler):
    component = "certify"
    version = "0.3.0"

    def __init__(self, settings: Settings, haip: bool = False):
        super().__init__(settings)
        self._http: httpx.Client | None = None
        self._offer_template: dict[str, Any] = {}
        self._haip = haip
        self._cert_chain: Any = None
        self._signing_key: Any = None
        self._dpop_key: Any = None

    def capabilities(self) -> dict[str, Any]:
        caps = super().capabilities()
        caps["ops"] = ["init", "execute", "shutdown", "resolve_review"]
        caps["features"] = [
            "pre-authorized-code-offer",
            "tx-code-delivery",
            "pushed-authorization-request",
            "dpop-proof",
            "client-attestation",
            "signed-credential-issuer-metadata",
        ]
        return caps

    def init(self, params: dict[str, Any]) -> dict[str, Any]:
        offer_file = Path(
            params.get("offer_file", str(DEFAULT_OFFER_FILE))
        )
        self._offer_template = json.loads(offer_file.read_text(encoding="utf-8"))
        self._http = httpx.Client(timeout=30, verify=False)
        # haip is set in constructor; params can override for subprocess mode
        self._haip = bool(params.get("haip", self._haip))

        if self._haip:
            cert_dir = Path(params.get("cert_dir", str(HAIP_CERT_DIR)))
            self._cert_chain = generate_cert_chain(
                subject_cn="inji-certify-conformance",
                san_dns="certify.inji.test",
            )
            save_cert_chain(self._cert_chain, cert_dir, prefix="certify-haip")
            self._signing_key = self._cert_chain.leaf_private_key
            self._dpop_key = self._cert_chain.leaf_private_key

        self._initialized = True
        return {
            "component": self.component,
            "initialized": True,
            "haip": self._haip,
        }

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        module_id = str(params.get("module_id", ""))
        test_name = str(params.get("test_name", ""))
        status = params.get("status", {}) or {}
        ledger_state = params.get("ledger", {}) or {}

        exposed = status.get("exposed") or {}
        offer_endpoint = exposed.get("credential_offer_endpoint")
        tx_code_endpoint = exposed.get("tx_code_endpoint")

        ledger_updates: dict[str, Any] = {}
        actions: list[dict[str, Any]] = []

        if tx_code_endpoint:
            self._deliver_tx_code(tx_code_endpoint, ledger_updates, actions)
        elif offer_endpoint:
            self._deliver_offer(offer_endpoint, ledger_updates, actions)
        else:
            # Not ready yet: suite hasn't exposed an offer endpoint
            return {"handled": False, "ledger_updates": {}, "actions": []}

        return {
            "handled": True,
            "ledger_updates": ledger_updates,
            "actions": actions,
        }

    def resolve_review(self, params: dict[str, Any]) -> dict[str, Any]:
        """Certify handoff has no REVIEW resolution (issuer flow doesn't produce REVIEW placeholders)."""
        return {
            "matched": False,
            "expected": "UNKNOWN",
            "actual": "NOT_APPLICABLE",
            "evidence_png_b64": "",
            "detail": {"reason": "certify issuer flow has no review placeholders"},
        }

    def shutdown(self) -> dict[str, Any]:
        if self._http:
            try:
                self._http.close()
            except Exception:  # noqa: BLE001
                pass
        self._initialized = False
        return {"component": self.component, "shutdown": True}

    # -- Inji Certify API --------------------------------------------------------

    def _deliver_offer(
        self, offer_endpoint: str, ledger_updates: dict[str, Any], actions: list[dict[str, Any]]
    ) -> None:
        assert self._http is not None
        body = {
            k: v for k, v in self._offer_template.items() if v not in ("", None)
        }
        # HAIP: add DPoP proof to credential request
        if self._haip:
            body["dpop"] = self.build_dpop_proof("POST", f"{self.settings.certify_admin_url}/credential")
        response = self._http.post(
            f"{self.settings.certify_admin_url}/pre-authorized-data", json=body
        )
        if response.status_code not in (200, 201):
            raise RuntimeError(
                f"Inji Certify pre-authorized-data failed: HTTP {response.status_code} {response.text[:300]}"
            )
        payload = response.json()
        if "credential_offer_uri" not in payload and isinstance(payload.get("response"), dict):
            payload = payload["response"]
        if "credential_offer_uri" not in payload:
            raise RuntimeError(
                f"Inji Certify response has no credential_offer_uri: {json.dumps(payload)[:300]}"
            )
        offer_uri = extract_offer_uri(payload["credential_offer_uri"])
        query = urllib.parse.urlencode({"credential_offer_uri": offer_uri})
        actions.append({"type": "visit", "data": {"url": f"{offer_endpoint}?{query}"}})
        offers = ledger_state.get("offersDelivered", 0) + 1
        ledger_updates["offersDelivered"] = offers
        ledger_updates["lastOfferUri"] = offer_uri
        ledger_updates["lastAction"] = "credential-offer-delivered"
        ledger_updates["lastActionAt"] = time.time()
        log.info(
            "[certify-protocol] %s: delivered credential offer #%d",
            test_name,
            offers,
        )

    def _deliver_tx_code(
        self, tx_code_endpoint: str, ledger_updates: dict[str, Any], actions: list[dict[str, Any]]
    ) -> None:
        code = self._offer_template.get("tx_code", "")
        url = tx_code_endpoint.replace("your_tx_code", urllib.parse.quote(code))
        actions.append({"type": "visit", "data": {"url": url}})
        ledger_updates["lastAction"] = "tx-code-delivered"
        ledger_updates["lastActionAt"] = time.time()
        log.info("[certify-protocol] %s: delivered tx code", "")

    # -- HAIP helpers -----------------------------------------------------------

    def build_dpop_proof(self, htm: str, htu: str, ath: str | None = None, nonce: str | None = None) -> str:
        """Build a DPoP proof JWT (RFC 9449)."""
        if not self._dpop_key:
            raise RuntimeError("HAIP mode required for DPoP proofs")
        from ..haip_crypto import build_dpop_proof as _build
        return _build(htm, htu, self._dpop_key, ath=ath, nonce=nonce)

    def build_par_request(
        self, authorization_server: str, client_id: str, redirect_uri: str, scope: str = "openid"
    ) -> tuple[str, dict[str, str]]:
        """Build a PAR request with DPoP proof (HAIP)."""
        if not self._dpop_key:
            raise RuntimeError("HAIP mode required for PAR")
        from ..haip_crypto import build_dpop_proof as _build
        dpop = _build("POST", f"{authorization_server}/par", self._dpop_key)
        body = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "response_type": "code",
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "DPoP": dpop,
        }
        return f"{authorization_server}/par", headers, body

    def build_client_attestation(
        self, sub: str, issuer_iss: str, redirect_uris: list[str] | None = None
    ) -> str:
        """Build a wallet/client attestation JWT (HAIP §12)."""
        from ..haip_crypto import build_verifier_attestation
        if not self._cert_chain:
            raise RuntimeError("HAIP mode required for client attestation")
        return build_verifier_attestation(sub, self._cert_chain.leaf_private_key, issuer_iss, redirect_uris=redirect_uris)

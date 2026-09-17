"""Inji Verify <-> OID4VP verifier test handoff.

In ``oid4vp-1final-verifier-*`` modules the suite plays the wallet. After setup it
exposes ``authorization_endpoint`` and waits for "the openid4vp:// authorization
request produced by the verifier under test". This adapter:

1. asks Inji Verify for a VP request (``POST /v2/vp-request``),
2. rebuilds the authorization request query exactly like the Inji Verify SDK
   (``OpenID4VPVerification.getAuthorizationRequestParams``),
3. delivers it to the suite's authorization endpoint, after which the suite builds a
   VP token and posts it to Inji Verify's ``response_uri``,
4. when the suite then asks for a verification-result screenshot (REVIEW), reads
   Inji Verify's own verdict (``GET /vp-result/{transactionId}``), compares it with
   what the test expects, and uploads a rendered evidence card.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
import urllib.parse
from pathlib import Path
from typing import Any

import httpx

from ..evidence import render_card, to_data_url
from ..settings import REPO_ROOT, Settings
from .base import HandoffAdapter, HandoffContext

log = logging.getLogger(__name__)

# Mirrors inji-verify-sdk/src/utils/constants.ts VP_FORMATS_SUPPORTED.
VP_FORMATS_SUPPORTED = {
    "ldp_vp": {"proof_type": ["Ed25519Signature2018", "Ed25519Signature2020", "RsaSignature2018"]},
    "dc+sd-jwt": {
        "sd-jwt_alg_values": ["RS256", "ES256", "ES256K", "EdDSA"],
        "kb-jwt_alg_values": ["RS256", "ES256", "ES256K", "EdDSA"],
    },
    "vc+sd-jwt": {
        "sd-jwt_alg_values": ["RS256", "ES256", "ES256K", "EdDSA"],
        "kb-jwt_alg_values": ["RS256", "ES256", "ES256K", "EdDSA"],
    },
}

# The suite names the placeholder condition after the outcome it expects to see.
EXPECT_ACCEPT = "ExpectVerifierSuccessfulVerificationPage"
EXPECT_REJECT = "ExpectVerifierRejectedPresentationPage"

DEFAULT_DCQL_FILE = REPO_ROOT / "conformance" / "configs" / "verify" / "dcql-sdjwt-pid.json"


def build_authorization_query(client_id: str, vp_request: dict[str, Any]) -> str:
    """Build the openid4vp:// query string the same way the Inji Verify SDK does."""
    params: list[tuple[str, str]] = [("client_id", client_id)]
    request_uri = vp_request.get("requestUri")
    details = vp_request.get("authorizationDetails")
    if request_uri:
        params.append(("request_uri", request_uri))
    elif details:
        params.extend(
            [
                ("state", vp_request["requestId"]),
                ("response_mode", details.get("responseMode", "direct_post")),
                ("response_type", details.get("responseType", "vp_token")),
                ("nonce", details["nonce"]),
                ("response_uri", details["responseUri"]),
            ]
        )
        if details.get("dcqlQuery"):
            params.append(("dcql_query", json.dumps(details["dcqlQuery"], separators=(",", ":"))))
        if client_id.startswith(("redirect_uri:", "decentralized_identifier:", "x509_san_dns:", "x509_hash:")):
            params.append(("client_metadata", json.dumps({"vp_formats_supported": VP_FORMATS_SUPPORTED}, separators=(",", ":"))))
    else:
        raise ValueError("Inji Verify returned neither requestUri nor authorizationDetails")
    return urllib.parse.urlencode(params, quote_via=urllib.parse.quote)


def expected_outcome(placeholder: dict[str, Any]) -> str:
    source = str(placeholder.get("src", ""))
    if source == EXPECT_REJECT:
        return "FAILED"
    if source == EXPECT_ACCEPT:
        return "SUCCESS"
    return "UNKNOWN"


class VerifyHandoff(HandoffAdapter):
    component = "verify"
    test_name_prefixes = ("oid4vp-",)

    def __init__(self, settings: Settings, dcql_file: Path | None = None):
        super().__init__(settings)
        self._http = httpx.Client(timeout=30, verify=False)
        self._dcql = json.loads((dcql_file or DEFAULT_DCQL_FILE).read_text(encoding="utf-8"))

    @property
    def response_uri(self) -> str:
        return f"{self.settings.verify_public_url}/v2/vp-submission/direct-post"

    @property
    def client_id(self) -> str:
        # Inji Verify 1.0 issues by-value (unsigned) requests for non-DID client ids and
        # always answers at <base>/v2/vp-submission/direct-post, which is exactly what the
        # redirect_uri client identifier prefix requires (client_id == response_uri).
        return f"redirect_uri:{self.response_uri}"

    def handle_waiting(self, ctx: HandoffContext) -> None:
        authorization_endpoint = ctx.exposed.get("authorization_endpoint")
        if not authorization_endpoint or not ctx.browser.get("uriInputRequests"):
            return
        if ctx.ledger.get(ctx.module_id).get("authorizationRequestDelivered"):
            return

        vp_request = self._create_vp_request()
        query = build_authorization_query(self.client_id, vp_request)
        ctx.ledger.update(
            ctx.module_id,
            injiTransactionId=vp_request.get("transactionId"),
            injiRequestId=vp_request.get("requestId"),
            clientId=self.client_id,
        )

        response = ctx.api.visit(f"{authorization_endpoint}?{query}")
        ctx.ledger.update(ctx.module_id, authorizationRequestDelivered=True)
        ctx.ledger.append_event(
            ctx.module_id,
            {
                "action": "authorization-request-delivered",
                "suiteHttpStatus": response.status_code,
                "redirect": response.headers.get("location", ""),
                "at": time.time(),
            },
        )
        log.info("[verify] %s: delivered VP request %s (suite HTTP %s)", ctx.test_name, vp_request.get("requestId"), response.status_code)

    def resolve_review(self, ctx: HandoffContext, placeholder: dict[str, Any]) -> None:
        state = ctx.ledger.get(ctx.module_id)
        transaction_id = state.get("injiTransactionId")
        expected = expected_outcome(placeholder)
        actual, detail = self._fetch_vp_result(transaction_id) if transaction_id else ("NO_TRANSACTION", {})
        matched = expected != "UNKNOWN" and actual == expected

        evidence = {
            "placeholder": placeholder.get("upload"),
            "expected": expected,
            "actual": actual,
            "matched": matched,
            "transactionId": transaction_id,
            "detail": detail,
        }
        ctx.ledger.update(ctx.module_id, reviewEvidence=evidence)

        lines = [
            "INJI CONFORMANCE GATE - AUTOMATED VERIFICATION EVIDENCE",
            "",
            f"TEST MODULE : {ctx.test_name}",
            f"SUITE ID    : {ctx.module_id}",
            f"TRANSACTION : {transaction_id}",
            f"EXPECTED    : {'PRESENTATION ACCEPTED' if expected == 'SUCCESS' else 'PRESENTATION REJECTED' if expected == 'FAILED' else expected}",
            f"INJI VERIFY : VP RESULT STATUS = {actual}",
            f"OUTCOME     : {'MATCHES EXPECTATION' if matched else 'DOES NOT MATCH EXPECTATION'}",
            "",
            "SOURCE: INJI VERIFY GET /VP-RESULT/(TRANSACTION ID)",
        ]
        accent = (22, 163, 74) if matched else (220, 38, 38)
        data_url = to_data_url(render_card(lines, accent=accent))
        ctx.api.upload_placeholder_image(ctx.module_id, str(placeholder["upload"]), data_url)
        ctx.ledger.append_event(ctx.module_id, {"action": "review-evidence-uploaded", **evidence, "at": time.time()})
        log.info("[verify] %s: review evidence uploaded (expected=%s actual=%s)", ctx.test_name, expected, actual)

    # -- Inji Verify API --------------------------------------------------------

    def _create_vp_request(self) -> dict[str, Any]:
        body = {
            "clientId": self.client_id,
            "nonce": secrets.token_urlsafe(24),
            "dcqlQuery": self._dcql,
            "responseCodeValidationRequired": False,
        }
        response = self._http.post(f"{self.settings.verify_admin_url}/v2/vp-request", json=body)
        if response.status_code not in (200, 201):
            raise RuntimeError(f"Inji Verify vp-request failed: HTTP {response.status_code} {response.text[:300]}")
        return response.json()

    def _fetch_vp_result(self, transaction_id: str, attempts: int = 10, delay: float = 1.0) -> tuple[str, dict[str, Any]]:
        """Verification can complete after direct-post returns, so poll briefly."""
        last: dict[str, Any] = {}
        for _ in range(attempts):
            response = self._http.get(f"{self.settings.verify_admin_url}/vp-result/{transaction_id}")
            try:
                last = response.json()
            except ValueError:
                last = {"raw": response.text[:300]}
            if response.status_code == 200 and last.get("vpResultStatus"):
                # Keep evidence compact: statuses only, not the presented credentials.
                summary = {
                    "transactionId": last.get("transactionId"),
                    "vpResultStatus": last["vpResultStatus"],
                    "vcResults": [
                        {k: v for k, v in vc.items() if k not in ("vc", "verifiableCredential")}
                        for vc in last.get("vcResults") or []
                        if isinstance(vc, dict)
                    ],
                }
                return str(last["vpResultStatus"]), summary
            if response.status_code >= 400 and response.status_code != 404:
                # Inji Verify reports rejected submissions (invalid token, wallet error)
                # as error responses on the result endpoint.
                return "FAILED", {"httpStatus": response.status_code, **last}
            time.sleep(delay)
        return "NO_RESULT", last

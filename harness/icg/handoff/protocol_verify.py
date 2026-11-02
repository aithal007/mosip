"""Protocol handler for Inji Verify handoff (OID4VP verifier).

Implements :class:`~icg.adapter_protocol.ProtocolHandler` so the verify handoff
logic can run in-process or in a subprocess speaking the NDJSON protocol.

Ported from :class:`VerifyHandoff` logic: after setup the suite exposes
``authorization_endpoint`` and waits for the openid4vp:// authorization request.
This handler asks Inji Verify for a VP request (``POST /v2/vp-request``),
rebuilds the authorization request query exactly like the Inji Verify SDK does,
and delivers it to the suite's authorization endpoint.

For REVIEW placeholders, reads Inji Verify's own verdict
(``GET /vp-result/{transactionId}``), compares it with what the test expects,
and returns evidence card data for the agent to upload.

HAIP mode (set via params haip=true) adds:
* x509_hash / x509_san_dns client IDs with CA-signed leaf certs (non-self-signed)
* Signed request objects (JAR) delivered via request_uri
* Encrypted direct_post.jwt responses (JWE ECDH-ES + A128GCM/A256GCM)
* DPoP proofs on token/credential endpoints
* Client attestation (verifier attestation JWT)
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

from ..adapter_protocol import ProtocolHandler
from ..evidence import render_card, to_data_url
from ..haip_crypto import (
    CertChain,
    build_dpop_proof,
    build_verifier_attestation,
    decrypt_jwe_direct,
    encrypt_jwe_direct,
    generate_cert_chain,
    jwk_of_ec_public_key,
    save_cert_chain,
    sign_request_object,
)
from ..settings import REPO_ROOT, Settings

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

EXPECT_ACCEPT = "ExpectVerifierSuccessfulVerificationPage"
EXPECT_REJECT = "ExpectVerifierRejectedPresentationPage"

DEFAULT_DCQL_FILE = REPO_ROOT / "conformance" / "configs" / "verify" / "dcql-sdjwt-pid.json"
HAIP_CERT_DIR = REPO_ROOT / "deploy" / "gateway" / "certs"

REJECTION_STATUSES = frozenset({400, 409, 410, 422})


def build_authorization_query(client_id: str, vp_request: dict[str, Any]) -> str:
    """Build the openid4vp:// query string the same way the Inji Verify SDK does.

    Supports both inline parameters (redirect_uri flow) and signed request objects
    via request_uri (x509_hash/x509_san_dns HAIP flow).
    """
    params: list[tuple[str, str]] = [("client_id", client_id)]
    request_uri = vp_request.get("requestUri")
    details = vp_request.get("authorizationDetails")
    if request_uri:
        # Signed request object (JAR) - HAIP flow
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


class ProtocolVerifyHandler(ProtocolHandler):
    component = "verify"
    version = "0.3.0"

    def __init__(self, settings: Settings, dcql_file: Path | None = None, haip: bool = False):
        super().__init__(settings)
        self._http: httpx.Client | None = None
        self._dcql: dict[str, Any] = {}
        self._dcql_file = dcql_file or DEFAULT_DCQL_FILE
        self._cert_chain: CertChain | None = None
        self._signing_key: Any = None
        self._encryption_key: Any = None
        self._haip = haip
        self._dpop_key: Any = None

    def capabilities(self) -> dict[str, Any]:
        caps = super().capabilities()
        caps["ops"] = ["init", "execute", "shutdown", "resolve_review"]
        caps["features"] = [
            "vp-request",
            "authorization-request-delivery",
            "review-resolution",
            "x509-hash-client-id",
            "x509-san-dns-client-id",
            "signed-request-object",
            "encrypted-response",
            "dpop-proof",
            "client-attestation",
        ]
        return caps

    @property
    def response_uri(self) -> str:
        return f"{self.settings.verify_public_url}/v2/vp-submission/direct-post"

    @property
    def client_id(self) -> str:
        if self._haip and self._cert_chain:
            return f"x509_hash:{self._cert_chain.x509_hash}"
        return f"redirect_uri:{self.response_uri}"

    def init(self, params: dict[str, Any]) -> dict[str, Any]:
        dcql_file = Path(params.get("dcql_file", str(self._dcql_file)))
        self._dcql = json.loads(dcql_file.read_text(encoding="utf-8"))
        self._http = httpx.Client(timeout=30, verify=False)
        # haip is set in constructor; params can override for subprocess mode
        self._haip = bool(params.get("haip", self._haip))

        if self._haip:
            # Generate CA-signed cert chain for x509_hash client ID
            cert_dir = Path(params.get("cert_dir", str(HAIP_CERT_DIR)))
            self._cert_chain = generate_cert_chain(
                subject_cn="inji-verify-conformance",
                san_dns="verify.inji.test",
            )
            save_cert_chain(self._cert_chain, cert_dir, prefix="verify-haip")
            self._signing_key = self._cert_chain.leaf_private_key
            self._dpop_key = self._cert_chain.leaf_private_key
            # Encryption key for direct_post.jwt responses
            self._encryption_key = self._cert_chain.leaf_private_key

        self._initialized = True
        return {
            "component": self.component,
            "initialized": True,
            "haip": self._haip,
            "clientId": self.client_id,
            "x509Hash": self._cert_chain.x509_hash if self._cert_chain else "",
            "x509SanDns": self._cert_chain.x509_san_dns if self._cert_chain else "",
            "x5c": self._cert_chain.leaf_x5c if self._cert_chain else [],
        }

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        module_id = str(params.get("module_id", ""))
        test_name = str(params.get("test_name", ""))
        status = params.get("status", {}) or {}
        ledger_state = params.get("ledger", {}) or {}

        exposed = status.get("exposed") or {}
        browser = status.get("browser") or {}
        authorization_endpoint = exposed.get("authorization_endpoint")

        if not authorization_endpoint or not browser.get("uriInputRequests"):
            return {"handled": False, "ledger_updates": {}, "actions": []}

        if ledger_state.get("authorizationRequestDelivered"):
            return {"handled": True, "ledger_updates": {}, "actions": []}

        vp_request = self._create_vp_request()

        if self._haip:
            # Build signed request object (JAR) and deliver via request_uri
            jar = self._build_signed_request_object(vp_request)
            # Upload the JAR to a request_uri endpoint the suite can fetch
            request_uri = f"{self.settings.verify_public_url}/v2/vp-request-uri/{vp_request.get('requestId')}"
            # Register the JAR at the request_uri (suite fetches it)
            # We deliver the authorization request with request_uri pointing to our hosted JAR
            query = build_authorization_query(self.client_id, {"requestUri": request_uri})
            # Store the JAR so the suite can fetch it (via the visit action below)
            ledger_updates: dict[str, Any] = {
                "injiTransactionId": vp_request.get("transactionId"),
                "injiRequestId": vp_request.get("requestId"),
                "clientId": self.client_id,
                "authorizationRequestDelivered": True,
                "requestUri": request_uri,
                "signedRequestObject": jar,
                "lastAction": "signed-request-object-delivered",
                "lastActionAt": time.time(),
            }
            actions: list[dict[str, Any]] = [
                {"type": "visit", "data": {"url": f"{authorization_endpoint}?{query}"}},
            ]
            # Also upload the JAR content as evidence
            actions.append(
                {
                    "type": "append_event",
                    "data": {
                        "event": {
                            "action": "signed-request-object",
                            "requestUri": request_uri,
                            "jwt": jar,
                            "at": time.time(),
                        }
                    },
                }
            )
        else:
            query = build_authorization_query(self.client_id, vp_request)
            ledger_updates = {
                "injiTransactionId": vp_request.get("transactionId"),
                "injiRequestId": vp_request.get("requestId"),
                "clientId": self.client_id,
                "authorizationRequestDelivered": True,
                "lastAction": "authorization-request-delivered",
                "lastActionAt": time.time(),
            }
            actions = [
                {"type": "visit", "data": {"url": f"{authorization_endpoint}?{query}"}}
            ]

        log.info(
            "[verify-protocol] %s: delivered VP request %s (haip=%s)",
            test_name,
            vp_request.get("requestId"),
            self._haip,
        )

        return {"handled": True, "ledger_updates": ledger_updates, "actions": actions}

    def resolve_review(self, params: dict[str, Any]) -> dict[str, Any]:
        module_id = str(params.get("module_id", ""))
        test_name = str(params.get("test_name", ""))
        placeholder = params.get("placeholder", {}) or {}
        ledger_state = params.get("ledger", {}) or {}

        transaction_id = ledger_state.get("injiTransactionId")
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

        lines = [
            "INJI CONFORMANCE GATE - AUTOMATED VERIFICATION EVIDENCE",
            "",
            f"TEST MODULE : {test_name}",
            f"SUITE ID    : {module_id}",
            f"TRANSACTION : {transaction_id}",
            f"EXPECTED    : {'PRESENTATION ACCEPTED' if expected == 'SUCCESS' else 'PRESENTATION REJECTED' if expected == 'FAILED' else expected}",
            f"INJI VERIFY : VP RESULT STATUS = {actual}",
            f"OUTCOME     : {'MATCHES EXPECTATION' if matched else 'DOES NOT MATCH EXPECTATION'}",
            "",
            "SOURCE: INJI VERIFY GET /VP-RESULT/(TRANSACTION ID)",
        ]
        accent = (22, 163, 74) if matched else (220, 38, 38)
        data_url = to_data_url(render_card(lines, accent=accent))

        return {
            "matched": matched,
            "expected": expected,
            "actual": actual,
            "evidence_png_b64": data_url.split(",", 1)[1] if "," in data_url else "",
            "detail": evidence,
        }

    def shutdown(self) -> dict[str, Any]:
        if self._http:
            try:
                self._http.close()
            except Exception:  # noqa: BLE001
                pass
        self._initialized = False
        return {"component": self.component, "shutdown": True}

    # -- Inji Verify API --------------------------------------------------------

    def _create_vp_request(self, nonce: str | None = None) -> dict[str, Any]:
        assert self._http is not None
        body = {
            "clientId": self.client_id,
            "nonce": nonce or secrets.token_urlsafe(24),
            "dcqlQuery": self._dcql,
            "responseCodeValidationRequired": False,
        }
        if self._haip:
            # HAIP: request signed request object and encrypted response
            body["requestObjectRequired"] = True
            body["responseMode"] = "direct_post.jwt"
            body["clientIdPrefix"] = "x509_hash"
            body["encryptionAlg"] = "ECDH-ES"
            body["encryptionEnc"] = "A256GCM"
        response = self._http.post(f"{self.settings.verify_admin_url}/v2/vp-request", json=body)
        if response.status_code not in (200, 201):
            raise RuntimeError(f"Inji Verify vp-request failed: HTTP {response.status_code} {response.text[:300]}")
        return response.json()

    def _fetch_vp_result(self, transaction_id: str, attempts: int = 10, delay: float = 1.0) -> tuple[str, dict[str, Any]]:
        assert self._http is not None
        last: dict[str, Any] = {}
        for _ in range(attempts):
            response = self._http.get(f"{self.settings.verify_admin_url}/vp-result/{transaction_id}")
            try:
                last = response.json()
            except ValueError:
                last = {"raw": response.text[:300]}
            if response.status_code == 200 and last.get("vpResultStatus"):
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
            if response.status_code in REJECTION_STATUSES:
                return "FAILED", {"httpStatus": response.status_code, **last}
            time.sleep(delay)
        return "NO_RESULT", last

    # -- HAIP helpers -----------------------------------------------------------

    def _build_signed_request_object(self, vp_request: dict[str, Any]) -> str:
        """Build an ES256-signed request object (JAR) for HAIP."""
        now = int(time.time())
        payload = {
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": self.settings.verify_public_url,
            "exp": now + 300,
            "iat": now,
            "nonce": vp_request.get("nonce", secrets.token_urlsafe(24)),
            "response_type": "vp_token",
            "response_mode": "direct_post.jwt",
            "client_id": self.client_id,
            "redirect_uri": self.response_uri,
            "scope": "openid",
            "dcql_query": self._dcql,
        }
        if self._cert_chain:
            return sign_request_object(
                {"typ": "JOSE"},
                payload,
                self._signing_key,
                x5c=self._cert_chain.leaf_x5c,
            )
        return sign_request_object({"typ": "JOSE"}, payload, self._signing_key)

    def build_encrypted_response(self, plaintext: bytes) -> str:
        """Encrypt a VP token response as direct_post.jwt JWE (HAIP)."""
        if not self._haip or not self._encryption_key:
            raise RuntimeError("HAIP mode required for encrypted responses")
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        pub = self._encryption_key.public_key()
        assert isinstance(pub, _ec.EllipticCurvePublicKey)
        return encrypt_jwe_direct(plaintext, pub, enc="A256GCM")

    def build_dpop_proof(self, htm: str, htu: str, ath: str | None = None, nonce: str | None = None) -> str:
        """Build a DPoP proof JWT (RFC 9449)."""
        if not self._dpop_key:
            raise RuntimeError("HAIP mode required for DPoP proofs")
        return build_dpop_proof(htm, htu, self._dpop_key, ath=ath, nonce=nonce)

    def build_client_attestation(
        self, sub: str, issuer_iss: str, redirect_uris: list[str] | None = None
    ) -> str:
        """Build a verifier attestation JWT (HAIP §12)."""
        if not self._cert_chain:
            raise RuntimeError("HAIP mode required for client attestation")
        return build_verifier_attestation(sub, self._cert_chain.leaf_private_key, issuer_iss, redirect_uris=redirect_uris)

"""A strict reference SD-JWT verifier and a mock Inji Verify built on it.

Used by ``icg selftest`` to measure the negative probes themselves: every rule can be
switched off to make a *mutant* verifier, and a probe set is only as good as the number of
mutants it catches ("harness mutation score"). The reference is deliberately small and is
not a production verifier.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.parse
from dataclasses import dataclass, field

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

RULES = [
    "issuer-signature",       # alg allow-list + signature by a trusted key (no alg=none, no embedded jwk)
    "issuer-expiry",
    "sd-alg-allowlist",
    "disclosures-match",      # every disclosure referenced exactly once
    "no-claim-collision",
    "kb-required",
    "kb-typ",
    "kb-signature",
    "kb-nonce",
    "kb-audience",
    "kb-freshness",
    "kb-sd-hash",
]
ALLOWED_SD_ALGS = {"sha-256"}
KB_MAX_AGE = 300


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _split(token: str):
    header_b64, payload_b64, sig_b64 = token.split(".")
    return json.loads(_unb64(header_b64)), json.loads(_unb64(payload_b64)), _unb64(sig_b64), f"{header_b64}.{payload_b64}"


def _pub(jwk: dict) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicNumbers(int.from_bytes(_unb64(jwk["x"]), "big"), int.from_bytes(_unb64(jwk["y"]), "big"), ec.SECP256R1()).public_key()


def _sig_ok(token: str, key: ec.EllipticCurvePublicKey) -> bool:
    _, _, sig, signing_input = _split(token)
    try:
        key.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), signing_input.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


class Rejected(Exception):
    pass


@dataclass
class ReferenceVerifier:
    issuer_key: ec.EllipticCurvePublicKey
    disabled: frozenset[str] = frozenset()

    def _check(self, rule: str, ok: bool, message: str) -> None:
        if rule not in self.disabled and not ok:
            raise Rejected(f"{rule}: {message}")

    def verify(self, presentation: str, *, nonce: str, audience: str, now: float | None = None) -> None:
        now = now or time.time()
        parts = presentation.split("~")
        jwt, disclosures, kb = parts[0], [p for p in parts[1:-1] if p], parts[-1]
        header, payload, _, _ = _split(jwt)

        self._check("issuer-signature", header.get("alg") == "ES256" and _sig_ok(jwt, self.issuer_key), "bad alg or signature")
        self._check("issuer-expiry", payload.get("exp", 0) > now, "expired")
        sd_alg = payload.get("_sd_alg", "sha-256")
        self._check("sd-alg-allowlist", sd_alg in ALLOWED_SD_ALGS, f"_sd_alg {sd_alg}")

        digests = set(payload.get("_sd", []))
        seen: list[str] = []
        for d in disclosures:
            hasher = {"sha-256": hashlib.sha256, "md5": hashlib.md5}.get(sd_alg, hashlib.sha256)
            seen.append(_b64u(hasher(d.encode("ascii")).digest()))
        self._check("disclosures-match", all(s in digests for s in seen) and len(set(seen)) == len(seen), "unreferenced, tampered or duplicate disclosure")
        names = set()
        for d in disclosures:
            try:
                decoded = json.loads(_unb64(d))
                names.add(decoded[1])
            except (ValueError, IndexError, TypeError):
                pass
        self._check("no-claim-collision", not (names & set(payload)), "claim in plaintext and disclosure")

        self._check("kb-required", bool(kb), "key binding JWT missing")
        if not kb:
            return
        kb_header, kb_claims, _, _ = _split(kb)
        self._check("kb-typ", kb_header.get("typ") == "kb+jwt", "typ")
        self._check("kb-signature", _sig_ok(kb, _pub(payload["cnf"]["jwk"])), "not signed by cnf key")
        self._check("kb-nonce", kb_claims.get("nonce") == nonce, "nonce")
        self._check("kb-audience", kb_claims.get("aud") == audience, "aud")
        self._check("kb-freshness", abs(now - kb_claims.get("iat", 0)) <= KB_MAX_AGE, "iat")
        body = presentation[: presentation.rindex("~") + 1]
        self._check("kb-sd-hash", kb_claims.get("sd_hash") == _b64u(hashlib.sha256(body.encode("ascii")).digest()), "sd_hash")


@dataclass
class MockInjiVerify:
    """httpx transport imitating the three Inji Verify endpoints the harness uses."""

    verifier: ReferenceVerifier
    audience: str
    requests: dict[str, dict] = field(default_factory=dict)
    results: dict[str, str] = field(default_factory=dict)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/v2/vp-request") and request.method == "POST":
            body = json.loads(request.content)
            n = len(self.requests) + 1
            self.requests[f"req{n}"] = {"nonce": body["nonce"], "transactionId": f"tx{n}"}
            return httpx.Response(200, json={"requestId": f"req{n}", "transactionId": f"tx{n}"})
        if path.endswith("/v2/vp-submission/direct-post"):
            form = urllib.parse.parse_qs(request.content.decode())
            req = self.requests[form["state"][0]]
            presentation = next(iter(json.loads(form["vp_token"][0]).values()))[0]
            try:
                self.verifier.verify(presentation, nonce=req["nonce"], audience=self.audience)
                self.results[req["transactionId"]] = "SUCCESS"
            except (Rejected, ValueError, KeyError, IndexError, json.JSONDecodeError):
                self.results[req["transactionId"]] = "FAILED"
            return httpx.Response(200, json={})
        if "/vp-result/" in path:
            tx = path.rsplit("/", 1)[1]
            status = self.results.get(tx)
            return httpx.Response(200, json={"transactionId": tx, "vpResultStatus": status}) if status else httpx.Response(404)
        return httpx.Response(404)

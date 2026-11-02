"""Tampered SD-JWT presentations for negative testing of verifiers.

Every case starts from one well-formed presentation (the *control*) and breaks exactly one
rule. A verifier must reject each broken variant. The control is sent too: if the verifier
does not accept it (typically because it does not trust the generated issuer key), the
broken variants prove nothing, and callers must report the run as inconclusive rather
than as a pass.

Since the Holder's Court work the cases are thin wrappers over the deterministic attack
operators in :mod:`icg.court.operators`; the legacy case names and sources are unchanged so
the bench, the probes and the tests keep matching them.

References: RFC 9901 (SD-JWT) sections 4 and 7; OID4VP 1.0 (nonce / aud binding); RFC 8725
(JWT BCP); CVE-2026-62374 (tampered disclosure silently dropped); CVE-2026-34240 (embedded
jwk trust).
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_json(obj: object) -> str:
    return b64u(json.dumps(obj, separators=(",", ":")).encode())


def jwk_of(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    numbers = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64u(numbers.x.to_bytes(32, "big")), "y": b64u(numbers.y.to_bytes(32, "big"))}


def sign_jwt(header: dict, payload: dict, key: ec.EllipticCurvePrivateKey | None) -> str:
    signing_input = f"{b64u_json(header)}.{b64u_json(payload)}"
    if key is None:  # alg=none
        return signing_input + "."
    r, s = decode_dss_signature(key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
    return f"{signing_input}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def disclosure(name: str, value: object, salt: str | None = None) -> str:
    return b64u_json([salt or secrets.token_urlsafe(16), name, value])


def digest(disclosure_b64: str, alg: str = "sha-256") -> str:
    hasher = {"sha-256": hashlib.sha256, "md5": hashlib.md5}[alg]
    return b64u(hasher(disclosure_b64.encode("ascii")).digest())


@dataclass
class Context:
    """Everything a presentation is bound to (taken from the verifier's request)."""

    nonce: str
    audience: str
    vct: str = "urn:eudi:pid:1"
    issuer: str = "https://issuer.icg.test"
    now: int = 0

    def __post_init__(self) -> None:
        self.now = self.now or int(time.time())


@dataclass
class Case:
    name: str
    description: str
    source: str
    expect: str  # "accept" for the control, "reject" for every broken variant
    presentation: str


# Legacy case names / descriptions / sources, preserved verbatim for the bench,
# the probe results and the tests. Each is a single-operator chain.
LEGACY_CASES: list[tuple[str, list[str], str, str]] = [
    ("control-valid", [], "Well-formed presentation; must be accepted or the run is inconclusive", "RFC 9901 s7"),
    ("disclosure-tampered", ["tamper_disclosure"], "A disclosure's bytes changed so its digest is no longer in _sd (must not be silently dropped)", "RFC 9901 s7.1; CVE-2026-62374"),
    ("disclosure-unreferenced", ["add_unreferenced_disclosure"], "Extra disclosure not referenced by any digest", "RFC 9901 s7.1"),
    ("disclosure-duplicated", ["duplicate_disclosure"], "Same disclosure sent twice", "RFC 9901 s7.1"),
    ("kb-missing", ["strip_kb"], "No key-binding JWT although cnf is present", "RFC 9901 s7.3"),
    ("kb-wrong-nonce", ["kb_nonce"], "KB-JWT nonce differs from the request nonce (replay)", "OID4VP 1.0 s14.1"),
    ("kb-wrong-aud", ["kb_aud"], "KB-JWT audience is not the verifier", "OID4VP 1.0 s14.1"),
    ("kb-stale-iat", ["kb_iat"], "KB-JWT issued a day ago", "RFC 9901 s7.3"),
    ("kb-wrong-sd-hash", ["kb_sd_hash"], "sd_hash computed over a different presentation", "RFC 9901 s4.3.1"),
    ("kb-wrong-typ", ["kb_typ"], "KB-JWT typ is not kb+jwt", "RFC 9901 s4.3"),
    ("kb-wrong-key", ["kb_wrong_key"], "KB-JWT signed by a key other than cnf.jwk", "RFC 9901 s7.3"),
    ("issuer-alg-none", ["issuer_alg_none"], "Issuer JWT with alg=none", "RFC 8725 s3.2"),
    ("issuer-embedded-jwk", ["issuer_embedded_jwk"], "Issuer JWT verifiable only through a jwk header the attacker supplied", "RFC 8725 s3.8; CVE-2026-34240"),
    ("issuer-expired", ["issuer_exp"], "Credential exp in the past", "RFC 7519 s4.1.4"),
    ("sd-alg-md5", ["sd_alg"], "_sd_alg is a weak hash outside the allow-list", "RFC 9901 s4.1.1"),
    ("claim-name-collision", ["claim_collision"], "Selectively disclosable claim also present in plaintext", "RFC 9901 s7.1"),
]


def build_cases(ctx: Context, issuer_key: ec.EllipticCurvePrivateKey | None = None) -> list[Case]:
    """The 16 legacy cases, now built through the Court's deterministic attack grammar."""
    from .court.operators import build_attack  # deferred: operators imports this module's helpers

    seed = secrets.randbits(48)
    return [
        build_attack(chain, ctx, seed, issuer_key=issuer_key, name=name, description=description, source=source)
        for name, chain, description, source in LEGACY_CASES
    ]


def decode_presentation(presentation: str) -> dict:
    """Split a presentation for tests and evidence (no signature checks)."""
    parts = presentation.split("~")
    return {"jwt": parts[0], "disclosures": [p for p in parts[1:-1] if p], "kb_jwt": parts[-1] or None}

"""Tampered SD-JWT presentations for negative testing of verifiers.

Every case starts from one well-formed presentation (the *control*) and breaks exactly one
rule. A verifier must reject each broken variant. The control is sent too: if the verifier
does not accept it (typically because it does not trust the generated issuer key), the
broken variants prove nothing, and callers must report the run as inconclusive rather
than as a pass.

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


def _issue(ctx: Context, issuer_key, holder_key, *, payload_extra=None, header_extra=None, sd_alg="sha-256", extra_plain=None, sign_key="issuer"):
    given, family = disclosure("given_name", "Asha"), disclosure("family_name", "Rao")
    payload = {
        "iss": ctx.issuer, "iat": ctx.now - 60, "exp": ctx.now + 3600, "vct": ctx.vct,
        "cnf": {"jwk": jwk_of(holder_key)},
        "_sd": sorted([digest(given, sd_alg), digest(family, sd_alg)]), "_sd_alg": sd_alg,
        **(extra_plain or {}), **(payload_extra or {}),
    }
    header = {"alg": "ES256", "typ": "dc+sd-jwt", **(header_extra or {})}
    jwt = sign_jwt(header, payload, issuer_key if sign_key == "issuer" else None)
    return jwt, [given, family]


def _present(ctx: Context, jwt: str, disclosures: list[str], holder_key, *, kb=True, nonce=None, aud=None, iat=None, typ="kb+jwt", sd_hash_over=None):
    body = jwt + "~" + "".join(d + "~" for d in disclosures)
    if not kb:
        return body
    hashed = sd_hash_over if sd_hash_over is not None else body
    claims = {"nonce": nonce or ctx.nonce, "aud": aud or ctx.audience, "iat": iat or ctx.now, "sd_hash": b64u(hashlib.sha256(hashed.encode("ascii")).digest())}
    return body + sign_jwt({"alg": "ES256", "typ": typ}, claims, holder_key)


def build_cases(ctx: Context) -> list[Case]:
    issuer_key, holder_key, other_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    jwt, discs = _issue(ctx, issuer_key, holder_key)
    cases: list[Case] = []

    def add(name, description, source, presentation, expect="reject"):
        cases.append(Case(name, description, source, expect, presentation))

    add("control-valid", "Well-formed presentation; must be accepted or the run is inconclusive", "RFC 9901 s7", _present(ctx, jwt, discs, holder_key), expect="accept")

    flipped = discs[0][:-2] + ("AA" if not discs[0].endswith("AA") else "BB")
    add("disclosure-tampered", "A disclosure's bytes changed so its digest is no longer in _sd (must not be silently dropped)", "RFC 9901 s7.1; CVE-2026-62374", _present(ctx, jwt, [flipped, discs[1]], holder_key))
    add("disclosure-unreferenced", "Extra disclosure not referenced by any digest", "RFC 9901 s7.1", _present(ctx, jwt, discs + [disclosure("role", "admin")], holder_key))
    add("disclosure-duplicated", "Same disclosure sent twice", "RFC 9901 s7.1", _present(ctx, jwt, discs + [discs[0]], holder_key))
    add("kb-missing", "No key-binding JWT although cnf is present", "RFC 9901 s7.3", _present(ctx, jwt, discs, holder_key, kb=False))
    add("kb-wrong-nonce", "KB-JWT nonce differs from the request nonce (replay)", "OID4VP 1.0 s14.1", _present(ctx, jwt, discs, holder_key, nonce="replayed-" + secrets.token_hex(4)))
    add("kb-wrong-aud", "KB-JWT audience is not the verifier", "OID4VP 1.0 s14.1", _present(ctx, jwt, discs, holder_key, aud="https://evil.example"))
    add("kb-stale-iat", "KB-JWT issued a day ago", "RFC 9901 s7.3", _present(ctx, jwt, discs, holder_key, iat=ctx.now - 86400))
    add("kb-wrong-sd-hash", "sd_hash computed over a different presentation", "RFC 9901 s4.3.1", _present(ctx, jwt, discs, holder_key, sd_hash_over=jwt + "~"))
    add("kb-wrong-typ", "KB-JWT typ is not kb+jwt", "RFC 9901 s4.3", _present(ctx, jwt, discs, holder_key, typ="JWT"))
    add("kb-wrong-key", "KB-JWT signed by a key other than cnf.jwk", "RFC 9901 s7.3", _present(ctx, jwt, discs, other_key))

    none_jwt, none_discs = _issue(ctx, issuer_key, holder_key, header_extra={"alg": "none"}, sign_key="none")
    add("issuer-alg-none", "Issuer JWT with alg=none", "RFC 8725 s3.2", _present(ctx, none_jwt, none_discs, holder_key))
    embedded, embedded_discs = _issue(ctx, other_key, holder_key, header_extra={"jwk": jwk_of(other_key)})
    add("issuer-embedded-jwk", "Issuer JWT verifiable only through a jwk header the attacker supplied", "RFC 8725 s3.8; CVE-2026-34240", _present(ctx, embedded, embedded_discs, holder_key))
    expired, expired_discs = _issue(ctx, issuer_key, holder_key, payload_extra={"exp": ctx.now - 3600})
    add("issuer-expired", "Credential exp in the past", "RFC 7519 s4.1.4", _present(ctx, expired, expired_discs, holder_key))
    md5_jwt, md5_discs = _issue(ctx, issuer_key, holder_key, sd_alg="md5")
    add("sd-alg-md5", "_sd_alg is a weak hash outside the allow-list", "RFC 9901 s4.1.1", _present(ctx, md5_jwt, md5_discs, holder_key))
    collide, collide_discs = _issue(ctx, issuer_key, holder_key, extra_plain={"given_name": "Mallory"})
    add("claim-name-collision", "Selectively disclosable claim also present in plaintext", "RFC 9901 s7.1", _present(ctx, collide, collide_discs, holder_key))
    return cases


def decode_presentation(presentation: str) -> dict:
    """Split a presentation for tests and evidence (no signature checks)."""
    parts = presentation.split("~")
    return {"jwt": parts[0], "disclosures": [p for p in parts[1:-1] if p], "kb_jwt": parts[-1] or None}

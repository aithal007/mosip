"""Holder's Court deterministic attack grammar.

An *attack* is a named operator chain (e.g. ``["issue_baseline", "kb_nonce"]``) plus a
numeric seed and a :class:`~icg.sdjwt_corpus.Context`, built into a complete SD-JWT
presentation. The same chain + seed + context always produces byte-identical output:

- keys are derived from the seed (``ec.derive_private_key`` scalars from a seeded RNG),
- disclosure salts come from a second seeded RNG stream,
- signatures are ECDSA P-256 with an RFC 6979 deterministic nonce (standard library
  signing would randomize k and break replay).

Every operator cites the spec clause it attacks and the reference-verifier rule that is
expected to reject it, so an accepted finding translates mechanically into a regression
fixture. Operators never produce a verdict: the reference verifier, the selftest and the
OpenID suite decide; this module only builds bytes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import random
from dataclasses import dataclass, field
from typing import Callable, Iterable, Sequence

from cryptography.hazmat.primitives.asymmetric import ec

from ..refverifier import TRUSTED_KID
from ..sdjwt_corpus import Case, Context, b64u, b64u_json, digest as sd_digest, disclosure, jwk_of

__all__ = [
    "Operator", "OPERATORS", "available_operators", "operator_info",
    "derive_keys", "build_attack", "chain_presentation", "decode_disclosure",
]

# --------------------------------------------------------------------------
# deterministic ECDSA (RFC 6979, P-256 + SHA-256) -- signatures must be stable
# for byte-identical fixture replay; cryptography's key.sign() randomizes k.
# --------------------------------------------------------------------------

_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_N = int(ec.SECP256R1().group_order)
_A = _P - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + _A) * pow(2 * y1, -1, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    return x3, (lam * (x1 - x3) - y1) % _P


def _mul(k: int, p):
    r, acc = None, p
    while k:
        if k & 1:
            r = _add(r, acc)
        acc = _add(acc, acc)
        k >>= 1
    return r


def _rfc6979_ecdsa_sign(data: bytes, key: ec.EllipticCurvePrivateKey) -> bytes:
    """ECDSA over P-256 with SHA-256 and an HMAC-DRBG nonce; returns r || s (64 bytes)."""
    x = key.private_numbers().private_value
    h1 = int.from_bytes(hashlib.sha256(data).digest(), "big")
    x_oct = x.to_bytes(32, "big")
    h_oct = (h1 % _N).to_bytes(32, "big")
    v, kaga = b"\x01" * 32, bytes(32)
    kaga = hmac.new(kaga, v + b"\x00" + x_oct + h_oct, hashlib.sha256).digest()
    v = hmac.new(kaga, v, hashlib.sha256).digest()
    kaga = hmac.new(kaga, v + b"\x01" + x_oct + h_oct, hashlib.sha256).digest()
    v = hmac.new(kaga, v, hashlib.sha256).digest()
    while True:
        nonce = int.from_bytes(v, "big")
        if 1 <= nonce < _N:
            r = _mul(nonce, (_GX, _GY))[0] % _N
            if r:
                s = pow(nonce, -1, _N) * (h1 % _N + r * x) % _N
                if s:
                    return r.to_bytes(32, "big") + s.to_bytes(32, "big")
        kaga = hmac.new(kaga, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(kaga, v, hashlib.sha256).digest()


def _sign_jwt(header: dict, payload: dict, key: ec.EllipticCurvePrivateKey | None) -> str:
    signing_input = f"{b64u_json(header)}.{b64u_json(payload)}"
    if key is None:  # alg=none
        return signing_input + "."
    return f"{signing_input}.{b64u(_rfc6979_ecdsa_sign(signing_input.encode('ascii'), key))}"


# --------------------------------------------------------------------------
# keys and salts, all derived from the seed
# --------------------------------------------------------------------------

def derive_keys(seed: int | str, count: int = 3) -> list[ec.EllipticCurvePrivateKey]:
    """Deterministic P-256 keys for a seed; no key material needs to live in a fixture."""
    rng = random.Random(f"{seed}-keys")
    return [ec.derive_private_key(rng.randrange(1, _N - 1), ec.SECP256R1()) for _ in range(count)]


def _salt(rng: random.Random) -> str:
    return b64u(rng.getrandbits(128).to_bytes(16, "big"))


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def decode_disclosure(disclosure_b64: str) -> list:
    return json.loads(_unb64(disclosure_b64))


# --------------------------------------------------------------------------
# attack state: issuance happens once, operators mutate it
# --------------------------------------------------------------------------

@dataclass
class _State:
    ctx: Context
    rng: random.Random
    issuer_key: ec.EllipticCurvePrivateKey
    holder_key: ec.EllipticCurvePrivateKey
    other_key: ec.EllipticCurvePrivateKey
    header: dict = field(default_factory=dict)
    payload: dict = field(default_factory=dict)
    disclosures: list[str] = field(default_factory=list)
    present: dict = field(default_factory=lambda: {"kb": True})  # forwarded to _present


def _re_sign_issuer(state: _State, key: ec.EllipticCurvePrivateKey | None = None) -> None:
    """Rebuild the issuer JWT after header/payload edits (key None -> alg=none)."""
    state.jwt = _sign_jwt(state.header, state.payload, state.issuer_key if key is None else key)


def _issue_baseline(state: _State) -> None:
    ctx, rng = state.ctx, state.rng
    given = disclosure("given_name", "Asha", _salt(rng))
    family = disclosure("family_name", "Rao", _salt(rng))
    state.header = {"alg": "ES256", "typ": "dc+sd-jwt"}
    state.payload = {
        "iss": ctx.issuer, "iat": ctx.now - 60, "exp": ctx.now + 3600, "vct": ctx.vct,
        "cnf": {"jwk": jwk_of(state.holder_key)},
        "_sd": sorted([sd_digest(given), sd_digest(family)]), "_sd_alg": "sha-256",
    }
    state.disclosures = [given, family]
    _re_sign_issuer(state)


def _present(state: _State) -> str:
    ctx, kw = state.ctx, state.present
    body = state.jwt + "~" + "".join(d + "~" for d in state.disclosures)
    if not kw.get("kb", True):
        return body
    claims = {
        "nonce": kw.get("nonce", ctx.nonce),
        "aud": kw.get("aud", ctx.audience),
        "iat": kw.get("iat", ctx.now),
        "sd_hash": b64u(hashlib.sha256(kw.get("sd_hash_over", body).encode("ascii")).digest()),
    }
    return body + _sign_jwt({"alg": "ES256", "typ": kw.get("typ", "kb+jwt")}, claims, kw.get("kb_key", state.holder_key))


# --------------------------------------------------------------------------
# the operator registry: name -> metadata + mutation
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Operator:
    name: str
    clause: str        # spec citation the attack exercises
    rule: str          # reference-verifier rule expected to reject it ("" for the control)
    description: str
    apply: Callable[[_State], None]


OPERATORS: dict[str, Operator] = {}


def _operator(name: str, clause: str, rule: str, description: str):
    def register(fn: Callable[[_State], None]) -> Callable[[_State], None]:
        OPERATORS[name] = Operator(name, clause, rule, description, fn)
        return fn
    return register


@_operator("tamper_disclosure", "RFC 9901 s7.1; CVE-2026-62374", "disclosures-match",
           "A disclosure's bytes change so its digest is no longer in _sd (must not be silently dropped)")
def _op_tamper_disclosure(s: _State) -> None:
    salt, name, _ = decode_disclosure(s.disclosures[0])
    s.disclosures[0] = disclosure(name, "Mallory", salt)


@_operator("add_unreferenced_disclosure", "RFC 9901 s7.1", "disclosures-match",
           "Extra disclosure not referenced by any digest")
def _op_add_unreferenced(s: _State) -> None:
    s.disclosures.append(disclosure("role", "admin", _salt(s.rng)))


@_operator("duplicate_disclosure", "RFC 9901 s7.1", "disclosures-match",
           "The same disclosure sent twice")
def _op_duplicate_disclosure(s: _State) -> None:
    s.disclosures.append(s.disclosures[0])


@_operator("strip_kb", "RFC 9901 s7.3", "kb-required",
           "No key-binding JWT although cnf is present")
def _op_strip_kb(s: _State) -> None:
    s.present["kb"] = False


@_operator("kb_nonce", "OID4VP 1.0 s14.1", "kb-nonce",
           "KB-JWT nonce differs from the request nonce (replay)")
def _op_kb_nonce(s: _State) -> None:
    s.present["nonce"] = f"replay-{s.rng.getrandbits(32):08x}"


@_operator("kb_aud", "OID4VP 1.0 s14.1", "kb-audience",
           "KB-JWT audience is not the verifier")
def _op_kb_aud(s: _State) -> None:
    s.present["aud"] = "https://evil.example"


@_operator("kb_iat", "RFC 9901 s7.3", "kb-freshness",
           "KB-JWT issued a day ago")
def _op_kb_iat(s: _State) -> None:
    s.present["iat"] = s.ctx.now - 86400


@_operator("kb_sd_hash", "RFC 9901 s4.3.1", "kb-sd-hash",
           "sd_hash computed over a different presentation")
def _op_kb_sd_hash(s: _State) -> None:
    s.present["sd_hash_over"] = s.jwt + "~"


@_operator("kb_typ", "RFC 9901 s4.3", "kb-typ",
           "KB-JWT typ is not kb+jwt")
def _op_kb_typ(s: _State) -> None:
    s.present["typ"] = "JWT"


@_operator("kb_wrong_key", "RFC 9901 s7.3", "kb-signature",
           "KB-JWT signed by a key other than cnf.jwk")
def _op_kb_wrong_key(s: _State) -> None:
    s.present["kb_key"] = s.other_key


@_operator("issuer_alg_none", "RFC 8725 s3.2", "alg-allowlist-strict",
           "Issuer JWT with alg=none")
def _op_issuer_alg_none(s: _State) -> None:
    s.header["alg"] = "none"
    _re_sign_issuer(s, key=None)


@_operator("issuer_embedded_jwk", "RFC 8725 s3.8; CVE-2026-34240", "issuer-signature",
           "Issuer JWT verifiable only through a jwk header the attacker supplied")
def _op_issuer_embedded_jwk(s: _State) -> None:
    s.header["jwk"] = jwk_of(s.other_key)
    _re_sign_issuer(s, key=s.other_key)


@_operator("issuer_exp", "RFC 7519 s4.1.4", "issuer-expiry",
           "Credential exp is in the past")
def _op_issuer_exp(s: _State) -> None:
    s.payload["exp"] = s.ctx.now - 3600
    _re_sign_issuer(s)


@_operator("sd_alg", "RFC 9901 s4.1.1", "sd-alg-allowlist",
           "_sd_alg is a weak hash outside the allow-list (digests rebuilt with md5)")
def _op_sd_alg(s: _State) -> None:
    alg = "md5"
    s.payload["_sd"] = sorted(sd_digest(d, alg) for d in s.disclosures)
    s.payload["_sd_alg"] = alg
    _re_sign_issuer(s)


@_operator("claim_collision", "RFC 9901 s7.1", "no-claim-collision",
           "Selectively disclosable claim also present in plaintext")
def _op_claim_collision(s: _State) -> None:
    s.payload["given_name"] = "Mallory"
    _re_sign_issuer(s)


# --- operators contributed by the Court (attack research), strictness overflow
# of the reference verifier is deliberate and frozen by fixtures ----------------

@_operator("alg_downgrade_hs256", "RFC 8725 s3.2; RFC 9901 s5.1.1.1", "alg-allowlist-strict",
           "Valid ECDSA signature but the header declares alg=HS256 (algorithm confusion)")
def _op_alg_downgrade(s: _State) -> None:
    s.header["alg"] = "HS256"
    _re_sign_issuer(s)  # signature stays verifiable over the actual bytes


@_operator("kid_injection", "RFC 9901 s5.1.1.1; RFC 8725 s3.8", "kid-pinning",
           "Issuer JWT carries an attacker-chosen kid while signed by the trusted key")
def _op_kid_injection(s: _State) -> None:
    s.header["kid"] = "https://attacker.test/jwks.json#k1"
    _re_sign_issuer(s)


@_operator("disclosure_in_array", "RFC 9901 s7.1", "disclosures-match",
           "Disclosures packed into one JSON-array segment instead of individual ~-separated segments")
def _op_disclosure_in_array(s: _State) -> None:
    s.disclosures = [json.dumps(s.disclosures)]


@_operator("duplicate_sd_digest", "RFC 9901 s5.1 (digest array entries must be unique)", "sd-array-unique",
           "The same digest appears twice in the _sd array")
def _op_duplicate_sd_digest(s: _State) -> None:
    s.payload["_sd"] = s.payload["_sd"] + [s.payload["_sd"][0]]
    _re_sign_issuer(s)


@_operator("nested_disclosure_reuse", "RFC 9901 s5.2 (salt uniqueness underpins collision resistance)", "salt-uniqueness",
           "A second disclosure reuses another disclosure's salt (nested-claim reuse)")
def _op_nested_disclosure_reuse(s: _State) -> None:
    salt, _, _ = decode_disclosure(s.disclosures[0])
    nick = disclosure("nickname", "Asha R", salt)
    alg = s.payload.get("_sd_alg", "sha-256")
    s.payload["_sd"] = sorted(s.payload["_sd"] + [sd_digest(nick, alg)])
    _re_sign_issuer(s)
    s.disclosures.append(nick)


@_operator("strip_cnf_reliance", "RFC 9901 s7.3; OID4VP 1.0 s14.1 (holder binding required)", "kb-binding-not-optional",
           "cnf stripped from the payload AND no KB-JWT: binding must not become optional because cnf is absent")
def _op_strip_cnf_reliance(s: _State) -> None:
    s.payload.pop("cnf", None)
    _re_sign_issuer(s)
    s.present["kb"] = False


# --------------------------------------------------------------------------
# chain execution
# --------------------------------------------------------------------------

def available_operators() -> list[str]:
    return list(OPERATORS)


def operator_info(name: str) -> Operator:
    return OPERATORS[name]


def build_attack(
    chain: Sequence[str],
    ctx: Context,
    seed: int,
    *,
    issuer_key: ec.EllipticCurvePrivateKey | None = None,
    name: str | None = None,
    description: str | None = None,
    source: str | None = None,
) -> Case:
    """Build the presentation for one attack (or the control when chain is empty).

    Deterministic: same chain, seed and ctx -> byte-identical presentation.
    """
    keys = derive_keys(seed)
    issuer_key = issuer_key or keys[0]
    unknown = [name_ for name_ in chain if name_ not in OPERATORS]
    if unknown:
        raise ValueError(f"unknown operator(s): {', '.join(unknown)}")
    state = _State(ctx, random.Random(f"{seed}-salts"), issuer_key, keys[1], keys[2])
    _issue_baseline(state)
    for name_ in chain:
        OPERATORS[name_].apply(state)
    joined = "+".join(chain)
    return Case(
        name or (f"court-{joined}" if chain else "court-control"),
        description or (OPERATORS[chain[-1]].description if chain else "Well-formed control presentation"),
        source or (f"{OPERATORS[chain[-1]].clause} via Holder's Court operator {chain[-1]}" if chain else "RFC 9901 s7"),
        "accept" if not chain else "reject",
        _present(state),
    )


def chain_presentation(chain: Sequence[str], ctx: Context, seed: int) -> str:
    """Just the bytes, for tools that do not need a Case."""
    return build_attack(chain, ctx, seed).presentation


def iter_chains(chains: Iterable[Sequence[str]], ctx: Context, seed: int) -> list[Case]:
    return [build_attack(chain, ctx, seed) for chain in chains]

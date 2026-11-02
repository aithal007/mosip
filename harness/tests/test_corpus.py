import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from icg.sdjwt_corpus import Context, b64u, build_cases, decode_presentation

CTX = Context(nonce="n-123", audience="redirect_uri:https://v.test/direct-post", now=1_800_000_000)


def unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_parts(token):
    h, p, s = token.split(".")
    return json.loads(unb64(h)), json.loads(unb64(p)), unb64(s), f"{h}.{p}"


def pub_from_jwk(jwk):
    numbers = ec.EllipticCurvePublicNumbers(int.from_bytes(unb64(jwk["x"]), "big"), int.from_bytes(unb64(jwk["y"]), "big"), ec.SECP256R1())
    return numbers.public_key()


def check_sig(token, key):
    _, _, sig, signing_input = jwt_parts(token)
    key.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), signing_input.encode(), ec.ECDSA(hashes.SHA256()))


def by_name():
    return {c.name: c for c in build_cases(CTX)}


def test_control_is_valid_sd_jwt_with_correct_kb_binding():
    control = by_name()["control-valid"]
    assert control.expect == "accept"
    parts = decode_presentation(control.presentation)
    header, payload, _, _ = jwt_parts(parts["jwt"])
    assert header["typ"] == "dc+sd-jwt"
    digests = {b64u(hashlib.sha256(d.encode()).digest()) for d in parts["disclosures"]}
    assert digests == set(payload["_sd"])
    kb_header, kb, _, _ = jwt_parts(parts["kb_jwt"])
    assert kb_header["typ"] == "kb+jwt" and kb["nonce"] == CTX.nonce and kb["aud"] == CTX.audience
    body = control.presentation[: control.presentation.rindex("~") + 1]
    assert kb["sd_hash"] == b64u(hashlib.sha256(body.encode()).digest())
    check_sig(parts["kb_jwt"], pub_from_jwk(payload["cnf"]["jwk"]))


def test_one_control_and_all_variants_expect_rejection():
    cases = build_cases(CTX)
    assert sum(c.expect == "accept" for c in cases) == 1
    assert len({c.name for c in cases}) == len(cases)
    assert all(c.source for c in cases)


def test_each_variant_breaks_its_property():
    cases = by_name()
    tampered = decode_presentation(cases["disclosure-tampered"].presentation)
    _, payload, _, _ = jwt_parts(tampered["jwt"])
    digests = {b64u(hashlib.sha256(d.encode()).digest()) for d in tampered["disclosures"]}
    assert not digests <= set(payload["_sd"])
    assert decode_presentation(cases["kb-missing"].presentation)["kb_jwt"] is None
    assert jwt_parts(decode_presentation(cases["issuer-alg-none"].presentation)["jwt"])[0]["alg"] == "none"
    assert jwt_parts(decode_presentation(cases["kb-wrong-nonce"].presentation)["kb_jwt"])[1]["nonce"] != CTX.nonce
    assert jwt_parts(decode_presentation(cases["kb-wrong-typ"].presentation)["kb_jwt"])[0]["typ"] != "kb+jwt"
    assert jwt_parts(decode_presentation(cases["issuer-expired"].presentation)["jwt"])[1]["exp"] < CTX.now


def test_wrong_key_variant_does_not_verify_against_cnf():
    parts = decode_presentation(by_name()["kb-wrong-key"].presentation)
    _, payload, _, _ = jwt_parts(parts["jwt"])
    with pytest.raises(Exception):
        check_sig(parts["kb_jwt"], pub_from_jwk(payload["cnf"]["jwk"]))

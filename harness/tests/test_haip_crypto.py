"""Tests for HAIP cryptographic utilities."""

import json
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from icg.haip_crypto import (
    build_dpop_proof,
    build_verifier_attestation,
    decrypt_jwe_direct,
    encrypt_jwe_direct,
    generate_cert_chain,
    jwk_of_ec_public_key,
    save_cert_chain,
    sign_request_object,
)


def test_generate_cert_chain_produces_ca_signed_leaf():
    chain = generate_cert_chain(subject_cn="test-conformance", san_dns="test.example")

    # CA cert is self-signed
    ca_cert = x509.load_pem_x509_certificate(chain.ca_cert_pem.encode("ascii"))
    assert ca_cert.issuer == ca_cert.subject

    # Leaf cert is signed by CA (not self-signed)
    leaf_cert = x509.load_pem_x509_certificate(chain.leaf_cert_pem.encode("ascii"))
    assert leaf_cert.issuer != leaf_cert.subject
    assert leaf_cert.issuer == ca_cert.subject

    # Leaf has SAN
    san = leaf_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_names = [n.value for n in san.value if isinstance(n, x509.DNSName)]
    assert "test.example" in dns_names


def test_x509_hash_and_san():
    chain = generate_cert_chain(subject_cn="test", san_dns="verify.inji.test")

    x509_hash = chain.x509_hash
    assert len(x509_hash) > 0
    assert isinstance(x509_hash, str)

    san_dns = chain.x509_san_dns
    assert san_dns == "verify.inji.test"


def test_leaf_x5c_contains_only_leaf():
    chain = generate_cert_chain()
    x5c = chain.leaf_x5c
    assert len(x5c) == 1  # Only leaf cert, no CA (HAIP §5)

    # Verify x5c entry decodes to the leaf cert
    import base64
    der = base64.urlsafe_b64decode(x5c[0] + "==")
    cert = x509.load_der_x509_certificate(der)
    assert cert.subject == x509.load_pem_x509_certificate(chain.leaf_cert_pem.encode("ascii")).subject


def test_sign_request_object_es256():
    key = ec.generate_private_key(ec.SECP256R1())
    jar = sign_request_object({"typ": "JOSE"}, {"iss": "test", "aud": "test"}, key)

    parts = jar.split(".")
    assert len(parts) == 3
    header = json.loads(__import__("base64").urlsafe_b64decode(parts[0] + "=="))
    assert header["alg"] == "ES256"
    assert header["typ"] == "JOSE"


def test_sign_request_object_with_x5c():
    key = ec.generate_private_key(ec.SECP256R1())
    chain = generate_cert_chain()
    jar = sign_request_object(
        {"typ": "JOSE"}, {"iss": "test", "aud": "test"}, key, x5c=chain.leaf_x5c
    )
    parts = jar.split(".")
    header = json.loads(__import__("base64").urlsafe_b64decode(parts[0] + "=="))
    assert "x5c" in header
    assert len(header["x5c"]) == 1


def test_jwe_encrypt_decrypt_round_trip_a256gcm():
    recipient_key = ec.generate_private_key(ec.SECP256R1())
    plaintext = b'{"vp_token": "test-payload"}'

    jwe = encrypt_jwe_direct(plaintext, recipient_key.public_key(), enc="A256GCM")
    decrypted = decrypt_jwe_direct(jwe, recipient_key)

    assert decrypted == plaintext


def test_jwe_encrypt_decrypt_round_trip_a128gcm():
    recipient_key = ec.generate_private_key(ec.SECP256R1())
    plaintext = b'{"vp_token": "test-payload-128"}'

    jwe = encrypt_jwe_direct(plaintext, recipient_key.public_key(), enc="A128GCM")
    decrypted = decrypt_jwe_direct(jwe, recipient_key)

    assert decrypted == plaintext


def test_jwe_tamper_detection():
    recipient_key = ec.generate_private_key(ec.SECP256R1())
    plaintext = b'{"vp_token": "tamper-test"}'

    jwe = encrypt_jwe_direct(plaintext, recipient_key.public_key(), enc="A256GCM")
    parts = jwe.split(".")
    # Tamper with ciphertext
    parts[3] = "AAAA"
    tampered = ".".join(parts)

    with pytest.raises(Exception):
        decrypt_jwe_direct(tampered, recipient_key)


def test_jwe_wrong_key_fails():
    recipient_key = ec.generate_private_key(ec.SECP256R1())
    wrong_key = ec.generate_private_key(ec.SECP256R1())
    plaintext = b'{"vp_token": "wrong-key-test"}'

    jwe = encrypt_jwe_direct(plaintext, recipient_key.public_key(), enc="A256GCM")

    with pytest.raises(Exception):
        decrypt_jwe_direct(jwe, wrong_key)


def test_dpop_proof_structure():
    key = ec.generate_private_key(ec.SECP256R1())
    proof = build_dpop_proof("POST", "https://example.com/par", key)

    parts = proof.split(".")
    assert len(parts) == 3
    header = json.loads(__import__("base64").urlsafe_b64decode(parts[0] + "=="))
    assert header["alg"] == "ES256"
    assert header["typ"] == "dpop+jwt"

    payload = json.loads(__import__("base64").urlsafe_b64decode(parts[1] + "=="))
    assert payload["htm"] == "POST"
    assert payload["htu"] == "https://example.com/par"
    assert "jti" in payload
    assert "iat" in payload


def test_dpop_proof_with_ath():
    key = ec.generate_private_key(ec.SECP256R1())
    proof = build_dpop_proof("POST", "https://example.com/token", key, ath="abc123")

    payload = json.loads(__import__("base64").urlsafe_b64decode(proof.split(".")[1] + "=="))
    assert payload["ath"] == "abc123"


def test_verifier_attestation_structure():
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    attestation = build_verifier_attestation(
        sub="verifier.example",
        issuer_key=issuer_key,
        issuer_iss="https://attestation.example",
    )

    parts = attestation.split(".")
    assert len(parts) == 3
    payload = json.loads(__import__("base64").urlsafe_b64decode(parts[1] + "=="))
    assert payload["sub"] == "verifier.example"
    assert payload["iss"] == "https://attestation.example"
    assert "iat" in payload
    assert "exp" in payload


def test_verifier_attestation_with_redirect_uris():
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    attestation = build_verifier_attestation(
        sub="verifier.example",
        issuer_key=issuer_key,
        issuer_iss="https://attestation.example",
        redirect_uris=["https://verifier.example/callback"],
    )

    payload = json.loads(__import__("base64").urlsafe_b64decode(attestation.split(".")[1] + "=="))
    assert payload["redirect_uris"] == ["https://verifier.example/callback"]


def test_jwk_of_ec_public_key():
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = jwk_of_ec_public_key(key.public_key(), kid="test-kid")

    assert jwk["kty"] == "EC"
    assert jwk["crv"] == "P-256"
    assert jwk["kid"] == "test-kid"
    assert "x" in jwk
    assert "y" in jwk


def test_save_cert_chain(tmp_path):
    chain = generate_cert_chain(subject_cn="save-test")
    save_cert_chain(chain, tmp_path, prefix="test")

    assert (tmp_path / "test-ca.pem").exists()
    assert (tmp_path / "test-leaf.pem").exists()
    assert (tmp_path / "test-leaf-key.pem").exists()

    ca = (tmp_path / "test-ca.pem").read_text()
    leaf = (tmp_path / "test-leaf.pem").read_text()
    key = (tmp_path / "test-leaf-key.pem").read_text()

    assert "BEGIN CERTIFICATE" in ca
    assert "BEGIN CERTIFICATE" in leaf
    assert "BEGIN PRIVATE KEY" in key

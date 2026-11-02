"""HAIP cryptographic utilities for certificate-based conformance testing.

Implements the HAIP 1.0 Final security requirements:

* x509_hash / x509_san_dns client identifier prefixes — CA-signed leaf certificates
  (non-self-signed, x5c chain without trust anchor in header)
* Signed request objects (JAR) — ES256-signed JWTs delivered via request_uri
* Encrypted direct_post.jwt responses — JWE with ECDH-ES key agreement + A128GCM/A256GCM
* Client attestation — verifier attestation JWTs bound to a public key
* DPoP proofs — RFC 9449 sender-constrained access tokens

All certificate generation is deterministic (self-signed CA → leaf) for reproducible
conformance runs. Production deployments should use real CA-issued certificates.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

from .sdjwt_corpus import b64u, b64u_json, sign_jwt


def b64u_data(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def generate_ec_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def generate_rsa_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def private_key_pem(key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def public_key_pem(key: ec.EllipticCurvePublicKey | rsa.RSAPublicKey) -> str:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def jwk_of_ec_public_key(public_key: ec.EllipticCurvePublicKey, kid: str | None = None) -> dict[str, str]:
    numbers = public_key.public_numbers()
    jwk: dict[str, str] = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u_data(numbers.x.to_bytes(32, "big")),
        "y": b64u_data(numbers.y.to_bytes(32, "big")),
    }
    if kid:
        jwk["kid"] = kid
    return jwk


@dataclass
class CertChain:
    """A CA-issued certificate chain: CA cert + cert + leaf cert."""

    ca_cert_pem: str
    leaf_cert_pem: str
    leaf_private_key: ec.EllipticCurvePrivateKey
    ca_private_key: ec.EllipticCurvePrivateKey

    @property
    def leaf_x5c(self) -> list[str]:
        """x5c header entries: leaf cert only (CA cert NOT included per HAIP §5)."""
        der = self.leaf_cert_pem.encode("ascii")
        # PEM -> DER
        cert = x509.load_pem_x509_certificate(der)
        return [b64u_data(cert.public_bytes(serialization.Encoding.DER))]

    @property
    def x509_hash(self) -> str:
        """SHA-256 base64url of the DER-encoded leaf certificate (x509_hash client ID value)."""
        cert = x509.load_pem_x509_certificate(self.leaf_cert_pem.encode("ascii"))
        der = cert.public_bytes(serialization.Encoding.DER)
        return b64u_data(hashlib.sha256(der).digest())

    @property
    def x509_san_dns(self) -> str:
        """The DNS SAN from the leaf certificate (x509_san_dns client ID value).

        Returns the first non-localhost DNS SAN, or the first DNS SAN if none.
        """
        cert = x509.load_pem_x509_certificate(self.leaf_cert_pem.encode("ascii"))
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            names = [n.value for n in san.value if isinstance(n, x509.DNSName)]
            # Prefer non-localhost entries (those are the custom ones)
            for name in names:
                if name != "localhost":
                    return name
            return names[0] if names else ""
        except x509.ExtensionNotFound:
            return ""


def generate_cert_chain(
    subject_cn: str = "inji-conformance-gate",
    san_dns: str | None = None,
    valid_days: int = 365,
) -> CertChain:
    """Generate a self-signed CA + CA-signed leaf certificate chain.

    The leaf cert is signed by the CA but is NOT self-signed (HAIP requirement).
    The CA cert is NOT included in x5c (HAIP §5: trust anchor must not travel in header).
    """
    # --- CA key + cert (self-signed) ---
    ca_key = generate_ec_private_key()
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn + " CA")])
    ca_builder = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            key_cert_sign=True, crl_sign=True, digital_signature=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            content_commitment=False, encipher_only=False, decipher_only=False,
        ), critical=True)
    )
    ca_cert = ca_builder.sign(ca_key, hashes.SHA256())

    # --- Leaf key + cert (CA-signed, NOT self-signed) ---
    leaf_key = generate_ec_private_key()
    leaf_subject_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]
    san_entries = [x509.DNSName("localhost")]
    if san_dns:
        san_entries.append(x509.DNSName(san_dns))
    leaf_builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name(leaf_subject_attrs))
        .issuer_name(ca_subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=valid_days))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            key_cert_sign=False, crl_sign=False, digital_signature=True,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            content_commitment=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    )
    leaf_cert = leaf_builder.sign(ca_key, hashes.SHA256())

    return CertChain(
        ca_cert_pem=ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        leaf_cert_pem=leaf_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        leaf_private_key=leaf_key,
        ca_private_key=ca_key,
    )


def save_cert_chain(chain: CertChain, dir_path: Path, prefix: str = "haip") -> None:
    """Save CA cert, leaf cert, and leaf private key to files."""
    dir_path.mkdir(parents=True, exist_ok=True)
    (dir_path / f"{prefix}-ca.pem").write_text(chain.ca_cert_pem, encoding="utf-8")
    (dir_path / f"{prefix}-leaf.pem").write_text(chain.leaf_cert_pem, encoding="utf-8")
    (dir_path / f"{prefix}-leaf-key.pem").write_text(
        private_key_pem(chain.leaf_private_key), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Signed request object (JAR) — OID4VP §5.1, HAIP §5
# ---------------------------------------------------------------------------

def sign_request_object(
    header: dict[str, Any],
    payload: dict[str, Any],
    key: ec.EllipticCurvePrivateKey,
    x5c: list[str] | None = None,
) -> str:
    """Sign a request object JWT with ES256 and optional x5c header.

    HAIP requires ES256 for request object signing (alg=none is rejected).
    x5c carries the leaf cert chain only (CA trust anchor excluded).
    """
    hdr = dict(header)
    hdr["alg"] = "ES256"
    hdr["typ"] = "JOSE"
    if x5c:
        hdr["x5c"] = x5c
    return sign_jwt(hdr, payload, key)


# ---------------------------------------------------------------------------
# Encrypted response (JWE) — OID4VP §8.3, HAIP §8.3
#
# JWE compact serialization: A128GCM/A256GCM content encryption with ECDH-ES
# key agreement (direct mode: empty encrypted key, epk in header).
# ---------------------------------------------------------------------------

def encrypt_jwe_direct(
    plaintext: bytes,
    recipient_public_key: ec.EllipticCurvePublicKey,
    enc: str = "A256GCM",
    kid: str | None = None,
    aad: bytes = b"",
) -> str:
    """Encrypt plaintext as a JWE using ECDH-ES direct key agreement.

    Produces a 5-part compact JWE: header.encrypted_key.iv.ciphertext.tag
    where encrypted_key is empty (direct mode).
    """
    if enc not in ("A128GCM", "A256GCM"):
        raise ValueError(f"unsupported content encryption: {enc}")

    # Ephemeral key for ECDH
    epk = generate_ec_private_key()

    # ECDH-ES shared secret
    shared_secret = epk.exchange(ec.ECDH(), recipient_public_key)

    # Derive CEK using HKDF (concat KDF per RFC 7518 §5.1)
    key_len = 16 if enc == "A128GCM" else 32
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=key_len,
        salt=None,
        info=b"AES-GCM",
    )
    cek = kdf.derive(shared_secret)

    iv = secrets.token_bytes(12 if enc == "A128GCM" else 16)  # 96-bit IV for GCM
    aesgcm = AESGCM(cek)
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, aad)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    header: dict[str, Any] = {
        "alg": "ECDH-ES",
        "enc": enc,
        "epk": jwk_of_ec_public_key(epk.public_key()),
    }
    if kid:
        header["kid"] = kid

    parts = [
        b64u_data(json.dumps(header, separators=(",", ":")).encode()),
        "",  # encrypted key empty in direct mode
        b64u_data(iv),
        b64u_data(ciphertext),
        b64u_data(tag),
    ]
    return ".".join(parts)


def decrypt_jwe_direct(
    jwe: str,
    recipient_private_key: ec.EllipticCurvePrivateKey,
) -> bytes:
    """Decrypt a JWE encrypted with encrypt_jwe_direct."""
    parts = jwe.split(".")
    if len(parts) != 5:
        raise ValueError("JWE must have 5 compact serialization parts")

    header_b64, _ek_b64, iv_b64, ct_b64, tag_b64 = parts
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
    if header.get("alg") != "ECDH-ES":
        raise ValueError(f"unsupported JWE alg: {header.get('alg')}")

    epk_jwk = header["epk"]
    epk_public = ec.EllipticCurvePublicNumbers(
        int.from_bytes(base64.urlsafe_b64decode(epk_jwk["x"] + "=="), "big"),
        int.from_bytes(base64.urlsafe_b64decode(epk_jwk["y"] + "=="), "big"),
        ec.SECP256R1(),
    ).public_key()

    shared_secret = recipient_private_key.exchange(ec.ECDH(), epk_public)

    key_len = 16 if header.get("enc") == "A128GCM" else 32
    kdf = HKDF(algorithm=hashes.SHA256(), length=key_len, salt=None, info=b"AES-GCM")
    cek = kdf.derive(shared_secret)

    iv = base64.urlsafe_b64decode(iv_b64 + "=" * (-len(iv_b64) % 4))
    ciphertext = base64.urlsafe_b64decode(ct_b64 + "=" * (-len(ct_b64) % 4))
    tag = base64.urlsafe_b64decode(tag_b64 + "=" * (-len(tag_b64) % 4))

    aesgcm = AESGCM(cek)
    return aesgcm.decrypt(iv, ciphertext + tag, b"")


# ---------------------------------------------------------------------------
# Client attestation — HAIP §12
# ---------------------------------------------------------------------------

def build_verifier_attestation(
    sub: str,
    issuer_key: ec.EllipticCurvePrivateKey,
    issuer_iss: str,
    now: float | None = None,
    redirect_uris: list[str] | None = None,
) -> str:
    """Build a verifier attestation JWT (HAIP §12).

    The verifier attests to a public key (cnf.jwk) and its sub matches the
    original client identifier (without the verifier_attestation: prefix).
    """
    now = now or time.time()
    claims = {
        "iss": issuer_iss,
        "sub": sub,
        "iat": int(now),
        "exp": int(now + 3600),
    }
    if redirect_uris:
        claims["redirect_uris"] = redirect_uris
    return sign_jwt({"alg": "ES256", "typ": "kb+jwt"}, claims, issuer_key)


def build_dpop_proof(
    htm: str,
    htu: str,
    key: ec.EllipticCurvePrivateKey,
    ath: str | None = None,
    nonce: str | None = None,
    now: float | None = None,
) -> str:
    """Build a DPoP proof JWT (RFC 9449 §4.2).

    htm = HTTP method, htu = target URI (without query/fragment),
    ath = access token hash (optional), nonce = DPoP-Nonce challenge (optional).
    """
    now = now or time.time()
    claims = {
        "jti": b64u_data(secrets.token_bytes(16)),
        "iat": int(now),
        "exp": int(now + 3600),
        "htm": htm.upper(),
        "htu": htu,
    }
    if ath:
        claims["ath"] = ath
    if nonce:
        claims["nonce"] = nonce
    return sign_jwt(
        {"alg": "ES256", "typ": "dpop+jwt"},
        claims,
        key,
    )

"""Cryptographic ES256 verification for STIR/SHAKEN PASSporT tokens.

This module authenticates the JWS signature against a supplied X.509 leaf
certificate. It does NOT establish certificate-chain trust or authorisation;
those checks are mandatory before CYVORA accepts the caller assertion.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .exceptions import CertificateValidationError, PassportSignatureError
from .passport import ParsedPassport


@dataclass(frozen=True)
class SignatureVerificationResult:
    signature_valid: bool
    claims: dict[str, Any]
    certificate_fingerprint_sha256: str


def verify_passport_signature(
    passport: ParsedPassport,
    certificate_pem: bytes | str,
) -> SignatureVerificationResult:
    """Verify a PASSporT JWS signature using its candidate leaf certificate.

    The caller must obtain the certificate through a separately secured
    resolver and validate its chain, validity, TN authorization and trust
    policy before treating this result as an accepted caller identity.
    """
    try:
        cert_bytes = certificate_pem.encode("utf-8") if isinstance(certificate_pem, str) else certificate_pem
        certificate = x509.load_pem_x509_certificate(cert_bytes)
        public_key = certificate.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise CertificateValidationError("PASSporT certificate must contain an EC public key.")
        if not isinstance(public_key.curve, ec.SECP256R1):
            raise CertificateValidationError("PASSporT ES256 requires the P-256 elliptic curve.")
    except CertificateValidationError:
        raise
    except (ValueError, TypeError) as exc:
        raise CertificateValidationError("Could not load the PASSporT signing certificate.") from exc

    try:
        verified_claims = jwt.decode(
            passport.compact,
            key=public_key,
            algorithms=["ES256"],
            options={
                "verify_aud": False,
                "require": ["iat", "orig", "dest"],
            },
        )
    except jwt.PyJWTError as exc:
        raise PassportSignatureError("PASSporT ES256 signature or registered claims are invalid.") from exc

    if verified_claims.get("orig") != passport.claims.get("orig") or verified_claims.get("dest") != passport.claims.get("dest"):
        raise PassportSignatureError("Verified PASSporT claims do not match the parsed assertion.")

    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    return SignatureVerificationResult(
        signature_valid=True,
        claims=verified_claims,
        certificate_fingerprint_sha256=fingerprint,
    )

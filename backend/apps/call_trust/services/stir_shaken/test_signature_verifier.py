
"""Unit tests for STIR/SHAKEN ES256 signature verification."""

import unittest
from datetime import datetime, timedelta, timezone

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .exceptions import CertificateValidationError, PassportSignatureError
from .passport import parse_passport
from .signature_verifier import verify_passport_signature


def _make_certificate(private_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "CYVORA Local Test Certificate")
    ])

    now = datetime.now(timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )

    return certificate.public_bytes(serialization.Encoding.PEM)


def _make_passport(private_key):
    header = {
        "typ": "passport",
        "alg": "ES256",
        "ppt": "shaken",
        "x5u": "https://cert.example.test/leaf.pem",
    }

    claims = {
        "iat": 1795800000,
        "orig": {"tn": "+26876123456"},
        "dest": {"tn": "+26825186000"},
    }

    token = jwt.encode(claims, private_key, algorithm="ES256", headers=header)
    return parse_passport(token)


class SignatureVerifierTests(unittest.TestCase):
    def setUp(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.certificate_pem = _make_certificate(self.private_key)
        self.passport = _make_passport(self.private_key)

    def test_accepts_valid_es256_signature(self):
        result = verify_passport_signature(
            self.passport,
            self.certificate_pem,
        )

        self.assertTrue(result.signature_valid)
        self.assertEqual(
            result.claims["orig"]["tn"],
            "+26876123456",
        )
        self.assertEqual(
            len(result.certificate_fingerprint_sha256),
            64,
        )

    def test_rejects_signature_signed_by_wrong_key(self):
        wrong_key = ec.generate_private_key(ec.SECP256R1())
        wrong_certificate = _make_certificate(wrong_key)

        with self.assertRaises(PassportSignatureError):
            verify_passport_signature(
                self.passport,
                wrong_certificate,
            )

    def test_rejects_malformed_certificate(self):
        with self.assertRaises(CertificateValidationError):
            verify_passport_signature(
                self.passport,
                b"not a valid certificate",
            )

    def test_rejects_non_ec_certificate(self):
        from cryptography.hazmat.primitives.asymmetric import rsa

        rsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        certificate_pem = _make_certificate(rsa_key)

        with self.assertRaises(CertificateValidationError):
            verify_passport_signature(
                self.passport,
                certificate_pem,
            )


if __name__ == "__main__":
    unittest.main()

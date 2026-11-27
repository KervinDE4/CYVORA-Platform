"""Unit tests for strict PASSporT structural parsing."""

import base64
import json
import unittest

from .exceptions import PassportClaimError, PassportFormatError
from .passport import parse_passport


def _segment(value):
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _token(header=None, claims=None):
    header = header or {"typ": "passport", "alg": "ES256", "x5u": "https://cert.example.test/leaf.pem"}
    claims = claims or {
        "iat": 1795800000,
        "orig": {"tn": "+26876123456"},
        "dest": {"tn": "+26825186000"},
    }
    return f"{_segment(header)}.{_segment(claims)}.ZmFrZXNpZw"


class PassportParserTests(unittest.TestCase):
    def test_parses_valid_structure_without_claiming_authenticity(self):
        parsed = parse_passport(_token())
        self.assertEqual(parsed.origin_number, "+26876123456")
        self.assertEqual(parsed.destination_numbers, ("+26825186000",))
        self.assertEqual(parsed.header["alg"], "ES256")

    def test_rejects_non_es256_algorithm(self):
        with self.assertRaises(PassportFormatError):
            parse_passport(_token(header={"typ": "passport", "alg": "none", "x5u": "https://cert.example.test/leaf.pem"}))

    def test_rejects_malformed_compact_token(self):
        with self.assertRaises(PassportFormatError):
            parse_passport("not.a.valid.token")

    def test_rejects_non_e164_origin(self):
        claims = {"iat": 1795800000, "orig": {"tn": "076123456"}, "dest": {"tn": "+26825186000"}}
        with self.assertRaises(PassportClaimError):
            parse_passport(_token(claims=claims))

    def test_rejects_missing_certificate_url(self):
        with self.assertRaises(PassportFormatError):
            parse_passport(_token(header={"typ": "passport", "alg": "ES256"}))


if __name__ == "__main__":
    unittest.main()

"""Strict structural parsing for compact STIR/SHAKEN PASSporT JWTs.

Parsing is deliberately separate from signature verification. A parsed token is
UNTRUSTED until signature and certificate validation have both succeeded.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Any

from .exceptions import PassportClaimError, PassportFormatError

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_E164_RE = re.compile(r"^\+[1-9][0-9]{1,14}$")
_MAX_TOKEN_LENGTH = 16_384


@dataclass(frozen=True)
class ParsedPassport:
    """Unverified PASSporT fields. Never treat these as authenticated identity."""

    compact: str
    header: dict[str, Any]
    claims: dict[str, Any]
    signing_certificate_url: str
    issued_at: int
    origin_number: str
    destination_numbers: tuple[str, ...]


def _decode_segment(segment: str, label: str) -> dict[str, Any]:
    if not segment or not _BASE64URL_RE.fullmatch(segment):
        raise PassportFormatError(f"Invalid {label} base64url segment.")
    padded = segment + ("=" * (-len(segment) % 4))
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        value = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PassportFormatError(f"Could not decode PASSporT {label}.") from exc
    if not isinstance(value, dict):
        raise PassportFormatError(f"PASSporT {label} must be a JSON object.")
    return value


def _telephone_number(value: Any, claim_name: str) -> str:
    if not isinstance(value, str) or not _E164_RE.fullmatch(value):
        raise PassportClaimError(f"PASSporT {claim_name} must contain an E.164 telephone number.")
    return value


def parse_passport(compact_token: str) -> ParsedPassport:
    """Parse and validate PASSporT structure without asserting authenticity.

    Cryptographic signature verification and certificate trust validation must
    be performed separately before the identity assertion is accepted.
    """
    if not isinstance(compact_token, str) or not compact_token:
        raise PassportFormatError("A compact PASSporT token is required.")
    if len(compact_token) > _MAX_TOKEN_LENGTH:
        raise PassportFormatError("PASSporT token exceeds the maximum accepted size.")

    parts = compact_token.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise PassportFormatError("PASSporT must contain exactly three non-empty JWS segments.")

    header = _decode_segment(parts[0], "header")
    claims = _decode_segment(parts[1], "claims")

    if header.get("typ", "").lower() != "passport":
        raise PassportFormatError("JWT typ must be 'passport'.")
    if header.get("alg") != "ES256":
        raise PassportFormatError("Only ES256 PASSporT signatures are accepted.")
    if header.get("crit"):
        raise PassportFormatError("Critical JOSE header extensions are not supported.")

    if header.get("ppt") != "shaken":
        raise PassportFormatError("PASSporT header ppt must be 'shaken'.")

    certificate_url = header.get("x5u")
    if not isinstance(certificate_url, str) or not certificate_url:
        raise PassportFormatError("PASSporT header is missing its x5u certificate URL.")

    issued_at = claims.get("iat")
    if isinstance(issued_at, bool) or not isinstance(issued_at, int) or issued_at <= 0:
        raise PassportClaimError("PASSporT iat must be a positive integer Unix timestamp.")

    origin = claims.get("orig")
    destination = claims.get("dest")
    if not isinstance(origin, dict) or not isinstance(destination, dict):
        raise PassportClaimError("PASSporT must contain orig and dest objects.")

    origin_number = _telephone_number(origin.get("tn"), "orig.tn")
    destination_value = destination.get("tn")
    if isinstance(destination_value, str):
        destination_values = [destination_value]
    elif isinstance(destination_value, list) and destination_value:
        destination_values = destination_value
    else:
        raise PassportClaimError("PASSporT dest.tn must be a telephone number or a non-empty list.")

    destination_numbers = tuple(
        _telephone_number(number, "dest.tn") for number in destination_values
    )

    return ParsedPassport(
        compact=compact_token,
        header=header,
        claims=claims,
        signing_certificate_url=certificate_url,
        issued_at=issued_at,
        origin_number=origin_number,
        destination_numbers=destination_numbers,
    )

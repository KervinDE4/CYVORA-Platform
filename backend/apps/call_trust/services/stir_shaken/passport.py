"""Structural parsing for STIR/SHAKEN PASSporT compact JWTs.

Parsing does not authenticate a caller. Signature verification and trusted
certificate-chain validation are required before any identity assertion is
considered cryptographically verified.
"""
import base64
import json
import re
from dataclasses import dataclass
from typing import Any

class PassportError(ValueError):
    """A PASSporT token is malformed or contains invalid required claims."""

@dataclass(frozen=True)
class ParsedPassport:
    header: dict[str, Any]
    claims: dict[str, Any]
    issued_at: int
    origin_number: str
    destination_numbers: tuple[str, ...]

def _decode_segment(segment: str) -> dict:
    if not segment or not re.fullmatch(r"[A-Za-z0-9_-]+", segment):
        raise PassportError("Invalid PASSporT base64url segment.")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        value = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PassportError("Could not decode PASSporT JSON.") from exc
    if not isinstance(value, dict):
        raise PassportError("PASSporT header and claims must be JSON objects.")
    return value

def _e164(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"\\+[1-9][0-9]{1,14}", value):
        raise PassportError(f"PASSporT {label} must be an E.164 telephone number.")
    return value

def parse_passport(token: str) -> ParsedPassport:
    if not isinstance(token, str) or not token or len(token) > 16384:
        raise PassportError("A PASSporT token is required and must be at most 16 KB.")
    parts = token.split(".")
    if len(parts) != 3:
        raise PassportError("PASSporT must contain three JWS segments.")
    header, claims = _decode_segment(parts[0]), _decode_segment(parts[1])
    if str(header.get("typ", "")).lower() != "passport" or header.get("alg") != "ES256" or header.get("ppt") != "shaken":
        raise PassportError("Unsupported PASSporT type, algorithm or ppt claim.")
    if header.get("crit"):
        raise PassportError("Unsupported critical JOSE header extension.")
    issued_at = claims.get("iat")
    if isinstance(issued_at, bool) or not isinstance(issued_at, int) or issued_at <= 0:
        raise PassportError("PASSporT iat must be a positive Unix timestamp.")
    origin, destination = claims.get("orig"), claims.get("dest")
    if not isinstance(origin, dict) or not isinstance(destination, dict):
        raise PassportError("PASSporT must contain orig and dest objects.")
    origin_number = _e164(origin.get("tn"), "orig.tn")
    raw_destinations = destination.get("tn")
    if isinstance(raw_destinations, str):
        raw_destinations = [raw_destinations]
    if not isinstance(raw_destinations, list) or not raw_destinations:
        raise PassportError("PASSporT dest.tn must be a number or non-empty list.")
    destinations = tuple(_e164(item, "dest.tn") for item in raw_destinations)
    return ParsedPassport(header, claims, issued_at, origin_number, destinations)

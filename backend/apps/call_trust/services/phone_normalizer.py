import re

COUNTRY_PREFIX_MAP = {
    "+268": ("SZ", "Eswatini (+268)", 8),
    "+27": ("ZA", "South Africa (+27)", 9),
    "+267": ("BW", "Botswana (+267)", 7, 8),
    "+266": ("LS", "Lesotho (+266)", 8),
    "+264": ("NA", "Namibia (+264)", 7, 9),
    "+258": ("MZ", "Mozambique (+258)", 9),
}


def normalize_phone_number(raw_phone: str, default_region: str = "SZ") -> dict:
    raw = (raw_phone or "").strip()
    format_flags = []

    if not raw:
        return {
            "raw": raw,
            "normalized": "",
            "is_valid_format": False,
            "country_label": "Unknown",
            "format_flags": [
                {
                    "id": "empty_phone",
                    "title": "Missing Phone Number",
                    "severity": "high",
                    "detail": "No phone number was provided for verification.",
                }
            ],
        }

    # Preserve leading '+' if present, strip spaces, hyphens, and parentheses
    has_plus = raw.startswith("+")
    digits_only = re.sub(r"\D", "", raw)

    if has_plus:
        normalized = f"+{digits_only}"
    elif digits_only.startswith("00") and len(digits_only) > 4:
        normalized = f"+{digits_only[2:]}"
    elif default_region == "SZ" and len(digits_only) == 8 and digits_only[0] in {"2", "7"}:
        # Local 8-digit Eswatini subscriber number (e.g., 76001234 -> +26876001234)
        normalized = f"+268{digits_only}"
    elif default_region == "ZA" and digits_only.startswith("0") and len(digits_only) == 10:
        # Local 10-digit South African number (e.g., 0821234567 -> +27821234567)
        normalized = f"+27{digits_only[1:]}"
    elif digits_only:
        normalized = f"+{digits_only}"
        format_flags.append({
            "id": "missing_country_code",
            "title": "No Country Code Prefix Detected",
            "severity": "low",
            "detail": f"Normalized '{raw}' to '{normalized}' using default assumptions; confirm international prefix.",
        })
    else:
        normalized = ""

    country_label = "International / Unmapped"
    valid_length = 7 <= len(digits_only) <= 15

    for prefix, meta in COUNTRY_PREFIX_MAP.items():
        if normalized.startswith(prefix):
            country_label = meta[1]
            sub_len = len(normalized) - len(prefix)
            allowed_lengths = set(meta[2:])
            if sub_len not in allowed_lengths:
                valid_length = False
                format_flags.append({
                    "id": "unusual_subscriber_length",
                    "title": f"Unusual Number Length for {country_label}",
                    "severity": "medium",
                    "detail": f"Number '{normalized}' has {sub_len} subscriber digits outside standard length for {country_label}.",
                })
            break

    if not digits_only or not valid_length:
        format_flags.append({
            "id": "invalid_phone_length",
            "title": "Invalid or Non-Standard Phone Length",
            "severity": "high",
            "detail": f"Phone '{raw}' does not match standard E.164 digit length.",
        })

    # Detect repetitive / spoof-looking digit sequences (e.g., 77777777 or 1234567)
    if len(digits_only) >= 6 and re.search(r"(\d)\1{5,}", digits_only):
        format_flags.append({
            "id": "repeated_digits",
            "title": "Repetitive Digit Pattern Detected",
            "severity": "medium",
            "detail": f"Number '{normalized}' contains repeated digits common in synthetic or spoofed caller IDs.",
        })

    is_valid_format = bool(digits_only) and valid_length

    return {
        "raw": raw,
        "normalized": normalized,
        "is_valid_format": is_valid_format,
        "country_label": country_label,
        "format_flags": format_flags,
    }
from difflib import SequenceMatcher
from urllib.parse import urlparse
import re


PROTECTED_BRANDS = {
    "fnb": ["fnbeswatiland.co.sz", "fnb.co.za"],
    "standardbank": ["standardbank.co.sz", "standardbank.co.za"],
    "nedbank": ["nedbank.co.sz", "nedbank.co.za"],
    "mtn": ["mtn.co.sz", "mtnmomo.co.sz"],
    "ers": ["ers.org.sz"],
    "eswatini": ["gov.sz"],
    "microsoft": ["microsoft.com", "login.microsoftonline.com"],
    "google": ["google.com", "accounts.google.com"],
}

HIGH_RISK_LURE_TOKENS = [
    "login", "verify", "update", "security", "account", "wallet", "pin",
    "otp", "banking", "portal", "confirm", "unlock", "suspend", "claim", "bonus"
]

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".click", ".zip", ".rest"}


def _domain_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def analyze_url(raw_url: str) -> dict:
    target = (raw_url or "").strip()
    if not target.startswith(("http://", "https://")):
        target_for_parse = f"http://{target}"
    else:
        target_for_parse = target

    parsed = urlparse(target_for_parse)
    host = (parsed.hostname or "").lower().strip(".")
    path_and_query = f"{parsed.path or ''}?{parsed.query or ''}".lower()

    score = 0
    indicators = []
    mitre_techniques = []

    if not host or "." not in host:
        return {
            "normalized_url": target,
            "host": host,
            "score": 65,
            "indicators": [
                {
                    "id": "malformed_host",
                    "title": "Malformed or Non-Standard Target Host",
                    "severity": "high",
                    "detail": f"Target '{raw_url}' does not resolve to a standard domain name.",
                }
            ],
            "mitre_techniques": ["T1566.002"],
        }

    # 1. Raw IP address instead of domain
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        score += 35
        indicators.append({
            "id": "ip_literal_url",
            "title": "Direct IP Address Used Instead of Domain",
            "severity": "high",
            "detail": f"Host '{host}' uses a raw IPv4 address, common in phishing infrastructure and direct droppers.",
        })
        mitre_techniques.append("T1566.002")

    # 2. Punycode / IDN homograph check
    if "xn--" in host:
        score += 35
        indicators.append({
            "id": "punycode_homograph",
            "title": "Internationalized Domain (Punycode) Detected",
            "severity": "critical",
            "detail": f"Host '{host}' contains 'xn--', which can disguise lookalike characters from non-Latin scripts.",
        })
        mitre_techniques.append("T1566.002")

    # 3. Unencrypted HTTP on login/credential-like paths
    if parsed.scheme == "http" and any(tok in path_and_query for tok in ("login", "signin", "auth", "pin", "otp", "pay")):
        score += 20
        indicators.append({
            "id": "cleartext_sensitive_path",
            "title": "Unencrypted HTTP on Credential/Auth Path",
            "severity": "high",
            "detail": "Sensitive authentication or payment path is served over plain HTTP rather than HTTPS.",
        })

    # 4. High-risk TLD check
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score += 20
            indicators.append({
                "id": "high_risk_tld",
                "title": f"High-Abuse Top-Level Domain ({tld})",
                "severity": "medium",
                "detail": f"Domain '{host}' uses '{tld}', frequently abused in short-lived phishing campaigns.",
            })
            break

    # 5. Brand impersonation & combosquatting / typosquatting
    host_compact = re.sub(r"[^a-z0-9]", "", host.split(".")[0] if "." in host else host)
    for brand, official_domains in PROTECTED_BRANDS.items():
        brand_in_host = brand in host
        is_official = any(host == dom or host.endswith(f".{dom}") for dom in official_domains)

        if brand_in_host and not is_official:
            hyphen_count = host.count("-")
            score += 45 if hyphen_count >= 2 else 35
            indicators.append({
                "id": "brand_combosquatting",
                "title": f"Brand Impersonation & Combosquatting ({brand.upper()})",
                "severity": "critical",
                "detail": (
                    f"Target host '{host}' references '{brand.upper()}' outside official domains "
                    f"({', '.join(official_domains)})."
                ),
            })
            mitre_techniques.extend(["T1566.002", "T1598"])
            break

        # Near-typosquatting on root label
        root_label = host.split(".")[0]
        sim = _domain_similarity(root_label, brand)
        if not is_official and sim >= 0.72 and len(root_label) <= len(brand) + 4:
            score += 30
            indicators.append({
                "id": "typosquatting_similarity",
                "title": f"Lookalike / Typosquatting Domain ({brand.upper()})",
                "severity": "high",
                "detail": f"Domain label '{root_label}' closely resembles '{brand}' (similarity: {sim:.0%}).",
            })
            mitre_techniques.append("T1566.002")
            break

    # 6. Phishing lure keywords in URL path/query/subdomain
    matched_lures = [tok for tok in HIGH_RISK_LURE_TOKENS if tok in f"{host}{path_and_query}"]
    if len(matched_lures) >= 2:
        score += 20
        indicators.append({
            "id": "lure_keywords",
            "title": "Social Engineering Lure Keywords in URL",
            "severity": "medium",
            "detail": f"URL contains high-frequency credential/urgency terms: {', '.join(matched_lures[:5])}.",
        })

    # 7. Excessive subdomains or deep obfuscation
    if host.count(".") >= 4 or len(target) > 110:
        score += 15
        indicators.append({
            "id": "url_obfuscation",
            "title": "Complex Subdomain Chain or Oversized URL",
            "severity": "low",
            "detail": "Deeply nested subdomains or unusually long URLs are often used to hide final destinations.",
        })

    return {
        "normalized_url": target,
        "host": host,
        "score": min(score, 100),
        "indicators": indicators,
        "mitre_techniques": sorted(set(mitre_techniques)),
    }
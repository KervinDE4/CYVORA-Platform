# backend/apps/threat_scan/services/regional_intel.py
import re

SOUTHERN_AFRICA_PACKS = {
    "SZ": {
        "country": "Eswatini",
        "dial_prefix": "+268",
        "tlds": [".co.sz", ".org.sz", ".gov.sz", ".sz"],
        "entities": {
            "mtn momo": {"official": ["mtn.co.sz", "mtnmomo.co.sz"], "category": "Mobile Money Fraud", "keywords": ["momo", "mobile money", "emalangeni", "szl", "cashout", "voucher"]},
            "fnb eswatini": {"official": ["fnbeswatiland.co.sz", "fnb.co.za"], "category": "Banking Phishing", "keywords": ["fnb", "ewallet", "incontact", "swaziland", "eswatini"]},
            "standard bank": {"official": ["standardbank.co.sz", "standardbank.co.za"], "category": "Banking Phishing", "keywords": ["standard bank", "stanbic", "instant money"]},
            "nedbank": {"official": ["nedbank.co.sz", "nedbank.co.za"], "category": "Banking Phishing", "keywords": ["nedbank", "send-imali"]},
            "ers": {"official": ["ers.org.sz"], "category": "Government / Tax Impersonation", "keywords": ["ers", "revenue service", "tax refund", "customs"]},
            "eec": {"official": ["eec.co.sz"], "category": "Utility Scam", "keywords": ["eec", "eswatini electricity", "prepaid meter", "power disconnect"]},
            "ewsc": {"official": ["ewsc.co.sz"], "category": "Utility Scam", "keywords": ["ewsc", "water services", "water bill"]},
        },
    },
    "ZA": {
        "country": "South Africa",
        "dial_prefix": "+27",
        "tlds": [".co.za", ".gov.za", ".org.za", ".za"],
        "entities": {
            "capitec": {"official": ["capitecbank.co.za"], "category": "Banking Phishing", "keywords": ["capitec", "global one", "remote pin"]},
            "fnb": {"official": ["fnb.co.za"], "category": "Banking Phishing", "keywords": ["fnb", "ewallet", "ebucks"]},
            "standard bank": {"official": ["standardbank.co.za"], "category": "Banking Phishing", "keywords": ["standard bank", "instant money"]},
            "nedbank": {"official": ["nedbank.co.za"], "category": "Banking Phishing", "keywords": ["nedbank", "send-imali"]},
            "sars": {"official": ["sars.gov.za"], "category": "Tax Impersonation", "keywords": ["sars", "efiling", "tax refund", "itr12"]},
            "takealot": {"official": ["takealot.com"], "category": "E-Commerce Delivery Scam", "keywords": ["takealot", "parcel", "courier fee", "delivery failed"]},
            "eskom": {"official": ["eskom.co.za"], "category": "Utility Scam", "keywords": ["eskom", "load shedding", "meter token", "electricity arrears"]},
        },
    },
    "BW": {
        "country": "Botswana",
        "dial_prefix": "+267",
        "tlds": [".co.bw", ".gov.bw", ".bw"],
        "entities": {
            "orange money": {"official": ["orange.co.bw"], "category": "Mobile Money Fraud", "keywords": ["orange money", "pula", "bwp"]},
            "fnb botswana": {"official": ["fnbbotswana.co.bw"], "category": "Banking Phishing", "keywords": ["fnb botswana", "ewallet"]},
            "bpc": {"official": ["bpc.bw"], "category": "Utility Scam", "keywords": ["bpc", "botswana power"]},
        },
    },
    "LS": {
        "country": "Lesotho",
        "dial_prefix": "+266",
        "tlds": [".co.ls", ".gov.ls", ".ls"],
        "entities": {
            "mpesa lesotho": {"official": ["vodacom.co.ls"], "category": "Mobile Money Fraud", "keywords": ["m-pesa", "mpesa", "maloti", "lsl"]},
            "standard lesotho bank": {"official": ["standardlesothobank.co.ls"], "category": "Banking Phishing", "keywords": ["standard lesotho", "lesotho bank"]},
            "lec": {"official": ["lec.co.ls"], "category": "Utility Scam", "keywords": ["lec", "lesotho electricity"]},
        },
    },
    "NA": {
        "country": "Namibia",
        "dial_prefix": "+264",
        "tlds": [".com.na", ".gov.na", ".na"],
        "entities": {
            "fnb namibia": {"official": ["fnbnamibia.com.na"], "category": "Banking Phishing", "keywords": ["fnb namibia", "ewallet"]},
            "bank windhoek": {"official": ["bankwindhoek.com.na"], "category": "Banking Phishing", "keywords": ["bank windhoek", "easywallet"]},
            "nampower": {"official": ["nampower.com.na"], "category": "Utility Scam", "keywords": ["nampower", "namibia power"]},
        },
    },
    "MZ": {
        "country": "Mozambique",
        "dial_prefix": "+258",
        "tlds": [".co.mz", ".gov.mz", ".mz"],
        "entities": {
            "mpesa mozambique": {"official": ["vm.co.mz"], "category": "Mobile Money Fraud", "keywords": ["m-pesa", "mpesa", "metical", "mzn"]},
            "millennium bim": {"official": ["millenniumbim.co.mz"], "category": "Banking Phishing", "keywords": ["millennium bim", "bim"]},
            "edm": {"official": ["edm.co.mz"], "category": "Utility Scam", "keywords": ["edm", "electricidade de mocambique", "credelec"]},
        },
    },
}


def analyze_regional_scam_context(raw_input: str, host: str = "") -> dict:
    text = f"{raw_input} {host}".lower()
    host_lower = (host or "").lower()

    matched_regions = []
    matched_brands = []
    categories = []
    score_boost = 0
    confidence_boost = 0
    indicators = []

    for code, pack in SOUTHERN_AFRICA_PACKS.items():
        region_hit = False
        if pack["dial_prefix"] in text or any(host_lower.endswith(tld) for tld in pack["tlds"]):
            region_hit = True

        for brand_name, meta in pack["entities"].items():
            if any(kw in text for kw in meta["keywords"]):
                region_hit = True
                is_official_domain = host_lower and any(
                    host_lower == dom or host_lower.endswith(f".{dom}") for dom in meta["official"]
                )
                if not is_official_domain:
                    # A brand mention alone is weak contextual evidence. Do not
                    # raise the risk score or label it critical without a suspicious
                    # destination, credential request, payment lure, or corroboration.
                    matched_brands.append(brand_name.upper())
                    categories.append(meta["category"])
                    indicators.append({
                        "id": f"regional_brand_mention_{code.lower()}",
                        "title": f"Brand reference detected: {brand_name.upper()} ({pack['country']})",
                        "severity": "low",
                        "detail": (
                            f"The content mentions {brand_name.upper()} ({pack['country']}), but this "
                            "mention alone does not establish impersonation. Verify the sender and any "
                            "linked domain independently."
                        ),
                    })

        if region_hit and pack["country"] not in matched_regions:
            matched_regions.append(pack["country"])

    if re.search(r"\b(wrong\s*transfer|reversed\s*by\s*mistake|send\s*back\s*momo|ewallet\s*pin|voucher\s*pin)\b", text):
        score_boost += 15
        confidence_boost += 10
        categories.append("Mobile Money Reversal / Voucher Scam")
        indicators.append({
            "id": "regional_momo_reversal",
            "title": "Regional Mobile Money / eWallet Reversal Lure",
            "severity": "high",
            "detail": "Matches a high-frequency Southern African MoMo/eWallet reversal or voucher-PIN social engineering script.",
        })

    return {
        "regions": matched_regions,
        "targeted_brands": sorted(set(matched_brands)),
        "primary_category": categories[0] if categories else None,
        "score_boost": min(score_boost, 30),
        "confidence_boost": min(confidence_boost, 20),
        "indicators": indicators,
    }
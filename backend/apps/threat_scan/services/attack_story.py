# backend/apps/threat_scan/services/attack_story.py


def reconstruct_attack_story(scan_type: str, verdict: str, threat_dna: dict, regional_intel: dict) -> list[dict]:
    brands = regional_intel.get("targeted_brands") or []
    brand_label = brands[0] if brands else "a trusted institution"

    if verdict == "safe":
        return [
            {"step": 1, "title": "Payload Submitted", "detail": f"User submitted {scan_type} content for inspection."},
            {"step": 2, "title": "Heuristic Checks Passed", "detail": "No active brand spoofing or credential-lure signatures matched."},
            {"step": 3, "title": "Contextual Verification", "detail": "User confirms sender identity through an official channel before sharing data."},
        ]

    if scan_type == "call":
        return [
            {"step": 1, "title": "Spoofed Caller Initiates Contact", "detail": f"Caller claims to represent {brand_label} fraud desk or mobile money support."},
            {"step": 2, "title": "Manufactured Panic", "detail": "Attacker claims an unauthorized transaction or account freeze is underway."},
            {"step": 3, "title": "OTP / PIN Elicitation", "detail": "Victim is pressured to read out a one-time PIN or approve a USSD prompt."},
            {"step": 4, "title": "Session Hijack", "detail": "Attacker links victim's banking or MoMo profile to a rogue device."},
            {"step": 5, "title": "Rapid Funds Drain", "detail": "Balances are transferred out via instant eWallet/MoMo cashout channels."},
        ]

    if scan_type == "file" or threat_dna.get("malware_delivery", 0) >= 50:
        return [
            {"step": 1, "title": "Lure Attachment Delivered", "detail": "Victim receives a disguised invoice, receipt, or urgent notice."},
            {"step": 2, "title": "Payload Executed", "detail": "Opening the file triggers embedded script or trojan installation."},
            {"step": 3, "title": "Silent Persistence & Harvesting", "detail": "Malware captures keystrokes, browser sessions, or SMS OTP notifications."},
            {"step": 4, "title": "Command-and-Control Exfiltration", "detail": "Stolen tokens are transmitted to attacker infrastructure."},
            {"step": 5, "title": "Account & Device Takeover", "detail": "Attacker pivots into financial and messaging accounts."},
        ]

    # Default URL / QR / Message phishing story
    entry_action = "Victim Scans Malicious QR Code" if scan_type == "qr" else (
        "Victim Reads Lure Message & Taps Link" if scan_type == "message" else "Victim Opens Phishing Link"
    )
    return [
        {"step": 1, "title": entry_action, "detail": f"Message or link impersonates {brand_label} with urgent action framing."},
        {"step": 2, "title": "Fake Portal Loads", "detail": "Lookalike login or verification page mirrors legitimate branding."},
        {"step": 3, "title": "Credentials Entered", "detail": "Victim submits username, password, card details, or account PIN."},
        {"step": 4, "title": "Real-Time OTP Relay", "detail": "Attacker replays credentials on the real service and prompts victim for the SMS OTP."},
        {"step": 5, "title": "Attacker Gains Full Access", "detail": "Account is hijacked for unauthorized transfers or downstream identity fraud."},
    ]
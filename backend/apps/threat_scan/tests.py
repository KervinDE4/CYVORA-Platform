from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from .services.ai_advisor import _clean_advisor_response, generate_security_advisor_guidance
from .services.attack_profiles import build_attack_profile
from .services.attack_story import reconstruct_attack_story
from .services.confidence_engine import calculate_confidence_score
from .services.threat_dna import compute_threat_dna
from .services.impact_predictor import predict_victim_impact
from .services.risk_scoring import combine_message_url_scores, verdict_from_score
from .services.regional_intel import analyze_regional_scam_context


class RiskClassificationTests(SimpleTestCase):
    def test_safe_boundaries(self):
        self.assertEqual(verdict_from_score(0), "safe")
        self.assertEqual(verdict_from_score(30), "safe")

    def test_suspicious_boundaries(self):
        self.assertEqual(verdict_from_score(31), "suspicious")
        self.assertEqual(verdict_from_score(70), "suspicious")

    def test_malicious_boundary(self):
        self.assertEqual(verdict_from_score(71), "malicious")
        self.assertEqual(verdict_from_score(100), "malicious")

    def test_scores_are_clamped(self):
        self.assertEqual(verdict_from_score(-10), "safe")
        self.assertEqual(verdict_from_score(150), "malicious")

    def test_weak_message_and_url_signals_do_not_get_corroboration_bonus(self):
        self.assertEqual(combine_message_url_scores(20, 20), 20)

    def test_meaningful_message_and_url_signals_get_limited_bonus(self):
        self.assertEqual(combine_message_url_scores(35, 30), 37)


class ConfidenceScoringTests(SimpleTestCase):
    def test_single_low_severity_indicator_does_not_create_high_confidence(self):
        score = calculate_confidence_score(15, [{"id": "embedded_links", "severity": "low"}], {}, {})
        self.assertEqual(score, 29)

    def test_duplicate_indicator_is_counted_once(self):
        indicator = {"id": "credential_harvest_cue", "severity": "critical"}
        self.assertEqual(calculate_confidence_score(35, [indicator, indicator], {}, {}), 50)

    def test_multiple_indicators_and_community_reports_corroborate(self):
        score = calculate_confidence_score(
            70,
            [
                {"id": "credential_harvest_cue", "severity": "critical"},
                {"id": "artificial_urgency", "severity": "high"},
            ],
            {"confidence_boost": 5},
            {"similar_threats": 2, "community_reports": 1},
        )
        self.assertEqual(score, 86)

    def test_clean_scan_has_bounded_confidence(self):
        self.assertEqual(calculate_confidence_score(0, [], {}, {}), 78)


class RegionalFalsePositiveTests(SimpleTestCase):
    def test_brand_mention_alone_does_not_add_risk_points(self):
        result = analyze_regional_scam_context("This document explains FNB Eswatini account services.")
        self.assertEqual(result["score_boost"], 0)
        self.assertEqual(result["confidence_boost"], 0)
        self.assertEqual(result["indicators"], [])
        self.assertIsNone(result["primary_category"])
        self.assertIn("FNB ESWATINI", result["targeted_brands"])

    def test_generic_wrong_transfer_phrase_is_low_weight_context(self):
        result = analyze_regional_scam_context("Someone says they sent money by wrong transfer.")
        self.assertEqual(result["score_boost"], 8)
        self.assertEqual(result["confidence_boost"], 0)
        self.assertEqual(result["indicators"][0]["severity"], "low")
        self.assertIsNone(result["primary_category"])

    def test_request_for_wallet_pin_is_stronger_evidence(self):
        result = analyze_regional_scam_context("Please send your eWallet PIN.")
        self.assertEqual(result["score_boost"], 18)
        self.assertEqual(result["confidence_boost"], 5)
        self.assertEqual(result["indicators"][0]["severity"], "high")


class AttackStoryEvidenceTests(SimpleTestCase):
    def test_story_does_not_claim_credentials_or_compromise_without_evidence(self):
        story = reconstruct_attack_story("url", "malicious", {}, {}, [
            {"id": "high_risk_tld", "title": "High-risk domain", "detail": "The URL uses a high-risk TLD."}
        ])
        self.assertEqual(story[0]["evidence_status"], "observed")
        self.assertFalse(any("credentials entered" in step["title"].lower() for step in story))
        self.assertFalse(any("account takeover" in step["title"].lower() for step in story))

    def test_possible_credential_path_is_labelled_as_possible(self):
        story = reconstruct_attack_story("url", "malicious", {}, {}, [
            {"id": "credential_harvest_cue", "title": "Credential form detected"}
        ])
        self.assertEqual(story[-1]["evidence_status"], "possible")
        self.assertEqual(story[-1]["evidence_status"], "possible")
        self.assertTrue(story[-1]["title"].startswith("Possible:"))


class AdvisorValidationTests(SimpleTestCase):
    def test_rejects_missing_or_non_string_fields(self):
        self.assertIsNone(_clean_advisor_response({"why_dangerous": "x"}))

    def test_rejects_oversized_fields(self):
        payload = {key: "x" * 501 for key in (
            "why_dangerous", "what_happens_next", "what_to_do_now", "what_never_to_share"
        )}
        self.assertIsNone(_clean_advisor_response(payload))

    def test_accepts_exact_concise_schema(self):
        payload = {key: "Clear advice." for key in (
            "why_dangerous", "what_happens_next", "what_to_do_now", "what_never_to_share"
        )}
        self.assertEqual(_clean_advisor_response(payload), payload)

    @patch("apps.threat_scan.services.ai_advisor._call_gemini", return_value=None)
    def test_provider_failure_returns_safe_fallback(self, _mock):
        scan = SimpleNamespace(
            findings={"indicators": [{"title": "Credential form detected"}]},
            scan_type="url",
            verdict="malicious",
            risk_score=80,
        )
        guidance = generate_security_advisor_guidance(scan)
        self.assertIn("do not prove", guidance["why_dangerous"])
        self.assertIn("potential outcomes", guidance["what_happens_next"])



class ThreatAttackProfileTests(SimpleTestCase):
    def test_credential_profile_requires_credential_evidence(self):
        profile = build_attack_profile("message", [
            {"id": "credential_harvest_cue", "title": "PIN request", "severity": "critical"}
        ])
        self.assertEqual(profile["profile_id"], "credential_phishing")
        self.assertEqual(profile["evidence"][0]["indicator_id"], "credential_harvest_cue")
        self.assertTrue(all(step["evidence_status"] == "possible" for step in profile["possible_steps"]))

    def test_financial_lure_gets_mobile_money_profile(self):
        profile = build_attack_profile("message", [
            {"id": "regional_momo_reversal", "title": "Wallet PIN solicitation", "severity": "high"}
        ])
        self.assertEqual(profile["profile_id"], "financial_social_engineering")

    def test_brand_lookalike_is_not_automatically_credential_theft(self):
        profile = build_attack_profile("url", [
            {"id": "brand_combosquatting", "title": "Brand lookalike", "severity": "critical"}
        ])
        self.assertEqual(profile["profile_id"], "brand_impersonation")

    def test_risky_tld_alone_does_not_mean_malware(self):
        profile = build_attack_profile("url", [
            {"id": "high_risk_tld", "title": "High-abuse TLD", "severity": "medium"}
        ])
        self.assertEqual(profile["profile_id"], "suspicious_url_infrastructure")
        self.assertNotEqual(profile["profile_id"], "malware_delivery")

    def test_no_specific_indicators_returns_unclassified_profile(self):
        profile = build_attack_profile("qr", [])
        self.assertEqual(profile["profile_id"], "unclassified")
        self.assertEqual(profile["possible_steps"], [])

    def test_attack_story_separates_observed_and_possible_steps(self):
        profile = build_attack_profile("message", [
            {"id": "financial_social_bait", "title": "Financial lure", "severity": "high"}
        ])
        story = reconstruct_attack_story(
            "message", "suspicious", {}, {}, 
            [{"id": "financial_social_bait", "title": "Financial lure", "severity": "high"}],
            attack_profile=profile,
        )
        self.assertEqual(story[0]["evidence_status"], "observed")
        self.assertTrue(all(step["evidence_status"] == "possible" for step in story[1:]))



class ThreatDnaEvidenceTests(SimpleTestCase):
    def test_brand_mention_does_not_create_credential_or_financial_dna(self):
        dna = compute_threat_dna(
            "message", 60, [],
            {"targeted_brands": ["FNB"], "primary_category": None},
        )
        self.assertEqual(dna["credential_theft"], 0)
        self.assertEqual(dna["financial_fraud"], 0)
        self.assertEqual(dna["identity_theft"], 0)
        self.assertEqual(dna["malware_delivery"], 0)

    def test_file_scan_alone_does_not_mean_malware(self):
        dna = compute_threat_dna("file", 80, [], {})
        self.assertEqual(dna["malware_delivery"], 0)

    def test_financial_lure_only_contributes_to_financial_category(self):
        dna = compute_threat_dna(
            "message", 65,
            [{"id": "financial_social_bait", "severity": "high"}],
            {},
        )
        self.assertEqual(dna["financial_fraud"], 40)
        self.assertEqual(dna["credential_theft"], 0)
        self.assertEqual(dna["malware_delivery"], 0)

    def test_explicit_credential_signal_contributes_to_credential_category(self):
        dna = compute_threat_dna(
            "message", 80,
            [{"id": "credential_harvest_cue", "severity": "critical"}],
            {},
        )
        self.assertEqual(dna["credential_theft"], 65)

    def test_category_score_never_exceeds_overall_risk(self):
        dna = compute_threat_dna(
            "message", 20,
            [{"id": "credential_harvest_cue"}, {"id": "cleartext_sensitive_path"}],
            {},
        )
        self.assertLessEqual(dna["credential_theft"], 20)


class ImpactPredictionTests(SimpleTestCase):
    def test_bank_or_brand_context_alone_does_not_claim_account_takeover(self):
        impact = predict_victim_impact(
            20, {"financial_fraud": 0, "credential_theft": 0},
            {"targeted_brands": ["FNB"], "primary_category": None}, 70,
        )
        self.assertEqual(
            impact["potential_outcomes"],
            ["No specific downstream impact established from the available evidence"],
        )
        self.assertNotIn("Bank Account Takeover", impact["potential_outcomes"])

    def test_financial_lure_is_described_as_possible_payment_fraud(self):
        impact = predict_victim_impact(
            55, {"financial_fraud": 40},
            {"primary_category": None}, 62,
        )
        self.assertIn("Possible financial or payment fraud", impact["potential_outcomes"])
        self.assertNotIn("Bank Account Takeover", impact["potential_outcomes"])

    def test_wallet_fraud_requires_specific_mobile_money_context(self):
        impact = predict_victim_impact(
            75, {"financial_fraud": 70},
            {"primary_category": "Mobile Money Reversal / Voucher Scam"}, 80,
        )
        self.assertIn("Possible mobile-money or wallet fraud", impact["potential_outcomes"])

    def test_impact_confidence_uses_evidence_confidence_not_risk_blend(self):
        impact = predict_victim_impact(95, {}, {}, 23)
        self.assertEqual(impact["confidence"], 23)
        self.assertEqual(impact["severity"], "critical")
        self.assertTrue(impact["limitations"])

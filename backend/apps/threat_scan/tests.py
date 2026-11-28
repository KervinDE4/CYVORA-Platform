from django.test import SimpleTestCase

from .services.confidence_engine import calculate_confidence_score
from .services.risk_scoring import verdict_from_score
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


class ConfidenceScoringTests(SimpleTestCase):
    def test_single_low_severity_indicator_does_not_create_high_confidence(self):
        score = calculate_confidence_score(
            15,
            [{"id": "embedded_links", "severity": "low"}],
            {},
            {},
        )
        self.assertEqual(score, 29)

    def test_duplicate_indicator_is_counted_once(self):
        indicator = {"id": "credential_harvest_cue", "severity": "critical"}
        score = calculate_confidence_score(35, [indicator, indicator], {}, {})
        self.assertEqual(score, 50)

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
        result = analyze_regional_scam_context(
            "This document explains FNB Eswatini account services."
        )
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

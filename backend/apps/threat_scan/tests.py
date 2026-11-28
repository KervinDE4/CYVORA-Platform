from django.test import SimpleTestCase

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

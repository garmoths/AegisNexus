import unittest

from modules.victim_atlas.ingest import extract_case_fields


class VictimAtlasExtractionTests(unittest.TestCase):
    def test_extract_case_fields_detects_smishing_bank_signal(self):
        document = {
            "title": "SMS campaign targets bank users with fake login page",
            "raw_text": "Attackers sent SMS links to steal banking credentials and OTP codes.",
            "url": "https://example.org/advisory",
            "published_at": "2026-01-12T12:00:00Z",
        }
        case = extract_case_fields(document, trust_tier="tier1")
        self.assertEqual(case["attack_method"], "smishing")
        self.assertEqual(case["loss_type"], "bank_account")
        self.assertGreaterEqual(case["confidence_score"], 60)
        self.assertTrue(case["defense_steps"])

    def test_extract_case_fields_falls_back_safely(self):
        document = {
            "title": "Generic cyber incident update",
            "raw_text": "Suspicious activity reported in multiple services.",
            "url": "https://example.net/post",
            "published_at": "",
        }
        case = extract_case_fields(document, trust_tier="tier2")
        self.assertEqual(case["attack_method"], "phishing")
        self.assertIn("critical_warning", case)
        self.assertIn("case_slug", case)


if __name__ == "__main__":
    unittest.main()

import unittest

from modules.phishing_detector.url_normalize import normalize_url_record


class NormalizeUrlRecordTests(unittest.TestCase):
    def test_normalizes_basic_url(self):
        out = normalize_url_record("Example.com/login?b=2&a=1")
        self.assertEqual(out["domain_norm"], "example.com")
        self.assertTrue(out["canonical_url"].startswith("http://example.com/"))
        self.assertIn("a=1&b=2", out["canonical_url"])

    def test_returns_empty_for_comment(self):
        out = normalize_url_record("# comment")
        self.assertEqual(out, {})


if __name__ == "__main__":
    unittest.main()

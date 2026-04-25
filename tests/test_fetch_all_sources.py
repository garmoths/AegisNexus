import io
import unittest
import zipfile

from modules.phishing_detector.fetch_all_sources import (
    _extract_urls_from_kaggle_zip,
    _is_suspicious_certstream_domain,
    parse_feed_lines_to_urls,
)


class FetchAllSourcesTests(unittest.TestCase):
    def test_parse_feed_lines_accepts_domains_and_urls(self):
        content = """
        # comment
        example.com
        www.test.org
        https://secure.bank.example/login
        suspicious-domain.net/path
        """
        parsed = set(parse_feed_lines_to_urls(content))
        self.assertIn("http://example.com", parsed)
        self.assertIn("http://www.test.org", parsed)
        self.assertIn("https://secure.bank.example/login", parsed)
        self.assertIn("http://suspicious-domain.net/path", parsed)

    def test_extract_urls_from_kaggle_zip_parses_csv_and_txt(self):
        csv_content = "url,label\nhttps://alpha.example/login,1\nbeta.example,1\n"
        txt_content = "gamma.example\nhttps://delta.example/path\n"

        blob = io.BytesIO()
        with zipfile.ZipFile(blob, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("phishing.csv", csv_content)
            zf.writestr("extra.txt", txt_content)

        parsed = set(_extract_urls_from_kaggle_zip(blob.getvalue()))
        self.assertIn("https://alpha.example/login", parsed)
        self.assertIn("http://beta.example", parsed)
        self.assertIn("http://gamma.example", parsed)
        self.assertIn("https://delta.example/path", parsed)

    def test_certstream_suspicious_domain_heuristic(self):
        keywords = ["login", "verify"]
        self.assertTrue(_is_suspicious_certstream_domain("secure-login-check.com", keywords))
        self.assertTrue(_is_suspicious_certstream_domain("xn--pple-43d.com", keywords))
        self.assertFalse(_is_suspicious_certstream_domain("github.com", keywords))


if __name__ == "__main__":
    unittest.main()

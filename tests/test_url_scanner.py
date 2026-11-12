"""Regression tests for url_scanner.py.

Run from the project root:
    python -m unittest discover tests

WHOIS is mocked, so these tests need no internet and run in under a second.
"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import url_scanner as us


def fake_whois(age_days):
    created = datetime.now(timezone.utc) - timedelta(days=age_days)
    return lambda domain, timeout=None: SimpleNamespace(creation_date=created)


class NormalizeUrlTests(unittest.TestCase):
    def test_uppercase_scheme(self):
        url, domain, _ = us._normalize_url("HTTPS://Kbank-Secure.xyz/Login")
        self.assertEqual(url, "HTTPS://Kbank-Secure.xyz/Login")
        self.assertEqual(domain, "kbank-secure.xyz")

    def test_adds_scheme(self):
        url, domain, path = us._normalize_url("  bit.ly/abc  ")
        self.assertEqual(url, "https://bit.ly/abc")
        self.assertEqual(domain, "bit.ly")
        self.assertEqual(path, "/abc")

    def test_userinfo_trick_uses_real_host(self):
        _, domain, _ = us._normalize_url("https://kbank.co.th@evil.xyz/login")
        self.assertEqual(domain, "evil.xyz")


class BrandTests(unittest.TestCase):
    def test_common_word_is_not_brand(self):
        self.assertEqual(us.check_brand_impersonation("myonline-shop.com")["score"], 0)
        self.assertEqual(us.check_brand_impersonation("pineapple.com")["score"], 0)

    def test_short_brand_as_whole_part(self):
        self.assertGreater(us.check_brand_impersonation("line-login.xyz")["score"], 0)
        self.assertGreater(us.check_brand_impersonation("ktb.verify.cc")["score"], 0)

    def test_long_brand_inside_word_still_caught(self):
        self.assertGreater(us.check_brand_impersonation("kbankonline.com")["score"], 0)

    def test_official_domain_and_subdomain(self):
        self.assertEqual(us.check_brand_impersonation("kbank.co.th")["score"], 0)
        self.assertEqual(us.check_brand_impersonation("online.kbank.co.th")["score"], 0)

    def test_lookalike_of_official_domain(self):
        # used to pass because "fakekbank.co.th".endswith("kbank.co.th")
        self.assertGreater(us.check_brand_impersonation("fakekbank.co.th")["score"], 0)


class TldAndShortUrlTests(unittest.TestCase):
    def test_tld_only_matches_real_ending(self):
        self.assertEqual(us.check_suspicious_tld("www.cnn.com")["score"], 0)
        self.assertEqual(us.check_suspicious_tld("linkedin.com")["score"], 0)
        self.assertEqual(us.check_suspicious_tld("faepass.cc")["score"], us.SCORE_TLD_CC)

    def test_short_url_exact_domain(self):
        self.assertGreater(us.check_short_url("bit.ly")["score"], 0)
        self.assertEqual(us.check_short_url("tmn.com")["score"], 0)


class CredentialTests(unittest.TestCase):
    def test_short_keywords_need_whole_word(self):
        self.assertEqual(us.check_credential_keywords("example.com", "/opinion/atmosphere")["score"], 0)

    def test_real_keywords(self):
        r = us.check_credential_keywords("example.com", "/verify/otp")
        self.assertEqual(r["score"], us.SCORE_CREDENTIAL_MULTI)


class ScanUrlTests(unittest.TestCase):
    @patch.object(us.whois, "whois", fake_whois(3000))
    def test_blacklist_is_always_danger(self):
        # old domain + nothing else suspicious: before the fix this was only "warn"
        us.THAI_BLACKLIST.add("old-scam.com")
        try:
            r = us.scan_url("old-scam.com")
        finally:
            us.THAI_BLACKLIST.discard("old-scam.com")
        self.assertEqual(r["type"], "danger")
        self.assertGreaterEqual(r["risk"], us.RISK_THRESHOLD_DANGER)

    @patch.object(us.whois, "whois", fake_whois(3000))
    def test_official_site_is_safe(self):
        r = us.scan_url("https://www.kbank.co.th")
        self.assertEqual(r["type"], "safe")

    @patch.object(us.whois, "whois", fake_whois(5))
    def test_new_brand_phishing_is_danger(self):
        r = us.scan_url("kbank-secure.xyz/verify/login")
        self.assertEqual(r["type"], "danger")

    def test_whois_failure_falls_back(self):
        def boom(domain, timeout=None):
            raise TimeoutError("slow server")
        with patch.object(us.whois, "whois", boom):
            r = us.check_domain_age("example.com")
        self.assertEqual(r["score"], us.SCORE_DOMAIN_UNKNOWN)


if __name__ == "__main__":
    unittest.main()

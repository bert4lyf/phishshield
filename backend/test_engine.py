"""Automated diagnostic test suite for PhishShield AI Security Engine."""

import sys
import unittest
from fastapi.testclient import TestClient

from app.main import app
from app.schemas import RiskLevel


class TestPhishShieldEngine(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health_check(self):
        """Verify health check endpoint returns operational status and ML status."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("ml_model_loaded", data)
        self.assertTrue(data["ml_model_loaded"])

    def test_safe_domains_whitelist(self):
        """Verify authentic well-known enterprise domains always receive 0% SAFE rating."""
        safe_urls = [
            "https://www.google.com",
            "https://apple.com/iphone-16-pro",
            "https://github.com/torvalds/linux",
            "https://www.microsoft.com/en-us/windows",
            "https://paypal.com/signin",
            "https://en.wikipedia.org/wiki/Computer_security"
        ]
        for url in safe_urls:
            response = self.client.post("/api/v1/scan", json={"url": url})
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data["risk_level"], RiskLevel.SAFE.value)
            self.assertEqual(data["risk_score"], 0)
            print(f"[PASS] Verified Safe: {url} -> Score: {data['risk_score']} ({data['risk_level']})")

    def test_typosquatting_detection(self):
        """Verify typosquatting permutations (e.g. paypa1) are flagged."""
        payload = {"url": "https://www.paypa1-security.com/login"}
        response = self.client.post("/api/v1/scan", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn(data["risk_level"], [RiskLevel.HIGH.value, RiskLevel.CRITICAL.value])
        factor_codes = [f["code"] for f in data["detected_factors"]]
        self.assertTrue(any("TYPOSQUATTING" in code or "BRAND" in code or "ML_" in code for code in factor_codes))
        print(f"[PASS] Typosquatting: {data['url']} -> Score: {data['risk_score']} ({data['risk_level']})")

    def test_ip_address_host(self):
        """Verify raw IP addresses as hostnames are flagged as critical/high threat."""
        payload = {"url": "http://192.168.1.50/bankofamerica/signin"}
        response = self.client.post("/api/v1/scan", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn(data["risk_level"], [RiskLevel.HIGH.value, RiskLevel.CRITICAL.value])
        factor_codes = [f["code"] for f in data["detected_factors"]]
        self.assertIn("IP_ADDRESS_AS_HOST", factor_codes)
        print(f"[PASS] IP Host URL: {data['url']} -> Score: {data['risk_score']} ({data['risk_level']})")

    def test_high_entropy_and_suspicious_tld(self):
        """Verify high Shannon entropy DGA domains and suspicious TLDs are flagged."""
        payload = {"url": "http://xkjq9823nmzpa91823.top/account"}
        response = self.client.post("/api/v1/scan", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreaterEqual(data["risk_score"], 40)
        factor_codes = [f["code"] for f in data["detected_factors"]]
        self.assertTrue(any("ENTROPY" in code or "SUSPICIOUS_TLD" in code for code in factor_codes))
        print(f"[PASS] DGA URL: {data['url']} -> Score: {data['risk_score']} ({data['risk_level']})")

    def test_brand_in_subdomain(self):
        """Verify brand impersonation in subdomains is flagged."""
        payload = {"url": "https://paypal.account-verification-portal.net/auth"}
        response = self.client.post("/api/v1/scan", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        factor_codes = [f["code"] for f in data["detected_factors"]]
        self.assertIn("BRAND_IN_SUBDOMAIN", factor_codes)
        print(f"[PASS] Subdomain Impersonation: {data['url']} -> Score: {data['risk_score']} ({data['risk_level']})")

    def test_userinfo_at_exploit(self):
        """Verify userinfo '@' symbol URL hijacking is flagged as CRITICAL."""
        payload = {"url": "https://google.com@phishing-target-domain.xyz/auth"}
        response = self.client.post("/api/v1/scan", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("USERINFO_AT_SYMBOL_EXPLOIT", [f["code"] for f in data["detected_factors"]])
        print(f"[PASS] Userinfo @ Exploit: {data['url']} -> Score: {data['risk_score']} ({data['risk_level']})")

    def test_threat_report_and_analytics_endpoints(self):
        """Verify report submission, stats computation, and recent scan retrieval."""
        report_payload = {
            "url": "https://fake-binance-airdrop-gift.xyz",
            "reason": "Phishing site attempting to steal crypto private keys via fake wallet connector.",
            "reporter_id": "soc-analyst-01"
        }
        rep_res = self.client.post("/api/v1/report", json=report_payload)
        self.assertEqual(rep_res.status_code, 201)

        stats_res = self.client.get("/api/v1/analytics/stats")
        self.assertEqual(stats_res.status_code, 200)
        stats = stats_res.json()
        self.assertIn("total_scans", stats)
        self.assertIn("threats_intercepted", stats)
        print(f"[PASS] Analytics verified: Total Scans={stats['total_scans']}, Reports={stats['total_community_reports']}")


if __name__ == "__main__":
    unittest.main(verbosity=2)

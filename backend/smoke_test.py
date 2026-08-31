"""Smoke test script validating PhishShield AI API endpoints and serverless readiness."""

import json
import sys
from pathlib import Path

# Add backend and root to sys.path
_current = Path(__file__).resolve().parent
_root = _current.parent
for p in (str(_current), str(_root)):
    if p not in sys.path:
        sys.path.insert(0, p)

from fastapi.testclient import TestClient
from api.index import app


def run_smoke_test():
    print("=" * 70)
    print("PHISHSHIELD AI SERVERLESS SMOKE TEST")
    print("=" * 70)

    client = TestClient(app)

    # 1. Root HTML Endpoint (SOC Dashboard)
    r_html = client.get("/", headers={"accept": "text/html"})
    print(f"\n[1] Root Dashboard Route: HTTP {r_html.status_code}")
    assert r_html.status_code == 200, f"Root HTML returned {r_html.status_code}"
    print("    [PASS] Verified HTML dashboard rendered.")

    # 2. Root API Catalog JSON
    r_json = client.get("/", headers={"accept": "application/json"})
    print(f"\n[2] Root API JSON Catalog: HTTP {r_json.status_code}")
    assert r_json.status_code == 200
    print(f"    [PASS] Service Status: {r_json.json().get('status')}")

    # 3. Health Probe & HEAD check
    r_health = client.get("/health")
    r_head = client.head("/health")
    print(f"\n[3] Health Checks: GET={r_health.status_code}, HEAD={r_head.status_code}")
    assert r_health.status_code == 200 and r_head.status_code == 200
    print(f"    [PASS] Health Payload: {r_health.json()}")

    # 4. Multi-Tier Scan Tests
    test_cases = [
        ("Safe Mainstream Site", "https://www.google.com"),
        ("Typosquatting Permutation", "https://www.paypa1-security.com/login"),
        ("Raw IP Host Impersonation", "http://192.168.1.50/bankofamerica/signin"),
        ("DGA High Entropy Domain", "http://xkjq9823nmzpa91823.top/account"),
        ("Subdomain Brand Spoofing", "https://paypal.account-verification-portal.net/auth")
    ]

    print("\n" + "=" * 70)
    print("[4] MULTI-TIER SCAN PIPELINE EVALUATION:")
    print("=" * 70)

    for label, url in test_cases:
        res = client.post("/api/v1/scan", json={"url": url})
        assert res.status_code == 200
        data = res.json()
        print(f"\n>> [{label}] {data['url']}")
        print(f"   Verdict: {data['verdict']} | Level: {data['risk_level']} | Score: {data['risk_score']}/100")
        if data.get("tier_breakdown"):
            tb = data["tier_breakdown"]
            print(f"   Breakdown -> Heuristics: {tb['heuristic_score']} | ML: {tb['ml_score']} | AI: {tb['ai_score']}")
        print(f"   Latency: {data['scan_latency_ms']}ms")

    # 5. Community Threat Reporting
    print("\n" + "=" * 70)
    print("[5] COMMUNITY THREAT REPORTING TEST:")
    print("=" * 70)
    report_res = client.post(
        "/api/v1/report",
        json={
            "url": "https://metamask-seed-phrase-verify.buzz",
            "reason": "Phishing portal masquerading as MetaMask crypto recovery wallet.",
            "reporter_id": "smoke-test-runner"
        }
    )
    print(f"Report Status: HTTP {report_res.status_code}")
    assert report_res.status_code == 201

    # 6. Analytics & Telemetry
    print("\n" + "=" * 70)
    print("[6] SOC ANALYTICS & TELEMETRY:")
    print("=" * 70)
    stats_res = client.get("/api/v1/analytics/stats")
    assert stats_res.status_code == 200
    print(f"Stats Status: HTTP {stats_res.status_code} -> {stats_res.json()}")

    recent_res = client.get("/api/v1/analytics/recent?limit=5")
    assert recent_res.status_code == 200
    print(f"Recent Scans Count: {len(recent_res.json())}")

    print("\n" + "=" * 70)
    print("ALL SERVERLESS DEPLOYMENT CHECKS PASSED WITH 100% SUCCESS.")
    print("=" * 70)


if __name__ == "__main__":
    run_smoke_test()


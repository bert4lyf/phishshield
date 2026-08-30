"""Smoke test script validating live PhishShield AI API endpoints."""

import json
import requests


def run_smoke_test():
    base_url = "http://127.0.0.1:8000"
    print("=" * 70)
    print("PHISHSHIELD AI LIVE SMOKE TEST")
    print("=" * 70)

    # 1. Health Probe
    try:
        health = requests.get(f"{base_url}/health", timeout=5)
        print(f"\n[1] Health Check: HTTP {health.status_code}")
        print(json.dumps(health.json(), indent=2))
    except Exception as e:
        print(f"Failed to connect to backend at {base_url}: {e}")
        return

    # 2. Live Scan Endpoint Tests
    test_cases = [
        ("Safe Mainstream Site", "https://www.google.com"),
        ("Typosquatting Permutation", "https://www.paypa1-security.com/login"),
        ("Raw IP Host Impersonation", "http://192.168.1.50/bankofamerica/signin"),
        ("DGA High Entropy Domain", "http://xkjq9823nmzpa91823.top/account"),
        ("Subdomain Brand Spoofing", "https://paypal.account-verification-portal.net/auth")
    ]

    print("\n" + "=" * 70)
    print("[2] LIVE MULTI-TIER SCAN ENDPOINT TESTS:")
    print("=" * 70)

    for label, url in test_cases:
        res = requests.post(f"{base_url}/api/v1/scan", json={"url": url}, timeout=10)
        data = res.json()
        print(f"\n>> [{label}] {data['url']}")
        print(f"   Verdict: {data['verdict']} | Level: {data['risk_level']} | Score: {data['risk_score']}/100")
        if "tier_breakdown" in data and data["tier_breakdown"]:
            tb = data["tier_breakdown"]
            print(f"   Tier Breakdown -> Heuristics: {tb['heuristic_score']} | ML: {tb['ml_score']} | AI: {tb['ai_score']}")
        print(f"   Latency: {data['scan_latency_ms']}ms")
        print(f"   Summary: {data['explainability_summary']}")

    # 3. Community Threat Reporting
    print("\n" + "=" * 70)
    print("[3] COMMUNITY THREAT REPORTING TEST:")
    print("=" * 70)
    report_res = requests.post(
        f"{base_url}/api/v1/report",
        json={
            "url": "https://metamask-seed-phrase-verify.buzz",
            "reason": "Phishing portal masquerading as MetaMask crypto recovery wallet.",
            "reporter_id": "smoke-test-runner"
        },
        timeout=5
    )
    print(f"Report Status: HTTP {report_res.status_code}")
    print(json.dumps(report_res.json(), indent=2))

    # 4. Analytics & Stats
    print("\n" + "=" * 70)
    print("[4] SOC ANALYTICS & RECENT SCANS TELEMETRY:")
    print("=" * 70)
    stats_res = requests.get(f"{base_url}/api/v1/analytics/stats", timeout=5)
    print(f"Stats Status: HTTP {stats_res.status_code}")
    print(json.dumps(stats_res.json(), indent=2))

    recent_res = requests.get(f"{base_url}/api/v1/analytics/recent?limit=5", timeout=5)
    print(f"\nRecent Scans Count: {len(recent_res.json())}")
    print("=" * 70)
    print("ALL SMOKE TESTS COMPLETED SUCCESSFULLY.")
    print("=" * 70)


if __name__ == "__main__":
    run_smoke_test()

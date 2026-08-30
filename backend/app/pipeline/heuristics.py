"""Heuristic Threat Engine for rapid sub-millisecond phishing & scam analysis."""

import re
from typing import List, Tuple

try:
    import Levenshtein
except ImportError:
    try:
        from rapidfuzz.distance import Levenshtein as _rf_lev
        class Levenshtein:
            @staticmethod
            def distance(s1: str, s2: str) -> int:
                return int(_rf_lev.distance(s1, s2))
            @staticmethod
            def ratio(s1: str, s2: str) -> float:
                return float(_rf_lev.normalized_similarity(s1, s2))
    except ImportError:
        class Levenshtein:
            @staticmethod
            def distance(s1: str, s2: str) -> int:
                if s1 == s2:
                    return 0
                if len(s1) < len(s2):
                    return Levenshtein.distance(s2, s1)
                if len(s2) == 0:
                    return len(s1)
                prev = list(range(len(s2) + 1))
                for i, c1 in enumerate(s1):
                    curr = [i + 1]
                    for j, c2 in enumerate(s2):
                        curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
                    prev = curr
                return prev[-1]
            @staticmethod
            def ratio(s1: str, s2: str) -> float:
                lens = len(s1) + len(s2)
                if lens == 0:
                    return 1.0
                return 1.0 - (Levenshtein.distance(s1, s2) / max(len(s1), len(s2)))

from app.schemas import RiskFactor, RiskLevel
from app.utils.domain_tools import (
    calculate_shannon_entropy,
    extract_domain_components,
    find_suspicious_keywords,
    has_suspicious_tld,
    is_ip_address,
    is_punycode_or_idn,
    is_verified_top_domain,
)

# High-value brand targets frequently spoofed by attackers
TARGET_BRANDS = [
    "paypal", "google", "microsoft", "binance", "apple", "amazon", 
    "github", "bankofamerica", "netflix", "facebook", "instagram", 
    "wellsfargo", "coinbase", "chase", "dropbox", "linkedin", 
    "twitter", "yahoo", "ebay", "steam", "discord", "roblox", 
    "walmart", "citibank", "metamask", "ledger", "kraken", "usps", "ups", "fedex"
]

# Character substitution dictionary common in visual leetspeak / typosquatting
LEET_SUBS = {
    "1": "l", "0": "o", "3": "e", "5": "s", "8": "b", 
    "v": "u", "vv": "w", "rn": "m", "@": "a"
}


def normalize_leetspeak(text: str) -> str:
    """Convert visual leetspeak substitutions to normalized text."""
    normalized = text.lower()
    for leet, char in LEET_SUBS.items():
        normalized = normalized.replace(leet, char)
    return normalized


def check_typosquatting(domain: str, registered_domain: str, full_host: str) -> Tuple[int, List[RiskFactor]]:
    """
    Evaluate domain, registered domain, and subdomain tokens against known target brands
    using Levenshtein distance, leetspeak normalization, and token decomposition.
    """
    factors: List[RiskFactor] = []
    score_addition = 0
    clean_domain = domain.lower()
    normalized_domain = normalize_leetspeak(clean_domain)

    # Split domain into sub-tokens (e.g. 'paypa1-security' -> ['paypa1', 'security'])
    tokens = re.split(r"[-_.]", clean_domain)
    normalized_tokens = [normalize_leetspeak(t) for t in tokens]

    for brand in TARGET_BRANDS:
        # Exact match of genuine domain is safe for that brand (e.g. google.com or paypal.com)
        if clean_domain == brand and (registered_domain == f"{brand}.com" or registered_domain.startswith(f"{brand}.")):
            continue

        # 1. Check token-level Levenshtein & leetspeak (e.g. token 'paypa1' in 'paypa1-security')
        token_match = False
        for t, nt in zip(tokens, normalized_tokens):
            if not t:
                continue
            if t == brand and clean_domain != brand:
                token_match = True
                score_addition = max(score_addition, 60)
                factors.append(
                    RiskFactor(
                        code="BRAND_IN_DOMAIN_SLD",
                        severity=RiskLevel.HIGH,
                        message=f"Brand keyword '{brand}' was detected in unverified domain '{clean_domain}'."
                    )
                )
                break

            t_dist_raw = Levenshtein.distance(t, brand)
            t_dist_norm = Levenshtein.distance(nt, brand)
            t_ratio = Levenshtein.ratio(t, brand)
            if (t_dist_raw in (1, 2) and len(brand) >= 4) or (t_dist_norm in (0, 1) and len(t) >= 4) or t_ratio >= 0.82:
                token_match = True
                score_addition = max(score_addition, 65)
                factors.append(
                    RiskFactor(
                        code="TYPOSQUATTING_TARGET",
                        severity=RiskLevel.CRITICAL,
                        message=f"Domain token '{t}' is a deceptive typosquatting variation of brand '{brand}' (edit distance: {t_dist_raw}, normalized match: '{nt}')."
                    )
                )
                break

        if token_match:
            break

        # 2. Whole domain typosquatting check
        is_typo = (Levenshtein.distance(clean_domain, brand) in (1, 2) and len(brand) >= 4) or (Levenshtein.distance(normalized_domain, brand) in (0, 1) and clean_domain != brand and len(clean_domain) >= 4)
        is_high_sim = (Levenshtein.ratio(clean_domain, brand) >= 0.82 or Levenshtein.ratio(normalized_domain, brand) >= 0.85) and clean_domain != brand

        if is_typo or is_high_sim:
            score_addition = max(score_addition, 65)
            factors.append(
                RiskFactor(
                    code="TYPOSQUATTING_TARGET",
                    severity=RiskLevel.CRITICAL,
                    message=f"Domain '{clean_domain}' appears to be a typosquatting imitation of high-value brand '{brand}'."
                )
            )
            break

        # 3. Check brand or leetspeak brand embedded in composite domain (e.g. 'paypal-update', 'paypa1-security')
        if (brand in clean_domain or brand in normalized_domain) and clean_domain != brand:
            score_addition = max(score_addition, 60)
            factors.append(
                RiskFactor(
                    code="BRAND_IN_DOMAIN_SLD",
                    severity=RiskLevel.HIGH,
                    message=f"Brand keyword '{brand}' is embedded inside unverified domain '{clean_domain}'."
                )
            )
            break

    return score_addition, factors


def check_shannon_entropy(domain_comp: dict) -> Tuple[int, List[RiskFactor]]:
    """
    Evaluate Shannon entropy of subdomains, domain names, and full path.
    """
    factors: List[RiskFactor] = []
    score_addition = 0

    subdomain = domain_comp.get("subdomain", "")
    domain = domain_comp.get("domain", "")

    # Domain name entropy
    if domain:
        domain_entropy = calculate_shannon_entropy(domain)
        if len(domain) >= 10 and domain_entropy > 3.4:
            score_addition = max(score_addition, 45)
            factors.append(
                RiskFactor(
                    code="HIGH_DOMAIN_ENTROPY",
                    severity=RiskLevel.HIGH,
                    message=f"Domain '{domain}' has unusually high Shannon entropy ({domain_entropy:.2f}), indicative of algorithmic domain generation (DGA)."
                )
            )

    # Subdomain entropy
    if subdomain:
        sub_entropy = calculate_shannon_entropy(subdomain)
        if len(subdomain) >= 15 and sub_entropy > 3.8:
            score_addition = max(score_addition, 35)
            factors.append(
                RiskFactor(
                    code="HIGH_SUBDOMAIN_ENTROPY",
                    severity=RiskLevel.MEDIUM,
                    message=f"Subdomain '{subdomain}' demonstrates high entropy ({sub_entropy:.2f}), suggesting obfuscated routing."
                )
            )

    return score_addition, factors


def check_structural_anomalies(domain_comp: dict) -> Tuple[int, List[RiskFactor]]:
    """
    Inspect URL structure for deceptive technical anomalies, redirection tricks, and host manipulation.
    """
    factors: List[RiskFactor] = []
    score_addition = 0
    raw_url = domain_comp.get("raw_url", "")
    hostname = domain_comp.get("hostname", "")
    subdomain = domain_comp.get("subdomain", "")
    domain = domain_comp.get("domain", "")
    suffix = domain_comp.get("suffix", "")
    path = domain_comp.get("path", "").lower()
    port = domain_comp.get("port", "")

    # 1. Hostname is a raw IP address
    if is_ip_address(hostname):
        score_addition += 70
        factors.append(
            RiskFactor(
                code="IP_ADDRESS_AS_HOST",
                severity=RiskLevel.CRITICAL,
                message=f"Host is a raw IP address ({hostname}) rather than a verified domain name, a primary scam delivery pattern."
            )
        )
        # Check if brand is targeted in path of IP host
        for brand in TARGET_BRANDS:
            if brand in path:
                score_addition += 25
                factors.append(
                    RiskFactor(
                        code="BRAND_IN_IP_PATH",
                        severity=RiskLevel.CRITICAL,
                        message=f"Target brand '{brand}' was detected in path of raw IP server '{hostname}'."
                    )
                )
                break

    # 2. '@' symbol in URL (Userinfo redirection abuse)
    if "@" in raw_url:
        score_addition += 60
        factors.append(
            RiskFactor(
                code="USERINFO_AT_SYMBOL_EXPLOIT",
                severity=RiskLevel.CRITICAL,
                message="The URL contains an '@' character, commonly used to trick users into believing they are navigating to the prefix authority."
            )
        )

    # 3. Brand abuse in Subdomain (e.g. paypal.com.verify-login-portal.net)
    for brand in TARGET_BRANDS:
        if brand in subdomain:
            score_addition += 50
            factors.append(
                RiskFactor(
                    code="BRAND_IN_SUBDOMAIN",
                    severity=RiskLevel.CRITICAL,
                    message=f"Target brand '{brand}' was detected in the subdomain '{subdomain}' of registered domain '{domain_comp.get('registered_domain')}'."
                )
            )
            break

    # 4. Excessive Subdomain Depth (> 2 subdomain levels)
    if subdomain:
        sub_parts = [p for p in subdomain.split(".") if p]
        if len(sub_parts) >= 3:
            score_addition += 25
            factors.append(
                RiskFactor(
                    code="EXCESSIVE_SUBDOMAINS",
                    severity=RiskLevel.MEDIUM,
                    message=f"URL utilizes excessive subdomain nesting ({len(sub_parts)} levels), frequently used to hide actual root domain ownership."
                )
            )

    # 5. IDN Homograph / Punycode abuse
    is_idn, decoded = is_punycode_or_idn(hostname)
    if is_idn:
        score_addition += 45
        factors.append(
            RiskFactor(
                code="IDN_PUNYCODE_HOMOGRAPH",
                severity=RiskLevel.HIGH,
                message=f"Domain utilizes Internationalized Domain Name (Punycode / non-ASCII) encoding ('{decoded or hostname}'), often used to disguise lookalike characters."
            )
        )

    # 6. High-risk / Abused TLD
    if has_suspicious_tld(suffix):
        score_addition += 30
        factors.append(
            RiskFactor(
                code="SUSPICIOUS_TLD",
                severity=RiskLevel.MEDIUM,
                message=f"The top-level domain '.{suffix}' is statistically overrepresented in phishing and scam campaigns."
            )
        )

    # 7. Sensitive credential keywords in subdomains or path
    kw_sub = find_suspicious_keywords(subdomain)
    kw_path = find_suspicious_keywords(path)
    found_kws = list(set(kw_sub + kw_path))
    if found_kws:
        kw_score = min(len(found_kws) * 12, 35)
        score_addition += kw_score
        factors.append(
            RiskFactor(
                code="SECURITY_KEYWORDS_DETECTED",
                severity=RiskLevel.MEDIUM if kw_score >= 20 else RiskLevel.LOW,
                message=f"URL contains sensitive security/auth action keywords ({', '.join(found_kws[:4])})."
            )
        )

    # 8. Suspicious non-standard web port
    if port and port not in ("80", "443", "8000", "3000"):
        score_addition += 15
        factors.append(
            RiskFactor(
                code="NON_STANDARD_PORT",
                severity=RiskLevel.LOW,
                message=f"URL specifies a non-standard web service port (:{port})."
            )
        )

    # 9. Multiple consecutive hyphens or double slashes in path
    if "--" in domain or "//" in path:
        score_addition += 15
        factors.append(
            RiskFactor(
                code="SUSPICIOUS_STRING_FORMATTING",
                severity=RiskLevel.LOW,
                message="URL contains unusual formatting artifacts (consecutive hyphens or redundant path slashes)."
            )
        )

    return score_addition, factors


def run_heuristic_pipeline(url: str) -> Tuple[int, List[RiskFactor], dict]:
    """
    Execute full heuristic analysis on the input URL.
    
    Guarantees zero false positives for verified enterprise top domains,
    while maintaining rigorous detection for typosquatting, raw IP servers,
    brand subdomain impersonation, and DGA attacks.
    """
    components = extract_domain_components(url)
    registered_domain = components.get("registered_domain", "")
    raw_url = components.get("raw_url", "")
    hostname = components.get("hostname", "")

    all_factors: List[RiskFactor] = []

    # Priority Check: Check if domain is in authoritative verified whitelist
    if is_verified_top_domain(registered_domain):
        # Even for verified domains, ensure attacker hasn't embedded an '@' hijack or homoglyph
        is_idn, _ = is_punycode_or_idn(hostname)
        if "@" not in raw_url and not is_idn:
            all_factors.append(
                RiskFactor(
                    code="VERIFIED_AUTHORITATIVE_DOMAIN",
                    severity=RiskLevel.SAFE,
                    message=f"Domain '{registered_domain}' is an authoritative, verified enterprise web property."
                )
            )
            return 0, all_factors, components

    cumulative_score = 0

    # 1. Typosquatting & Leetspeak Analysis
    typo_score, typo_factors = check_typosquatting(
        domain=components["domain"],
        registered_domain=components["registered_domain"],
        full_host=components["hostname"]
    )
    cumulative_score += typo_score
    all_factors.extend(typo_factors)

    # 2. Shannon Entropy Analysis
    entropy_score, entropy_factors = check_shannon_entropy(components)
    cumulative_score += entropy_score
    all_factors.extend(entropy_factors)

    # 3. Structural Anomaly Analysis
    struct_score, struct_factors = check_structural_anomalies(components)
    cumulative_score += struct_score
    all_factors.extend(struct_factors)

    # Bound score between 0 and 100
    final_score = max(0, min(100, cumulative_score))

    # If no factors triggered, add a clean verification factor
    if not all_factors:
        all_factors.append(
            RiskFactor(
                code="HEURISTICS_CLEAN",
                severity=RiskLevel.SAFE,
                message="No structural anomalies, typosquatting patterns, or high-entropy signatures detected."
            )
        )

    return final_score, all_factors, components

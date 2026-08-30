"""Lexical and structural URL feature extraction for Tier 2 Machine Learning pipeline."""

import ipaddress
import re
from typing import Any, Dict, List
from urllib.parse import urlparse
import tldextract

# Standardized feature names in exact matrix column order
FEATURE_NAMES: List[str] = [
    "url_length",
    "dot_count",
    "hyphen_count",
    "underline_count",
    "slash_count",
    "question_count",
    "equal_count",
    "at_count",
    "digit_count",
    "hostname_length",
    "is_ip_address",
    "subdomain_count"
]

IP_V4_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _check_ip_address(host: str) -> int:
    """Check if host string is an IPv4 or IPv6 address."""
    if not host:
        return 0
    clean_host = host.strip("[]").split(":")[0]
    try:
        ipaddress.ip_address(clean_host)
        return 1
    except ValueError:
        pass
    if IP_V4_PATTERN.match(clean_host):
        return 1
    return 0


def extract_url_features(url: str) -> Dict[str, Any]:
    """
    Extract 12 deterministic numerical lexical and structural features from a URL.
    
    Features extracted:
    1. url_length: Total character length of URL.
    2. dot_count: Number of dots ('.').
    3. hyphen_count: Number of hyphens ('-').
    4. underline_count: Number of underlines ('_').
    5. slash_count: Number of slashes ('/').
    6. question_count: Number of question marks ('?').
    7. equal_count: Number of equal signs ('=').
    8. at_count: Number of '@' symbols.
    9. digit_count: Total numeric characters.
    10. hostname_length: Character length of the domain/hostname.
    11. is_ip_address: Boolean (1 or 0) indicating if host is an IPv4/IPv6 address.
    12. subdomain_count: Number of subdomains detected via tldextract.
    """
    clean_url = (url or "").strip()
    if not clean_url:
        return {k: 0 for k in FEATURE_NAMES}

    # Ensure parseable scheme for urllib
    parseable_url = clean_url
    if not (clean_url.startswith("http://") or clean_url.startswith("https://")):
        parseable_url = f"https://{clean_url}"

    parsed = urlparse(parseable_url)
    hostname = (parsed.hostname or parsed.netloc or "").lower().split(":")[0]

    # Subdomain extraction via tldextract
    ext = tldextract.extract(parseable_url)
    if ext.subdomain:
        subdomain_parts = [p for p in ext.subdomain.split(".") if p]
        subdomain_count = len(subdomain_parts)
    else:
        subdomain_count = 0

    features = {
        "url_length": len(clean_url),
        "dot_count": clean_url.count("."),
        "hyphen_count": clean_url.count("-"),
        "underline_count": clean_url.count("_"),
        "slash_count": clean_url.count("/"),
        "question_count": clean_url.count("?"),
        "equal_count": clean_url.count("="),
        "at_count": clean_url.count("@"),
        "digit_count": sum(1 for c in clean_url if c.isdigit()),
        "hostname_length": len(hostname),
        "is_ip_address": _check_ip_address(hostname),
        "subdomain_count": subdomain_count,
    }

    return features


def features_to_vector(features: Dict[str, Any]) -> List[float]:
    """Convert features dict to ordered numerical list matching FEATURE_NAMES."""
    return [float(features.get(name, 0)) for name in FEATURE_NAMES]


def extract_feature_vector(url: str) -> List[float]:
    """Extract features directly into ordered numerical vector."""
    features = extract_url_features(url)
    return features_to_vector(features)

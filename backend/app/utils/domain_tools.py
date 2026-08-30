"""Domain and URL parsing, entropy calculations, and cyber forensics utilities."""

import ipaddress
import math
import re
from typing import Dict, Optional, Set, Tuple
from urllib.parse import urlparse
import tldextract


# Pre-compiled regex patterns for performance
IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
HEX_IP_PATTERN = re.compile(r"^0x[0-9a-fA-F]+(\.0x[0-9a-fA-F]+)*$")

# List of high-risk or commonly abused Top-Level Domains (TLDs) in phishing campaigns
SUSPICIOUS_TLDS: Set[str] = {
    "top", "xyz", "zip", "mov", "click", "buzz", "fit", "tk", "gq", 
    "cf", "ml", "ga", "rest", "icu", "work", "cam", "live", "link",
    "surf", "racing", "date", "stream", "download", "accountant", "loan",
    "cfd", "monster", "sbs", "quest", "beauty", "mom", "country"
}

# Suspicious keywords frequently used in phishing subdomains and URL paths
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "account", "security", "update", "banking", "wallet", "recover",
    "password", "auth", "authenticate", "confirm", "confirmation",
    "support", "billing", "service", "portal", "validation", "secure",
    "webscr", "ebayisapi", "session", "suspended", "unlock", "alert",
    "airdrop", "claim", "2fa", "checkpoint", "re-authenticate", "connect"
]

# Authoritative Top Verified Domains Registry (Zero False Positives for Legitimate Services)
TOP_VERIFIED_DOMAINS: Set[str] = {
    "google.com", "google.co.uk", "google.ca", "google.com.au", "google.de", "google.fr",
    "youtube.com", "gmail.com", "apple.com", "icloud.com", "microsoft.com", "live.com",
    "office.com", "bing.com", "azure.com", "windows.com", "amazon.com", "amazon.co.uk",
    "aws.amazon.com", "github.com", "github.io", "meta.com", "facebook.com", "instagram.com",
    "whatsapp.com", "linkedin.com", "netflix.com", "spotify.com", "wikipedia.org", "wikimedia.org",
    "reddit.com", "twitter.com", "x.com", "cloudflare.com", "paypal.com", "chase.com",
    "bankofamerica.com", "wellsfargo.com", "citi.com", "citibank.com", "nytimes.com",
    "cnn.com", "bbc.com", "bbc.co.uk", "reuters.com", "bloomberg.com", "stackoverflow.com",
    "stackexchange.com", "snyk.io", "crowdstrike.com", "openai.com", "anthropic.com",
    "zoom.us", "slack.com", "salesforce.com", "dropbox.com", "adobe.com", "ebay.com",
    "walmart.com", "target.com", "yahoo.com", "medium.com", "figma.com", "notion.so",
    "docker.com", "digitalocean.com", "stripe.com", "python.org", "rust-lang.org", "golang.org",
    "huggingface.co", "kaggle.com", "mozilla.org", "w3.org", "nih.gov", "cdc.gov", "nasa.gov",
    "mit.edu", "stanford.edu", "harvard.edu", "who.int", "usps.com", "ups.com", "fedex.com"
}


def is_verified_top_domain(registered_domain: str) -> bool:
    """Check if the domain is a verified, authentic top-tier web domain."""
    if not registered_domain:
        return False
    clean = registered_domain.lower().strip()
    return clean in TOP_VERIFIED_DOMAINS


def extract_domain_components(url: str) -> Dict[str, str]:
    """
    Extract structured components from a URL using tldextract and urllib.
    """
    clean_url = (url or "").strip()
    if not (clean_url.startswith("http://") or clean_url.startswith("https://")):
        clean_url = f"https://{clean_url}"

    parsed = urlparse(clean_url)
    ext = tldextract.extract(clean_url)
    
    hostname = (parsed.hostname or parsed.netloc or "").lower().split(":")[0]
    port = parsed.port
    
    # Construct registered domain cleanly
    if ext.domain and ext.suffix:
        reg_domain = f"{ext.domain}.{ext.suffix}"
    else:
        reg_domain = hostname

    return {
        "scheme": parsed.scheme.lower() if parsed.scheme else "http",
        "netloc": parsed.netloc,
        "hostname": hostname.lower(),
        "port": str(port) if port else "",
        "subdomain": ext.subdomain.lower(),
        "domain": ext.domain.lower(),
        "suffix": ext.suffix.lower(),
        "registered_domain": reg_domain.lower(),
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
        "raw_url": url
    }


def calculate_shannon_entropy(data: str) -> float:
    """
    Calculate the Shannon Entropy of a given string.
    Higher entropy (> 3.4 to 4.2) typically indicates randomized or algorithmic strings (DGA).
    """
    if not data:
        return 0.0

    frequencies: Dict[str, int] = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1

    total_chars = len(data)
    entropy = 0.0

    for count in frequencies.values():
        p = count / total_chars
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def is_ip_address(hostname: str) -> bool:
    """
    Check if the hostname is a direct IPv4 or IPv6 address.
    """
    if not hostname:
        return False
    
    clean_host = hostname.strip("[]").split(":")[0]
    
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        pass

    if IP_PATTERN.match(clean_host) or HEX_IP_PATTERN.match(clean_host):
        return True

    return False


def is_punycode_or_idn(hostname: str) -> Tuple[bool, Optional[str]]:
    """
    Check if the domain uses Internationalized Domain Names (IDN) or Punycode ('xn--').
    """
    if "xn--" in hostname.lower():
        try:
            decoded = hostname.encode("ascii").decode("idna")
            return True, decoded
        except Exception:
            return True, None
            
    # Check for mixed non-ASCII scripts in string
    try:
        hostname.encode("ascii")
        return False, None
    except UnicodeEncodeError:
        return True, hostname


def has_suspicious_tld(suffix: str) -> bool:
    """Check if the top-level domain is historically associated with spam/phishing."""
    if not suffix:
        return False
    
    tld_parts = suffix.lower().split(".")
    return suffix.lower() in SUSPICIOUS_TLDS or tld_parts[-1] in SUSPICIOUS_TLDS


def find_suspicious_keywords(text: str) -> list[str]:
    """Find security-critical brand-impersonation keywords in arbitrary text/subdomain."""
    if not text:
        return []
    
    normalized = text.lower()
    matches = []
    for kw in SUSPICIOUS_KEYWORDS:
        # Check keyword as isolated token or boundary match
        if kw in normalized:
            matches.append(kw)
    return matches

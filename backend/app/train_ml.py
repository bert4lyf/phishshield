"""Synthetic dataset generator and XGBoost ML training pipeline for PhishShield AI."""

import json
import logging
import os
import random
from pathlib import Path
from typing import List, Tuple

import numpy as np
import xgboost as xgb

from app.config import settings
from app.pipeline.feature_extractor import FEATURE_NAMES, extract_url_features, features_to_vector

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-7s | %(message)s")
logger = logging.getLogger("phishshield.train_ml")

# Seed for deterministic reproducibility
RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)

LEGIT_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com", "github.com",
    "wikipedia.org", "bbc.co.uk", "nytimes.com", "cnn.com", "stackoverflow.com",
    "mozilla.org", "cloudflare.com", "linkedin.com", "stripe.com", "netflix.com",
    "paypal.com", "adobe.com", "spotify.com", "reddit.com", "medium.com",
    "dropbox.com", "salesforce.com", "zoom.us", "slack.com", "atlassian.com",
    "digitalocean.com", "docker.com", "python.org", "golang.org", "rust-lang.org",
    "openai.com", "anthropic.com", "huggingface.co", "kaggle.com", "nih.gov",
    "mit.edu", "stanford.edu", "harvard.edu", "who.int", "nasa.gov"
]

LEGIT_SUBDOMAINS = ["", "www", "app", "docs", "api", "blog", "developer", "support", "help", "account"]

LEGIT_PATHS = [
    "",
    "/",
    "/about",
    "/about-us",
    "/contact",
    "/products",
    "/docs/quickstart",
    "/docs/api/v2/reference",
    "/blog/2026/08/advances-in-cybersecurity",
    "/pricing",
    "/features",
    "/careers",
    "/terms-of-service",
    "/privacy-policy",
    "/search?q=open+source+security",
    "/dashboard/overview",
    "/settings/profile",
    "/help/article/10492",
    "/download/latest-release",
    "/community/discussions/492"
]

PHISH_BRANDS = [
    "paypal", "paypa1", "pay-pal", "chase", "chase-bank", "wellsfargo", "wells-fargo",
    "bankofamerica", "bofa", "citibank", "citi-online", "metamask", "meta-mask",
    "binance", "binance-us", "coinbase", "coinbase-pro", "appleid", "apple-id",
    "microsoft365", "ms-office", "netflix-verify", "amazon-security", "steam-gift",
    "discord-nitro", "roblox-reward", "ledger-live", "kraken-trade"
]

PHISH_ACTION_WORDS = [
    "login", "signin", "verify", "verification", "secure", "security", "security-update",
    "account-suspended", "unlock-wallet", "restore-access", "confirm-identity",
    "billing-declined", "kyc-approval", "seed-phrase-recovery", "2fa-bypass",
    "urgent-notice", "auth-token", "validate-card", "re-authenticate", "checkpoint"
]

SUSPICIOUS_TLDS_LIST = [
    "xyz", "top", "icu", "buzz", "rest", "tk", "ml", "ga", "cf", "gq",
    "click", "cam", "fit", "work", "loan", "stream", "download", "racing"
]

SAMPLE_IPS = [
    "192.168.1.50", "192.168.1.100", "45.33.32.156", "103.22.45.12", "185.220.101.5",
    "198.51.100.42", "203.0.113.195", "91.240.118.172", "194.26.29.112",
    "89.208.103.45", "104.244.76.104", "172.67.182.91", "216.58.214.206"
]


def generate_legitimate_url() -> str:
    """Generate a realistic legitimate URL structure."""
    protocol = random.choice(["https://", "https://", "https://", "http://"])
    domain = random.choice(LEGIT_DOMAINS)
    sub = random.choice(LEGIT_SUBDOMAINS)
    
    if sub and sub != "www":
        host = f"{sub}.{domain}"
    elif sub == "www":
        host = f"www.{domain}"
    else:
        host = domain

    path = random.choice(LEGIT_PATHS)
    # Occasionally append legitimate query parameters
    if path and random.random() < 0.25:
        path += f"?id={random.randint(10, 999)}&ref={random.choice(['home', 'nav', 'app'])}"
    return f"{protocol}{host}{path}"


def generate_phishing_url() -> str:
    """Generate an adversarial synthetic phishing / scam URL structure."""
    mode = random.choices(["typosquat", "raw_ip", "deep_subdomain", "obfuscated", "dga"], weights=[40, 20, 20, 10, 10])[0]
    protocol = random.choice(["http://", "https://"])
    
    if mode == "raw_ip":
        ip = random.choice(SAMPLE_IPS)
        brand = random.choice(PHISH_BRANDS)
        action = random.choice(PHISH_ACTION_WORDS)
        if random.random() < 0.5:
            path = f"/{brand}/{action}"
        else:
            path = f"/{brand}/{action}.php?session_id={random.randint(100000, 999999)}"
        return f"{protocol}{ip}{path}"

    elif mode == "deep_subdomain":
        brand = random.choice(PHISH_BRANDS)
        action = random.choice(PHISH_ACTION_WORDS)
        fake_tld = random.choice(["com", "net", "org"])
        suspicious_domain = f"portal-{random.randint(10, 99)}.{random.choice(SUSPICIOUS_TLDS_LIST + ['net', 'com', 'org'])}"
        subdomains = f"{brand}.{action}.service" if random.random() < 0.5 else f"{brand}.{fake_tld}.{action}"
        return f"{protocol}{subdomains}.{suspicious_domain}/auth?id={random.randint(1000, 9999)}"

    elif mode == "obfuscated":
        brand = random.choice(PHISH_BRANDS)
        action = random.choice(PHISH_ACTION_WORDS)
        tld = random.choice(SUSPICIOUS_TLDS_LIST + ["com", "online"])
        user_info = f"user{random.randint(100, 999)}:pass@" if random.random() < 0.5 else ""
        domain = f"{brand}-{action}-portal.{tld}"
        query = f"?redirect=https://www.google.com&token={random.randint(10000, 99999)}"
        return f"{protocol}{user_info}{domain}/login{query}"

    elif mode == "dga":
        # Random DGA-style domain with high symbol/character entropy
        chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        dga_name = "".join(random.choice(chars) for _ in range(random.randint(12, 22)))
        tld = random.choice(SUSPICIOUS_TLDS_LIST)
        return f"{protocol}{dga_name}.{tld}/account/verify"

    else: # typosquat & brand keyword combinations (short & medium length)
        brand = random.choice(PHISH_BRANDS)
        action = random.choice(PHISH_ACTION_WORDS)
        tld = random.choice(SUSPICIOUS_TLDS_LIST + ["com", "net", "org", "info", "online", "site"])
        delimiter = random.choice(["-", "--", ""])
        domain = f"{brand}{delimiter}{action}.{tld}"
        has_www = random.choice(["www.", ""])
        path = random.choice(["/login", "/signin", "/verify", "/update", "/account", "/"])
        return f"{protocol}{has_www}{domain}{path}"


def build_synthetic_dataset(num_samples: int = 1200) -> Tuple[List[str], List[int]]:
    """Generate a balanced synthetic dataset of legitimate (0) and phishing (1) URLs."""
    half = num_samples // 2
    urls: List[str] = []
    labels: List[int] = []

    # Legitimate samples (0)
    for _ in range(half):
        urls.append(generate_legitimate_url())
        labels.append(0)

    # Phishing samples (1)
    for _ in range(num_samples - half):
        urls.append(generate_phishing_url())
        labels.append(1)

    # Specific benchmark corner cases
    benchmark_phish = [
        "https://www.paypa1-security.com/login",
        "http://192.168.1.50/bankofamerica/signin",
        "http://xkjq9823nmzpa91823.top/account",
        "https://paypal.account-verification-portal.net/auth",
        "http://192.168.1.100/chase/signin",
        "https://microsoft.com.account-update.xyz/verify",
        "https://meta-mask-wallet-seed-recovery.top/connect",
        "https://binance-kyc-validation-auth.rest/login"
    ]
    for p_url in benchmark_phish:
        urls.append(p_url)
        labels.append(1)

    benchmark_legit = [
        "https://www.google.com",
        "https://www.google.com/search?q=test",
        "https://github.com/torvalds/linux",
        "https://docs.python.org/3/library/unittest.html",
        "https://en.wikipedia.org/wiki/Phishing",
        "https://www.amazon.com/gp/bestsellers",
        "https://stripe.com/docs/api",
        "https://apple.com/iphone"
    ]
    for l_url in benchmark_legit:
        urls.append(l_url)
        labels.append(0)

    # Shuffle dataset
    combined = list(zip(urls, labels))
    random.shuffle(combined)
    shuffled_urls, shuffled_labels = zip(*combined)

    return list(shuffled_urls), list(shuffled_labels)


def train_and_save_model(output_path: Path = settings.ML_MODEL_PATH) -> xgb.XGBClassifier:
    """
    Train Tier 2 XGBoost classifier on extracted URL features and save model.json.
    """
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

    logger.info("Generating synthetic training dataset of URLs...")
    urls, labels = build_synthetic_dataset(num_samples=1200)

    logger.info(f"Extracting 12 lexical features across {len(urls)} samples...")
    X_list = [features_to_vector(extract_url_features(url)) for url in urls]
    X = np.array(X_list, dtype=np.float32)
    y = np.array(labels, dtype=np.int32)

    # Train / Test split (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
    )

    logger.info(f"Training dataset: {X_train.shape[0]} samples | Testing dataset: {X_test.shape[0]} samples")

    # Train XGBoost Classifier
    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        subsample=0.9,
        colsample_bytree=0.9,
        random_state=RANDOM_SEED,
        eval_metric="logloss"
    )

    logger.info("Fitting XGBoost Classifier...")
    model.fit(X_train, y_train)

    # Evaluate model
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    logger.info("=" * 60)
    logger.info("TIER 2 XGBOOST MODEL EVALUATION REPORT:")
    logger.info(f"Accuracy : {acc * 100:.2f}%")
    logger.info(f"Precision: {prec * 100:.2f}%")
    logger.info(f"Recall   : {rec * 100:.2f}%")
    logger.info(f"F1-Score : {f1 * 100:.2f}%")
    logger.info("=" * 60)

    # Feature Importances
    importances = model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    logger.info("TOP FEATURE IMPORTANCES:")
    for rank, idx in enumerate(sorted_idx, start=1):
        logger.info(f"  {rank:2d}. {FEATURE_NAMES[idx]:<18} : {importances[idx] * 100:5.2f}%")
    logger.info("=" * 60)

    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Save model in standard XGBoost JSON format
    logger.info(f"Saving trained model to: {output_path}")
    model.save_model(str(output_path))
    logger.info(f"Successfully saved {output_path.name} ({os.path.getsize(output_path)} bytes)")

    return model


if __name__ == "__main__":
    train_and_save_model()

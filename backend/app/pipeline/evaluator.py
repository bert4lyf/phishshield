"""Pipeline orchestrator for PhishShield AI combining Heuristics, XGBoost ML, and Gemini AI."""

import logging
import time
from typing import List, Tuple

from app.config import settings
from app.pipeline.ai_context import analyze_with_gemini, generate_fallback_summary
from app.pipeline.heuristics import run_heuristic_pipeline
from app.pipeline.ml_model import get_ml_model
from app.schemas import RiskFactor, RiskLevel, ScanRequest, ScanResponse, TierBreakdown
from app.utils.domain_tools import is_verified_top_domain

logger = logging.getLogger("phishshield.evaluator")


def score_to_risk_level(score: int) -> RiskLevel:
    """Map aggregate numerical risk score (0-100) to standard RiskLevel enum."""
    if score <= settings.SAFE_MAX_SCORE:
        return RiskLevel.SAFE
    elif score <= settings.LOW_MAX_SCORE:
        return RiskLevel.LOW
    elif score <= settings.MEDIUM_MAX_SCORE:
        return RiskLevel.MEDIUM
    elif score <= settings.HIGH_MAX_SCORE:
        return RiskLevel.HIGH
    else:
        return RiskLevel.CRITICAL


def score_to_verdict(level: RiskLevel) -> str:
    """Generate concise verdict headline for security card and extension badge."""
    verdict_map = {
        RiskLevel.SAFE: "Verified Safe Link",
        RiskLevel.LOW: "Low Suspicion - Minimal Risk",
        RiskLevel.MEDIUM: "Caution - Suspicious Anomalies Detected",
        RiskLevel.HIGH: "Phishing / Impersonation Alert",
        RiskLevel.CRITICAL: "Malicious Scam Threat Blocked"
    }
    return verdict_map.get(level, "Security Scan Complete")


async def evaluate_link(request: ScanRequest) -> ScanResponse:
    """
    Execute the multi-tier PhishShield AI security evaluation pipeline.
    
    1. Tier 1: Executes deterministic heuristic & entropy threat models (35% weight).
    2. Tier 2: Executes XGBoost lexical ML model on 12 URL features (45% weight).
    3. Tier 3: Conditionally executes Gemini contextual AI on ambiguous scores or page DOM (20% weight).
    4. Multi-Engine Fusion: Computes weighted composite risk score:
       Final Risk Score = (Heuristic * 0.35) + (ML * 0.45) + (AI * 0.20)
    5. Returns unified ScanResponse with tier breakdown and explainability reasoning.
    """
    start_time = time.perf_counter()

    # -------------------------------------------------------------
    # Step 1: Tier 1 - Heuristic Threat Modeling (Weight: 35%)
    # -------------------------------------------------------------
    base_heuristic_score, heuristic_factors, domain_comp = run_heuristic_pipeline(request.url)
    heuristic_score = max(0, min(100, int(base_heuristic_score)))
    registered_domain = domain_comp.get("registered_domain", "")

    # -------------------------------------------------------------
    # Step 2: Tier 2 - XGBoost ML Inference (Weight: 45%)
    # -------------------------------------------------------------
    ml_engine = get_ml_model()
    raw_ml_prob = ml_engine.predict_risk_score(request.url)
    ml_score = max(0, min(100, int(round(raw_ml_prob))))

    # Protection: If domain is a verified authoritative top domain without structural hacks, clamp ML to 0
    if is_verified_top_domain(registered_domain) and heuristic_score == 0:
        ml_score = 0

    # Add ML-detected factor if ML risk is elevated
    combined_factors: List[RiskFactor] = list(heuristic_factors)
    if ml_score >= 80 and not any(f.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL) for f in heuristic_factors):
        combined_factors.append(
            RiskFactor(
                code="ML_CLASSIFIER_ANOMALY_HIGH",
                severity=RiskLevel.HIGH,
                message="Tier 2 XGBoost model identified high-probability structural/lexical phishing signatures."
            )
        )
    elif ml_score >= 50 and not any(f.code.startswith("ML_") for f in combined_factors):
        combined_factors.append(
            RiskFactor(
                code="ML_CLASSIFIER_SUSPICIOUS",
                severity=RiskLevel.MEDIUM,
                message="Tier 2 XGBoost model detected lexical anomalies in domain structure or token composition."
            )
        )

    # -------------------------------------------------------------
    # Step 3: Tier 3 - Contextual AI Analysis (Weight: 20%)
    # -------------------------------------------------------------
    is_ambiguous = (30 <= heuristic_score <= 75) or (30 <= ml_score <= 75)
    has_page_content = bool(request.page_text and len(request.page_text.strip()) > 10)
    should_run_ai = (is_ambiguous or has_page_content) and not (is_verified_top_domain(registered_domain) and heuristic_score == 0)

    ai_score_delta = 0
    explainability_summary = ""

    if should_run_ai:
        ai_score_delta, ai_factors, explainability_summary = await analyze_with_gemini(
            url=request.url,
            domain_comp=domain_comp,
            base_score=heuristic_score,
            heuristic_factors=heuristic_factors,
            page_text=request.page_text
        )
        combined_factors.extend(ai_factors)
        ai_score = max(0, min(100, heuristic_score + ai_score_delta))
    else:
        if is_verified_top_domain(registered_domain) and heuristic_score == 0:
            ai_score = 0
            domain_name = registered_domain or request.url
            explainability_summary = f"The destination '{domain_name}' is a verified legitimate web domain with no observed risk indicators."
        else:
            ai_score = int(round((heuristic_score * 0.5) + (ml_score * 0.5)))
            domain_name = registered_domain or domain_comp.get("hostname") or request.url
            explainability_summary = generate_fallback_summary(
                max(heuristic_score, ml_score), combined_factors, domain_name
            )

    # -------------------------------------------------------------
    # Step 4: Multi-Engine Weighted Score Fusion
    # Formula: Final = (Heuristic * 0.35) + (ML * 0.45) + (AI * 0.20)
    # -------------------------------------------------------------
    if is_verified_top_domain(registered_domain) and heuristic_score == 0:
        final_score = 0
    else:
        composite_raw = (
            (heuristic_score * settings.WEIGHT_HEURISTICS) +
            (ml_score * settings.WEIGHT_ML) +
            (ai_score * settings.WEIGHT_AI)
        )
        final_score = int(round(composite_raw))
        # If heuristics found a critical threat (like IP host, brand in subdomain, typosquatting), ensure score stays critical
        if heuristic_score >= 80:
            final_score = max(final_score, heuristic_score)

    final_score = max(0, min(100, final_score))
    risk_level = score_to_risk_level(final_score)
    verdict = score_to_verdict(risk_level)

    # Measure execution latency
    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

    tier_breakdown = TierBreakdown(
        heuristic_score=heuristic_score,
        ml_score=ml_score,
        ai_score=ai_score
    )

    return ScanResponse(
        url=request.url,
        risk_score=final_score,
        risk_level=risk_level,
        verdict=verdict,
        explainability_summary=explainability_summary,
        detected_factors=combined_factors,
        scan_latency_ms=latency_ms,
        tier_breakdown=tier_breakdown
    )

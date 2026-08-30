"""Contextual AI Security Analyst powered by Google Gemini (google-genai SDK)."""

import json
import logging
from typing import Any, List, Optional, Tuple

try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None
    types = None

from app.config import settings
from app.schemas import RiskFactor, RiskLevel

logger = logging.getLogger("phishshield.ai_context")

# Initialize Gemini Client if API key is provided
_gemini_client: Optional[Any] = None

def get_gemini_client():
    """Retrieve or initialize singleton Google GenAI client."""
    global _gemini_client
    if genai is None:
        return None
    if _gemini_client is None and settings.GEMINI_API_KEY:
        try:
            _gemini_client = genai.Client(api_key=settings.GEMINI_API_KEY)
            logger.info("Google GenAI client initialized successfully.")
        except Exception as e:
            logger.warning(f"Failed to initialize Google GenAI client: {e}")
            _gemini_client = None
    return _gemini_client


SYSTEM_INSTRUCTION = """You are PhishShield AI's Principal Cyber Threat Analyst.
Analyze the target URL, domain structure, and any extracted webpage content for phishing, scam, and social engineering indicators.

Look specifically for:
1. Urgency and panic triggers (e.g. 'account suspended within 24 hours', 'unauthorized access detected').
2. Credential harvesting forms, seed phrase requests, or banking OTP extraction attempts.
3. Brand impersonation, fake tech support, or fraudulent crypto giveaways.
4. Deceptive domain mimicry and obfuscation.

You must output a valid JSON object matching this schema:
{
  "ai_risk_score_delta": <integer between -20 and +50 to adjust base score>,
  "social_engineering_detected": <boolean>,
  "explainability_summary": "<Exactly 2 concise, non-technical, plain-English sentences explaining the safety or danger of this link to an everyday user>",
  "identified_threats": [
    {
      "code": "<string identifier, e.g. URGENCY_PSYCHOLOGICAL_PRESSURE>",
      "severity": "<SAFE|LOW|MEDIUM|HIGH|CRITICAL>",
      "message": "<Clear explanation of the observed social engineering pattern>"
    }
  ]
}
"""


def generate_fallback_summary(score: int, factors: List[RiskFactor], domain_name: str) -> str:
    """Generate deterministic plain-English 2-sentence summary when AI is offline or bypassed."""
    if score >= 75 or any(f.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL) for f in factors):
        threat_reasons = [f.message for f in factors if f.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL)]
        primary_reason = threat_reasons[0] if threat_reasons else "suspicious domain patterns and brand spoofing"
        return f"Warning: This link targeting '{domain_name}' exhibits deceptive characteristics ({primary_reason}). Do not enter passwords, credit card details, or personal credentials on this destination."
    
    if score >= 30:
        return f"Caution: '{domain_name}' presents moderate risk factors that warrant vigilance. Verify the web address carefully before interacting or providing any sensitive information."
    
    return f"This link to '{domain_name}' appears structurally consistent and safe with no common phishing signatures detected. Always verify the browser address bar before submitting confidential credentials."


async def analyze_with_gemini(
    url: str,
    domain_comp: dict,
    base_score: int,
    heuristic_factors: List[RiskFactor],
    page_text: Optional[str] = None
) -> Tuple[int, List[RiskFactor], str]:
    """
    Perform deep AI linguistic and social engineering threat analysis using Gemini.
    
    Returns:
        (score_delta: int, ai_factors: List[RiskFactor], explainability_summary: str)
    """
    client = get_gemini_client()
    domain_name = domain_comp.get("registered_domain") or domain_comp.get("hostname") or url

    # If Gemini client is not configured, gracefully generate deterministic summary
    if not client:
        summary = generate_fallback_summary(base_score, heuristic_factors, domain_name)
        return 0, [], summary

    # Prepare analysis prompt
    heuristic_summary = [f"[{f.severity.value}] {f.code}: {f.message}" for f in heuristic_factors]
    prompt_payload = {
        "url": url,
        "domain": domain_comp.get("domain"),
        "registered_domain": domain_comp.get("registered_domain"),
        "subdomain": domain_comp.get("subdomain"),
        "path": domain_comp.get("path"),
        "base_heuristic_score": base_score,
        "detected_heuristic_factors": heuristic_summary,
        "extracted_page_content": page_text[:2000] if page_text else "No DOM text supplied."
    }

    user_prompt = f"Analyze this candidate link and page content:\n{json.dumps(prompt_payload, indent=2)}"

    try:
        response = client.models.generate_content(
            model=settings.GEMINI_MODEL,
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTION,
                response_mime_type="application/json",
                temperature=0.2,
            )
        )

        response_text = response.text
        if not response_text:
            raise ValueError("Empty response from Gemini")

        parsed = json.loads(response_text)
        score_delta = int(parsed.get("ai_risk_score_delta", 0))
        summary = str(parsed.get("explainability_summary", "")).strip()

        if not summary:
            summary = generate_fallback_summary(base_score + score_delta, heuristic_factors, domain_name)

        ai_factors: List[RiskFactor] = []
        for t in parsed.get("identified_threats", []):
            try:
                sev_str = str(t.get("severity", "MEDIUM")).upper()
                severity = RiskLevel(sev_str) if sev_str in RiskLevel.__members__ else RiskLevel.MEDIUM
                ai_factors.append(
                    RiskFactor(
                        code=str(t.get("code", "AI_SOCIAL_ENGINEERING_MARKER")),
                        severity=severity,
                        message=str(t.get("message", "Suspicious psychological manipulation or credential lure detected."))
                    )
                )
            except Exception:
                continue

        return score_delta, ai_factors, summary

    except Exception as e:
        logger.error(f"Gemini contextual evaluation failed: {e}. Falling back to deterministic analysis.")
        fallback_summary = generate_fallback_summary(base_score, heuristic_factors, domain_name)
        return 0, [], fallback_summary

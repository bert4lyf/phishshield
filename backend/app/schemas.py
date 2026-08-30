"""Pydantic data schemas for PhishShield AI API request and response contracts."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, HttpUrl, field_validator


class RiskLevel(str, Enum):
    """Normalized threat classification levels."""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskFactor(BaseModel):
    """Specific vulnerability or suspicious heuristic anomaly identified in the link."""
    code: str = Field(..., description="Unique machine-readable identifier for the risk factor (e.g. TYPOSQUATTING_TARGET)")
    severity: RiskLevel = Field(..., description="Individual risk severity level of the identified factor")
    message: str = Field(..., description="Human-readable explanation of why this factor is considered risky")


class ScanRequest(BaseModel):
    """Payload sent by Chrome extension or client to inspect a URL."""
    url: str = Field(..., description="The target URL to be analyzed for phishing/scam patterns")
    page_text: Optional[str] = Field(None, description="Optional text content extracted from the webpage for contextual AI analysis")
    user_id: Optional[str] = Field(None, description="Optional anonymous identifier for rate-limiting or analytics")

    @field_validator("url")
    @classmethod
    def validate_url_format(cls, v: str) -> str:
        """Sanitize and validate URL input."""
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        if not (v.startswith("http://") or v.startswith("https://")):
            # Prepend https for naked domains passed by users
            v = f"https://{v}"
        return v


class TierBreakdown(BaseModel):
    """Detailed score breakdown across all three inspection tiers."""
    heuristic_score: int = Field(..., ge=0, le=100, description="Tier 1 Heuristic threat model score (0-100)")
    ml_score: int = Field(..., ge=0, le=100, description="Tier 2 XGBoost ML probability risk score (0-100)")
    ai_score: int = Field(..., ge=0, le=100, description="Tier 3 Gemini AI contextual risk score (0-100)")


class ScanResponse(BaseModel):
    """Complete diagnostic report and verdict returned by PhishShield AI."""
    url: str = Field(..., description="The analyzed URL")
    risk_score: int = Field(..., ge=0, le=100, description="Aggregate security risk score from 0 (harmless) to 100 (lethal)")
    risk_level: RiskLevel = Field(..., description="Overall risk classification")
    verdict: str = Field(..., description="High-level security verdict (e.g. 'Phishing Threat Detected', 'Safe Link')")
    explainability_summary: str = Field(..., description="2-sentence non-technical plain-English summary explaining the reasoning")
    detected_factors: List[RiskFactor] = Field(default_factory=list, description="List of all detected heuristic and contextual risk factors")
    scan_latency_ms: float = Field(..., description="Total pipeline execution latency in milliseconds")
    tier_breakdown: Optional[TierBreakdown] = Field(None, description="Detailed 3-tier scoring breakdown")


class ThreatReportCreate(BaseModel):
    """Payload for submitting a community scam threat report."""
    url: str = Field(..., description="The suspicious URL being reported")
    reason: str = Field(..., min_length=3, description="Description or reason why this link is malicious")
    reporter_id: Optional[str] = Field(None, description="Optional reporter identifier")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        if not (v.startswith("http://") or v.startswith("https://")):
            v = f"https://{v}"
        return v


class ThreatReportResponse(BaseModel):
    """Response payload for a registered community threat report."""
    id: int = Field(..., description="Unique report identifier")
    url: str = Field(..., description="Reported URL")
    reason: str = Field(..., description="Report reason")
    reporter_id: Optional[str] = Field(None, description="Reporter ID")
    created_at: str = Field(..., description="ISO 8601 creation timestamp")


class ScanLogResponse(BaseModel):
    """Telemetry log entry of a historical scan event."""
    id: int = Field(..., description="Log ID")
    url: str = Field(..., description="Scanned target URL")
    risk_score: int = Field(..., description="Computed composite risk score")
    risk_level: str = Field(..., description="Risk level classification")
    verdict: str = Field(..., description="Engine security verdict")
    latency_ms: float = Field(..., description="Evaluation latency in milliseconds")
    heuristic_score: Optional[int] = Field(0, description="Tier 1 Heuristics score")
    ml_score: Optional[int] = Field(0, description="Tier 2 ML score")
    ai_score: Optional[int] = Field(0, description="Tier 3 AI score")
    explainability_summary: Optional[str] = Field(None, description="Summary of reasoning")
    timestamp: str = Field(..., description="ISO 8601 timestamp of scan event")


class AnalyticsStatsResponse(BaseModel):
    """Real-time engine telemetry and aggregate metrics for SOC dashboard."""
    total_scans: int = Field(..., description="Total number of scans performed")
    threats_intercepted: int = Field(..., description="Total threats intercepted (HIGH & CRITICAL risk)")
    avg_latency_ms: float = Field(..., description="Average engine response time in milliseconds")
    risk_breakdown: dict[str, int] = Field(..., description="Count breakdown by RiskLevel")
    total_community_reports: int = Field(..., description="Total registered community threat reports")


class HealthResponse(BaseModel):
    """API health status and diagnostic response."""
    status: str = Field("healthy", description="Operational status of the API server")
    version: str = Field("1.0.0", description="API Version")
    gemini_ai_enabled: bool = Field(..., description="True if Gemini API key is configured and active")
    ml_model_loaded: bool = Field(..., description="True if Tier 2 XGBoost model is loaded")
    environment: str = Field("development", description="Server environment")

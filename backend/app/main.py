"""Main FastAPI Application entrypoint for PhishShield AI Security Engine."""

import sys
import os
from pathlib import Path

# Ensure backend directory and project root are in sys.path
_current_file = Path(__file__).resolve()
_backend_dir = _current_file.parent.parent
_root_dir = _backend_dir.parent

for _p in (str(_backend_dir), str(_root_dir)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db, init_db, SessionLocal
from app.models import ScanLog, ThreatReport
from app.pipeline.ai_context import get_gemini_client
from app.pipeline.evaluator import evaluate_link
from app.pipeline.ml_model import get_ml_model
from app.schemas import (
    AnalyticsStatsResponse,
    HealthResponse,
    RiskLevel,
    ScanLogResponse,
    ScanRequest,
    ScanResponse,
    ThreatReportCreate,
    ThreatReportResponse,
)

# Setup Structured Logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
)
logger = logging.getLogger("phishshield.main")


def log_scan_event_sync(
    url: str,
    risk_score: int,
    risk_level: str,
    verdict: str,
    latency_ms: float,
    heuristic_score: int = 0,
    ml_score: int = 0,
    ai_score: int = 0,
    explainability_summary: str = ""
) -> None:
    """Save a scan event to SQLite database."""
    db = SessionLocal()
    try:
        log_entry = ScanLog(
            url=url,
            risk_score=risk_score,
            risk_level=risk_level,
            verdict=verdict,
            latency_ms=latency_ms,
            heuristic_score=heuristic_score,
            ml_score=ml_score,
            ai_score=ai_score,
            explainability_summary=explainability_summary,
            timestamp=datetime.now(timezone.utc)
        )
        db.add(log_entry)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to log scan event to database for '{url}': {e}", exc_info=True)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle management."""
    logger.info(f"Starting {settings.PROJECT_NAME} v{settings.VERSION} on {settings.HOST}:{settings.PORT}")
    
    try:
        # Initialize SQLite tables
        init_db()
    except Exception as e:
        logger.warning(f"Database initialization warning in serverless environment: {e}")
    
    try:
        # Initialize ML Model
        ml_model = get_ml_model()
        if ml_model.is_loaded:
            logger.info("Tier 2 XGBoost ML Model loaded and ready for inference.")
        else:
            logger.warning("Tier 2 XGBoost model using heuristic fallback.")
    except Exception as e:
        logger.warning(f"ML model startup warning: {e}")

    try:
        # Initialize Gemini AI Engine
        gemini_client = get_gemini_client()
        if gemini_client:
            logger.info(f"Gemini AI Engine active with model: {settings.GEMINI_MODEL}")
        else:
            logger.info("Running in Heuristics+ML mode.")
    except Exception as e:
        logger.warning(f"Gemini AI client startup warning: {e}")
        
    yield
    logger.info("Shutting down PhishShield AI Security Engine.")


# Instantiate FastAPI application
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Real-time multi-tier heuristic, XGBoost ML, and Gemini AI phishing and scam URL detection engine.",
    lifespan=lifespan
)

# Enable CORS for dashboard, browser extensions, and external clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse, tags=["Diagnostics"])
async def health_check():
    """Liveness and readiness health probe returning engine status and AI/ML connectivity."""
    ml_model = get_ml_model()
    return HealthResponse(
        status="healthy",
        version=settings.VERSION,
        gemini_ai_enabled=bool(settings.GEMINI_API_KEY),
        ml_model_loaded=ml_model.is_loaded,
        environment=settings.ENVIRONMENT
    )


@app.post("/api/v1/scan", response_model=ScanResponse, tags=["Security Engine"])
async def scan_url(request: ScanRequest):
    """
    Inspect a target URL using Tier 1 Heuristics, Tier 2 XGBoost ML, and Tier 3 Gemini AI.
    
    Persists scan telemetry asynchronously into the SQLite database.
    """
    try:
        logger.info(f"Received scan request for URL: {request.url}")
        result = await evaluate_link(request)
        logger.info(
            f"Evaluated '{request.url}' -> Risk Score: {result.risk_score} ({result.risk_level.value}) in {result.scan_latency_ms}ms"
        )
        
        # Asynchronously log scan telemetry to SQLite
        h_score = result.tier_breakdown.heuristic_score if result.tier_breakdown else 0
        m_score = result.tier_breakdown.ml_score if result.tier_breakdown else 0
        a_score = result.tier_breakdown.ai_score if result.tier_breakdown else 0

        asyncio.create_task(
            asyncio.to_thread(
                log_scan_event_sync,
                url=result.url,
                risk_score=result.risk_score,
                risk_level=result.risk_level.value,
                verdict=result.verdict,
                latency_ms=result.scan_latency_ms,
                heuristic_score=h_score,
                ml_score=m_score,
                ai_score=a_score,
                explainability_summary=result.explainability_summary
            )
        )

        return result
    except ValueError as ve:
        logger.warning(f"Validation error scanning URL '{request.url}': {ve}")
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(ve))
    except Exception as e:
        logger.error(f"Unexpected error processing scan request for '{request.url}': {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while evaluating the security of the provided link."
        )


@app.post("/api/v1/report", response_model=ThreatReportResponse, status_code=status.HTTP_201_CREATED, tags=["Community Intelligence"])
async def submit_threat_report(report: ThreatReportCreate, db: Session = Depends(get_db)):
    """
    Submit a suspicious scam or phishing link to community threat intelligence.
    """
    try:
        logger.info(f"Received community threat report for URL: {report.url}")
        db_report = ThreatReport(
            url=report.url,
            reason=report.reason,
            reporter_id=report.reporter_id or "anonymous-user",
            created_at=datetime.now(timezone.utc)
        )
        db.add(db_report)
        db.commit()
        db.refresh(db_report)
        
        return ThreatReportResponse(
            id=db_report.id,
            url=db_report.url,
            reason=db_report.reason,
            reporter_id=db_report.reporter_id,
            created_at=db_report.created_at.isoformat()
        )
    except Exception as e:
        db.rollback()
        logger.error(f"Error registering threat report for '{report.url}': {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register community threat report."
        )


@app.get("/api/v1/analytics/recent", response_model=List[ScanLogResponse], tags=["Analytics & SOC"])
async def get_recent_scans(limit: int = 20, db: Session = Depends(get_db)):
    """
    Retrieve the last N scanned URLs with their computed risk scores and verdicts.
    """
    try:
        records = (
            db.query(ScanLog)
            .order_by(desc(ScanLog.timestamp))
            .limit(min(limit, 100))
            .all()
        )
        return [
            ScanLogResponse(
                id=r.id,
                url=r.url,
                risk_score=r.risk_score,
                risk_level=r.risk_level,
                verdict=r.verdict,
                latency_ms=r.latency_ms,
                heuristic_score=r.heuristic_score or 0,
                ml_score=r.ml_score or 0,
                ai_score=r.ai_score or 0,
                explainability_summary=r.explainability_summary,
                timestamp=r.timestamp.isoformat() if r.timestamp else datetime.utcnow().isoformat()
            )
            for r in records
        ]
    except Exception as e:
        logger.error(f"Error fetching recent scans: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve recent scans.")


@app.get("/api/v1/analytics/stats", response_model=AnalyticsStatsResponse, tags=["Analytics & SOC"])
async def get_analytics_stats(db: Session = Depends(get_db)):
    """
    Compute live security operations metrics: Total Scans, Threats Intercepted, Avg Latency, and Breakdown.
    """
    try:
        total_scans = db.query(func.count(ScanLog.id)).scalar() or 0
        threats_intercepted = (
            db.query(func.count(ScanLog.id))
            .filter(ScanLog.risk_level.in_(["HIGH", "CRITICAL"]))
            .scalar() or 0
        )
        avg_latency = (
            db.query(func.avg(ScanLog.latency_ms)).scalar() or 0.0
        )
        
        # Risk level counts
        breakdown_rows = (
            db.query(ScanLog.risk_level, func.count(ScanLog.id))
            .group_by(ScanLog.risk_level)
            .all()
        )
        risk_breakdown = {"SAFE": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for level, count in breakdown_rows:
            if level in risk_breakdown:
                risk_breakdown[level] = count

        total_reports = db.query(func.count(ThreatReport.id)).scalar() or 0

        return AnalyticsStatsResponse(
            total_scans=total_scans,
            threats_intercepted=threats_intercepted,
            avg_latency_ms=round(float(avg_latency), 2),
            risk_breakdown=risk_breakdown,
            total_community_reports=total_reports
        )
    except Exception as e:
        logger.error(f"Error computing analytics statistics: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to calculate telemetry statistics.")


@app.get("/api/v1/reports", response_model=List[ThreatReportResponse], tags=["Community Intelligence"])
async def list_threat_reports(limit: int = 20, db: Session = Depends(get_db)):
    """
    Retrieve recent community-submitted threat reports.
    """
    try:
        reports = (
            db.query(ThreatReport)
            .order_by(desc(ThreatReport.created_at))
            .limit(min(limit, 100))
            .all()
        )
        return [
            ThreatReportResponse(
                id=r.id,
                url=r.url,
                reason=r.reason,
                reporter_id=r.reporter_id,
                created_at=r.created_at.isoformat() if r.created_at else datetime.utcnow().isoformat()
            )
            for r in reports
        ]
    except Exception as e:
        logger.error(f"Error fetching threat reports: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch threat reports.")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global fallback exception handler ensuring clean JSON error responses."""
    logger.error(f"Unhandled exception during {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error occurred within PhishShield AI security engine."}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=True)

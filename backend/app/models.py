from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Float, Integer, String, Text
from app.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class ScanLog(Base):
    """Telemetry log record for every link scanned by PhishShield AI."""
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    url = Column(String(2048), nullable=False, index=True)
    risk_score = Column(Integer, nullable=False, index=True)
    risk_level = Column(String(32), nullable=False, index=True)
    verdict = Column(String(255), nullable=False)
    latency_ms = Column(Float, nullable=False)
    heuristic_score = Column(Integer, nullable=True, default=0)
    ml_score = Column(Integer, nullable=True, default=0)
    ai_score = Column(Integer, nullable=True, default=0)
    explainability_summary = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=utc_now, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "url": self.url,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "verdict": self.verdict,
            "latency_ms": self.latency_ms,
            "heuristic_score": self.heuristic_score,
            "ml_score": self.ml_score,
            "ai_score": self.ai_score,
            "explainability_summary": self.explainability_summary,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }


class ThreatReport(Base):
    """Community-submitted threat reports for manual review and intelligence feeds."""
    __tablename__ = "threat_reports"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    url = Column(String(2048), nullable=False, index=True)
    reason = Column(Text, nullable=False)
    reporter_id = Column(String(255), nullable=True, index=True)
    created_at = Column(DateTime, default=utc_now, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "url": self.url,
            "reason": self.reason,
            "reporter_id": self.reporter_id,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

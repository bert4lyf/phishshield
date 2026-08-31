"""Database engine and session management for PhishShield AI using SQLAlchemy and SQLite."""

import os
import logging
from pathlib import Path
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from app.config import settings

logger = logging.getLogger("phishshield.database")

# Serverless Storage Resolution
is_serverless = bool(
    os.getenv("VERCEL")
    or os.getenv("AWS_LAMBDA_FUNCTION_NAME")
    or os.getenv("LAMBDA_TASK_ROOT")
)

if is_serverless:
    db_path = Path("/tmp/phishshield.db")
    db_url = os.getenv("DATABASE_URL", "sqlite:////tmp/phishshield.db")
else:
    db_path = settings.SQLITE_DB_PATH
    db_url = settings.DATABASE_URL

# Ensure parent directory for database exists and is writable
try:
    db_path.parent.mkdir(parents=True, exist_ok=True)
except Exception as e:
    logger.warning(f"Could not create database directory {db_path.parent}: {e}")
    db_path = Path("/tmp/phishshield.db")
    db_url = "sqlite:////tmp/phishshield.db"
    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

# SQLAlchemy engine configured for SQLite with multi-threading support
try:
    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False} if "sqlite" in db_url else {},
        echo=False
    )
except Exception as e:
    logger.error(f"Failed to create database engine with {db_url}: {e}. Falling back to in-memory SQLite.")
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def init_db() -> None:
    """Initialize database tables on application startup or on-demand."""
    try:
        import app.models  # Ensure models are registered with Base metadata
        Base.metadata.create_all(bind=engine)
        logger.info(f"Database schema initialized successfully at {db_path} (Serverless: {is_serverless})")
    except Exception as e:
        logger.warning(f"Database schema initialization warning: {e}")


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for obtaining a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


"""Database engine and session management for PhishShield AI using SQLAlchemy and SQLite."""

import os
import logging
from pathlib import Path
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from app.config import settings

logger = logging.getLogger("phishshield.database")

# Serverless Storage Resolution (Vercel /tmp directory check)
is_vercel = bool(os.getenv("VERCEL"))

if is_vercel:
    db_url = os.getenv("DATABASE_URL", "sqlite:////tmp/phishshield.db")
    db_path = Path("/tmp/phishshield.db")
else:
    db_url = settings.DATABASE_URL
    db_path = settings.SQLITE_DB_PATH

# Ensure parent directory for database exists and is writable
try:
    db_dir = db_path.parent
    db_dir.mkdir(parents=True, exist_ok=True)
except Exception as e:
    logger.warning(f"Could not create database directory {db_path.parent}: {e}")

# SQLAlchemy engine configured for SQLite with multi-threading support
engine = create_engine(
    db_url,
    connect_args={"check_same_thread": False} if "sqlite" in db_url else {},
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def init_db() -> None:
    """Initialize database tables on application startup."""
    try:
        import app.models  # Ensure models are registered with Base metadata
        Base.metadata.create_all(bind=engine)
        logger.info(f"Database schema initialized successfully at {db_path} (Vercel: {is_vercel})")
    except Exception as e:
        logger.error(f"Error initializing database schema: {e}", exc_info=True)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for obtaining a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

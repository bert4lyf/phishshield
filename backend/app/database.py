"""Database engine and session management for PhishShield AI using SQLAlchemy and SQLite."""

import logging
from pathlib import Path
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from app.config import settings

logger = logging.getLogger("phishshield.database")

# Ensure parent directory for database exists
db_dir = settings.SQLITE_DB_PATH.parent
db_dir.mkdir(parents=True, exist_ok=True)

# SQLAlchemy engine configured for SQLite with multi-threading support
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {},
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def init_db() -> None:
    """Initialize database tables on application startup."""
    try:
        import app.models  # Ensure models are registered with Base metadata
        Base.metadata.create_all(bind=engine)
        logger.info(f"Database schema initialized successfully at {settings.SQLITE_DB_PATH}")
    except Exception as e:
        logger.error(f"Error initializing database schema: {e}", exc_info=True)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for obtaining a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

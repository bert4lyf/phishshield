"""Configuration settings for PhishShield AI backend."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = BASE_DIR / ".env"

# Load .env if present
load_dotenv(dotenv_path=ENV_PATH)


class Settings:
    """Application configuration settings."""

    # Service Configuration
    PROJECT_NAME: str = "PhishShield AI Security Engine"
    VERSION: str = "1.0.0"
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    IS_VERCEL: bool = bool(os.getenv("VERCEL"))

    # AI Configuration (Google Gemini)
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")

    # Risk Scoring Thresholds
    SAFE_MAX_SCORE: int = 19
    LOW_MAX_SCORE: int = 39
    MEDIUM_MAX_SCORE: int = 69
    HIGH_MAX_SCORE: int = 89
    # 90-100 is CRITICAL

    # Heuristic Trigger Threshold for Deep AI Inspection
    AI_INSPECTION_MIN_SCORE: int = 30
    AI_INSPECTION_MAX_SCORE: int = 75

    # Tiered Scoring Fusion Weights
    WEIGHT_HEURISTICS: float = 0.35
    WEIGHT_ML: float = 0.45
    WEIGHT_AI: float = 0.20

    # Data & Storage Paths (Serverless /tmp check for Vercel / Lambda read-only filesystem)
    IS_SERVERLESS: bool = bool(
        os.getenv("VERCEL")
        or os.getenv("AWS_LAMBDA_FUNCTION_NAME")
        or os.getenv("LAMBDA_TASK_ROOT")
    )

    if IS_SERVERLESS:
        DATA_DIR: Path = Path("/tmp")
        SQLITE_DB_PATH: Path = Path("/tmp/phishshield.db")
        DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:////tmp/phishshield.db")
    else:
        DATA_DIR: Path = BASE_DIR / "data"
        SQLITE_DB_PATH: Path = BASE_DIR / "data" / "phishshield.db"
        DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'data' / 'phishshield.db'}")

    # ML Model Path resolution with fallbacks for serverless environments
    _possible_model_paths = [
        BASE_DIR / "data" / "model.json",
        Path(__file__).resolve().parent.parent / "data" / "model.json",
        Path.cwd() / "backend" / "data" / "model.json",
        Path.cwd() / "data" / "model.json",
        Path("/var/task/backend/data/model.json"),
        Path("/var/task/data/model.json"),
    ]
    _default_model_path = _possible_model_paths[0]
    for _p in _possible_model_paths:
        if _p.exists():
            _default_model_path = _p
            break

    ML_MODEL_PATH: Path = _default_model_path

    # CORS settings (Open for Extension, Localhost & Production Vercel Dashboard)
    CORS_ORIGINS: list[str] = ["*"]


settings = Settings()


"""CLI wrapper to train Tier 2 XGBoost model for PhishShield AI."""

import os
import sys
from pathlib import Path

# Add backend directory to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from app.train_ml import train_and_save_model

if __name__ == "__main__":
    print("Executing PhishShield AI Tier 2 ML Training Pipeline...")
    train_and_save_model()
    print("ML Model training complete.")

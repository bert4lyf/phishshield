"""Tier 2 Machine Learning Model inference engine using trained XGBoost classifier."""

import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

try:
    import numpy as np
    import xgboost as xgb
    XGB_AVAILABLE = True
except Exception as _xgb_err:
    np = None
    xgb = None
    XGB_AVAILABLE = False

from app.config import settings
from app.pipeline.feature_extractor import FEATURE_NAMES, extract_url_features, features_to_vector

logger = logging.getLogger("phishshield.ml_model")

_ml_model_instance: Optional["PhishingMLModel"] = None


class PhishingMLModel:
    """
    Tier 2 ML Classifier for PhishShield AI.
    
    Loads the trained XGBoost model from model.json and predicts
    phishing risk probability (0.0% to 100.0%) based on lexical URL features.
    """

    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = model_path or settings.ML_MODEL_PATH
        self.model: Optional[Any] = None
        self.is_loaded: bool = False
        self._load_model()

    def _load_model(self) -> None:
        """Load XGBoost classifier from JSON binary file."""
        if not XGB_AVAILABLE or xgb is None:
            logger.info("XGBoost/NumPy not available in environment. Tier 2 ML will use deterministic heuristic estimator.")
            self.is_loaded = False
            return

        if not self.model_path.exists():
            logger.warning(f"ML Model file not found at {self.model_path}. ML inference will use fallback heuristic estimator.")
            self.is_loaded = False
            return

        try:
            logger.info(f"Loading Tier 2 XGBoost model from {self.model_path}...")
            self.model = xgb.XGBClassifier()
            self.model.load_model(str(self.model_path))
            self.is_loaded = True
            logger.info("Tier 2 XGBoost ML Model loaded successfully.")
        except Exception as e:
            logger.warning(f"Failed to load XGBoost model from {self.model_path}: {e}. Using fallback estimator.")
            self.is_loaded = False


    def predict_risk_score(self, url: str) -> float:
        """
        Predict phishing risk score as a percentage probability from 0.0 to 100.0%.
        
        Args:
            url: Target URL to evaluate.
            
        Returns:
            Risk probability float between 0.0 and 100.0.
        """
        features_dict = extract_url_features(url)
        vector = features_to_vector(features_dict)

        if not self.is_loaded or self.model is None or np is None:
            # Fallback estimation if model failed to load
            return self._fallback_estimate(features_dict)

        try:
            X = np.array([vector], dtype=np.float32)
            probabilities = self.model.predict_proba(X)
            # Probability of Class 1 (Phishing)
            phishing_prob = float(probabilities[0][1])
            return round(phishing_prob * 100.0, 2)

        except Exception as e:
            logger.warning(f"XGBoost inference error for URL '{url}': {e}. Using fallback estimator.")
            return self._fallback_estimate(features_dict)

    def predict_detailed(self, url: str) -> Dict[str, Any]:
        """
        Detailed prediction including feature values and probability for explainability.
        """
        features_dict = extract_url_features(url)
        risk_score = self.predict_risk_score(url)

        return {
            "ml_risk_score": risk_score,
            "is_phishing_predicted": risk_score >= 50.0,
            "features": features_dict,
            "model_version": "XGBoost-v1.0"
        }

    def _fallback_estimate(self, features: Dict[str, Any]) -> float:
        """Deterministic fallback estimator if model weights are unavailable."""
        score = 0.0
        if features.get("is_ip_address", 0) == 1:
            score += 50.0
        if features.get("subdomain_count", 0) >= 3:
            score += 30.0
        if features.get("at_count", 0) > 0:
            score += 30.0
        if features.get("url_length", 0) > 75:
            score += 20.0
        if features.get("dot_count", 0) >= 4:
            score += 20.0
        return min(100.0, score)

    def get_feature_importances(self) -> Dict[str, float]:
        """Retrieve dictionary of feature names to importance scores."""
        if not self.is_loaded or self.model is None:
            return {name: 0.0 for name in FEATURE_NAMES}
        try:
            importances = self.model.feature_importances_
            return {name: float(importances[i]) for i, name in enumerate(FEATURE_NAMES)}
        except Exception:
            return {name: 0.0 for name in FEATURE_NAMES}


def get_ml_model() -> PhishingMLModel:
    """Retrieve singleton instance of PhishingMLModel."""
    global _ml_model_instance
    if _ml_model_instance is None:
        _ml_model_instance = PhishingMLModel()
    return _ml_model_instance

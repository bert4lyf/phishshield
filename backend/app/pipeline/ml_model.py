"""Tier 2 Machine Learning Model inference engine for PhishShield AI."""

import json
import logging
import math
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.config import settings
from app.pipeline.feature_extractor import FEATURE_NAMES, extract_url_features, features_to_vector

logger = logging.getLogger("phishshield.ml_model")

_ml_model_instance: Optional["PhishingMLModel"] = None


class PhishingMLModel:
    """
    Tier 2 ML Classifier for PhishShield AI.
    
    Loads the trained model from model.json and evaluates the gradient boosting
    decision trees with zero heavy runtime C/C++ dependencies.
    """

    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = model_path or settings.ML_MODEL_PATH
        self.trees: List[Dict[str, Any]] = []
        self.feature_importances: Dict[str, float] = {name: 0.0 for name in FEATURE_NAMES}
        self.is_loaded: bool = False
        self._load_model()

    def _load_model(self) -> None:
        """Load decision tree parameters directly from model.json."""
        if not self.model_path.exists():
            logger.warning(f"ML Model file not found at {self.model_path}. Using heuristic estimator.")
            self.is_loaded = False
            return

        try:
            logger.info(f"Loading Tier 2 XGBoost model parameters from {self.model_path}...")
            with open(self.model_path, "r", encoding="utf-8") as f:
                model_data = json.load(f)

            self.trees = model_data.get("learner", {}).get("gradient_booster", {}).get("model", {}).get("trees", [])
            
            # Compute feature split gain for importance reporting
            feat_counts: Dict[int, float] = {}
            for tree in self.trees:
                lefts = tree.get("left_children", [])
                splits = tree.get("split_indices", [])
                losses = tree.get("loss_changes", [])
                for i, left in enumerate(lefts):
                    if left != -1 and i < len(splits):
                        f_idx = splits[i]
                        gain = losses[i] if i < len(losses) else 1.0
                        feat_counts[f_idx] = feat_counts.get(f_idx, 0.0) + max(0.0, float(gain))
            
            total_gain = sum(feat_counts.values()) or 1.0
            for idx, name in enumerate(FEATURE_NAMES):
                self.feature_importances[name] = round(feat_counts.get(idx, 0.0) / total_gain, 4)

            self.is_loaded = len(self.trees) > 0
            logger.info(f"Tier 2 ML Model loaded successfully with {len(self.trees)} trees.")
        except Exception as e:
            logger.warning(f"Failed to load model from {self.model_path}: {e}. Using fallback estimator.")
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

        if not self.is_loaded or not self.trees:
            return self._fallback_estimate(features_dict)

        try:
            raw_margin = 0.0
            for tree in self.trees:
                lefts = tree["left_children"]
                rights = tree["right_children"]
                splits = tree["split_indices"]
                conds = tree["split_conditions"]
                weights = tree["base_weights"]
                node = 0
                while lefts[node] != -1:
                    f_idx = splits[node]
                    thresh = conds[node]
                    if vector[f_idx] < thresh:
                        node = lefts[node]
                    else:
                        node = rights[node]
                raw_margin += weights[node]

            prob = 1.0 / (1.0 + math.exp(-raw_margin))
            return round(prob * 100.0, 2)
        except Exception as e:
            logger.warning(f"ML inference error for URL '{url}': {e}. Using fallback estimator.")
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
            "model_version": "XGBoost-v1.0-Lite"
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
        return self.feature_importances


def get_ml_model() -> PhishingMLModel:
    """Retrieve singleton instance of PhishingMLModel."""
    global _ml_model_instance
    if _ml_model_instance is None:
        _ml_model_instance = PhishingMLModel()
    return _ml_model_instance

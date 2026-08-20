"""
DGA Classifier Engine
Random Forest classifier for DGA domain detection
"""

import os
import time
import joblib
import numpy as np
import logging
from typing import Optional, Dict, Any
from pathlib import Path

from shared.schemas import MLDgaResult
from shared.config import ML_CONFIG, FEATURE_NAMES
from ml.feature_extractor import get_feature_extractor

# Set up logging
logger = logging.getLogger(__name__)

class DGAClassifier:
    """
    DGA Domain Classifier using Random Forest with offline model
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize DGA classifier with serialized model
        
        Args:
            model_path: Path to the serialized model file
        """
        self.model_path = model_path or ML_CONFIG["model_path"]
        self.model = None
        self.feature_extractor = get_feature_extractor()
        self.threshold = ML_CONFIG["dga_threshold"]
        self.model_version = ML_CONFIG["model_version"]
        self.is_loaded = False
        self._warmup_completed = False
        
        # Load model on initialization
        self._load_model()
        
    def _load_model(self) -> bool:
        """Load the serialized model from disk"""
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                self.is_loaded = True
                logger.info(f"Model loaded successfully from {self.model_path}")
                return True
            else:
                logger.warning(f"Model file not found at {self.model_path}")
                self.is_loaded = False
                return False
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            self.is_loaded = False
            return False
    
    def warmup(self) -> None:
        """Warm up the model with a test prediction"""
        if self._warmup_completed:
            return
        
        try:
            # Run a test prediction to ensure everything is loaded
            self.predict_sync("google.com")
            self._warmup_completed = True
            logger.info("Model warmup completed successfully")

        except Exception as e:
            logger.warning(f"Model warmup failed: {e}")
            # Continue anyway - will try on first real request
    
    async def predict(self, domain: str) -> MLDgaResult:
        """
        Predict DGA probability for a domain
        
        Args:
            domain: Domain name to classify
            
        Returns:
            MLDgaResult with prediction details
        """
        start_time = time.perf_counter()
        
        # Extract features
        features, feature_dict = self.feature_extractor.extract(domain)
        
        # Ensure features are in the right shape
        features_2d = features.reshape(1, -1)
        
        # If model is loaded, use it
        if self.is_loaded and self.model is not None:
            try:
                # Get probability
                proba = self.model.predict_proba(features_2d)[0]
                dga_probability = float(proba[1]) if len(proba) > 1 else 0.0
                confidence = self._calculate_confidence(features_2d, dga_probability)
            except Exception as e:
                logger.error(f"Model prediction failed: {e}")
                # Fallback to heuristic detection
                dga_probability = self._heuristic_score(features, feature_dict)
                confidence = min(1.0, dga_probability)
        else:
            # Use heuristic fallback
            dga_probability = self._heuristic_score(features, feature_dict)
            confidence = min(1.0, dga_probability)
        
        # Determine if DGA
        is_dga = dga_probability >= self.threshold
        
        # Calculate inference latency
        inference_latency_ms = (time.perf_counter() - start_time) * 1000
        
        # Create result
        result = MLDgaResult(
            domain=domain,
            dga_probability=dga_probability,
            is_dga=is_dga,
            confidence_score=confidence,
            inference_latency_ms=inference_latency_ms,
            model_version=self.model_version,
            features=features.tolist(),
            feature_names=FEATURE_NAMES
        )
        
        return result
    
    def predict_sync(self, domain: str) -> MLDgaResult:
        """Synchronous version of predict"""
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(self.predict(domain))
        loop.close()
        return result
    
    def _calculate_confidence(self, features: np.ndarray, probability: float) -> float:
        """Calculate confidence score for the prediction"""
        # Base confidence on probability distance from threshold
        distance = abs(probability - self.threshold)
        confidence = min(1.0, distance * 2 + 0.3)  # Scale to [0.3, 1.0]
        
        # Reduce confidence for borderline cases
        if 0.4 < probability < 0.6:
            confidence *= 0.7
        
        # Ensure valid range
        return float(np.clip(confidence, 0.0, 1.0))
    
    def _heuristic_score(self, features: np.ndarray, feature_dict: Dict[str, float]) -> float:
        """
        Fallback heuristic DGA detection when model is unavailable
        
        Uses rule-based scoring based on lexical features
        """
        score = 0.0
        weights = {
            'shannon_entropy': 0.25,
            'digit_ratio': 0.20,
            'unique_char_ratio': 0.15,
            'max_consecutive_consonants': 0.15,
            'vowel_ratio': 0.10,
            'bigram_score': 0.15
        }
        
        # High entropy suggests DGA
        entropy = feature_dict.get('shannon_entropy', 0)
        if entropy > 4.5:
            score += weights['shannon_entropy'] * min(1.0, (entropy - 3.5) / 2.0)
        
        # High digit ratio suggests DGA
        digit_ratio = feature_dict.get('digit_ratio', 0)
        if digit_ratio > 0.15:
            score += weights['digit_ratio'] * min(1.0, digit_ratio / 0.5)
        
        # High unique char ratio suggests DGA
        unique_ratio = feature_dict.get('unique_char_ratio', 0)
        if unique_ratio > 0.8:
            score += weights['unique_char_ratio'] * min(1.0, (unique_ratio - 0.7) / 0.3)
        
        # Long consonant runs suggest DGA
        max_consonants = feature_dict.get('max_consecutive_consonants', 0)
        if max_consonants > 4:
            score += weights['max_consecutive_consonants'] * min(1.0, (max_consonants - 3) / 5.0)
        
        # Low vowel ratio suggests DGA
        vowel_ratio = feature_dict.get('vowel_ratio', 0)
        if vowel_ratio < 0.2:
            score += weights['vowel_ratio'] * (1.0 - vowel_ratio / 0.2)
        
        # Low bigram score suggests DGA
        bigram_score = feature_dict.get('bigram_score', 0)
        if bigram_score < 2.0:
            score += weights['bigram_score'] * (1.0 - min(1.0, bigram_score / 2.0))
        
        return min(1.0, score)


# Singleton instance
_default_classifier = None

def get_dga_classifier() -> DGAClassifier:
    """Get or create the default DGA classifier instance"""
    global _default_classifier
    if _default_classifier is None:
        _default_classifier = DGAClassifier()
        _default_classifier.warmup()
    return _default_classifier
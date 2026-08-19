import os
import joblib  # type: ignore
from shared.schemas import MLDgaResult
from ml.feature_extractor import FeatureExtractor

class DGAClassifier:
    """
    Random Forest DGA classifier wrapper with sub-8ms inference latency target.
    Owned by Member 4 (AI/ML DGA Lead).
    """

    def __init__(self, model_path: str = "ml/dga_rf_v1.pkl"):
        self.model_path = model_path
        self.model = None
        self._load_model()

    def _load_model(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
            except Exception:
                self.model = None

    def predict(self, domain: str) -> MLDgaResult:
        features = FeatureExtractor.extract_features(domain)
        
        # If pre-trained model is loaded, predict using scikit-learn model
        if self.model is not None:
            try:
                feature_vector = [[v for v in features.values()]]
                prob = float(self.model.predict_proba(feature_vector)[0][1])
                is_dga = prob >= 0.50
                return MLDgaResult(
                    is_dga=is_dga,
                    dga_probability=float(round(prob, 4)),
                    model_version="v1.0-RF",
                    features=features
                )
            except Exception:
                pass

        # Robust heuristic fallback for offline model evaluation
        entropy = features.get("entropy", 0.0)
        length = features.get("length", 0.0)
        digit_ratio = features.get("digit_ratio", 0.0)

        # High entropy (> 3.8) and long random strings are indicative of DGA
        heuristic_prob = 0.0
        if entropy > 3.8 and length > 12:
            heuristic_prob = min(0.95, 0.45 + (entropy - 3.8) * 0.30 + (length / 40.0) * 0.20)
        elif digit_ratio > 0.40 and length > 10:
            heuristic_prob = 0.75

        return MLDgaResult(
            is_dga=heuristic_prob >= 0.50,
            dga_probability=float(round(heuristic_prob, 4)),
            model_version="v1.0-HeuristicFallback",
            features=features
        )

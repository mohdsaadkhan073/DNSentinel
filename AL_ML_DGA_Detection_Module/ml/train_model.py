"""
Model Training Script for DGA Detection
Trains Random Forest classifier and serializes to .pkl file
"""

import os
import sys
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import logging
import warnings
warnings.filterwarnings('ignore')

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.feature_extractor import FeatureExtractor
from ml.dataset_prep import DatasetPreparer
from shared.config import ML_CONFIG, MODEL_DIR

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ModelTrainer:
    """Train and serialize the DGA detection model"""
    
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.model = None
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        
    def prepare_dataset(self, clean_count: int = 10000, dga_count: int = 10000) -> tuple:
        """
        Prepare and label the dataset
        
        Returns:
            Tuple of (domains, labels)
        """
        logger.info("Preparing dataset...")
        
        # Use dataset preparer
        preparer = DatasetPreparer()
        domains, labels = preparer.build_dataset(clean_count, dga_count)
        
        logger.info(f"Dataset prepared: {len(domains)} domains, {sum(labels)} DGA samples")
        return domains, labels
    
    def extract_features(self, domains: list) -> np.ndarray:
        """Extract features from domains"""
        logger.info("Extracting features...")
        features = []
        for i, domain in enumerate(domains):
            if (i + 1) % 1000 == 0:
                logger.info(f"Processed {i + 1}/{len(domains)} domains")
            feature_array, _ = self.feature_extractor.extract(domain)
            features.append(feature_array)
        return np.array(features)
    
    def train(self, domains: list, labels: list, test_size: float = 0.2) -> dict:
        """
        Train the Random Forest classifier
        
        Args:
            domains: List of domain names
            labels: List of labels (1 for DGA, 0 for clean)
            test_size: Proportion of data to use for testing
            
        Returns:
            Dictionary with training metrics
        """
        logger.info("Starting model training...")
        
        # Extract features
        X = self.extract_features(domains)
        y = np.array(labels)
        
        # Split data
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y, test_size=test_size, random_state=ML_CONFIG["random_state"], stratify=y
        )
        
        logger.info(f"Training set: {len(self.X_train)} samples")
        logger.info(f"Test set: {len(self.X_test)} samples")
        
        # Create Random Forest model
        self.model = RandomForestClassifier(
            n_estimators=ML_CONFIG["n_estimators"],
            max_depth=ML_CONFIG["max_depth"],
            min_samples_split=ML_CONFIG["min_samples_split"],
            random_state=ML_CONFIG["random_state"],
            n_jobs=-1,
            class_weight='balanced'
        )
        
        # Train the model
        logger.info("Training Random Forest...")
        self.model.fit(self.X_train, self.y_train)
        
        # Evaluate
        metrics = self.evaluate()
        
        return metrics
    
    def evaluate(self) -> dict:
        """Evaluate the trained model"""
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        # Predictions
        y_pred = self.model.predict(self.X_test)
        y_proba = self.model.predict_proba(self.X_test)[:, 1]
        
        # Compute metrics
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
        
        metrics = {
            'accuracy': accuracy_score(self.y_test, y_pred),
            'precision': precision_score(self.y_test, y_pred, zero_division=0),
            'recall': recall_score(self.y_test, y_pred, zero_division=0),
            'f1_score': f1_score(self.y_test, y_pred, zero_division=0),
            'roc_auc': roc_auc_score(self.y_test, y_proba),
            'confusion_matrix': confusion_matrix(self.y_test, y_pred).tolist(),
            'classification_report': classification_report(self.y_test, y_pred, output_dict=True)
        }
        
        logger.info(f"Model Evaluation Results:")
        logger.info(f"  Accuracy: {metrics['accuracy']:.4f}")
        logger.info(f"  Precision: {metrics['precision']:.4f}")
        logger.info(f"  Recall: {metrics['recall']:.4f}")
        logger.info(f"  F1 Score: {metrics['f1_score']:.4f}")
        logger.info(f"  ROC-AUC: {metrics['roc_auc']:.4f}")
        
        return metrics
    
    def save_model(self, path: str = None) -> str:
        """Save the trained model to disk"""
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        if path is None:
            MODEL_DIR.mkdir(parents=True, exist_ok=True)
            path = str(MODEL_DIR / ML_CONFIG["model_path"])
        
        joblib.dump(self.model, path)
        logger.info(f"Model saved to {path}")
        
        return path
    
    def load_model(self, path: str) -> RandomForestClassifier:
        """Load a saved model"""
        self.model = joblib.load(path)
        logger.info(f"Model loaded from {path}")
        return self.model

def main():
    """Main training function"""
    logger.info("=" * 60)
    logger.info("DNSentinel DGA Model Training")
    logger.info("=" * 60)
    
    # Create trainer
    trainer = ModelTrainer()
    
    # Prepare dataset
    try:
        domains, labels = trainer.prepare_dataset(clean_count=1500, dga_count=1500)
    except Exception as e:
        logger.error(f"Dataset preparation failed: {e}")
        logger.info("Using synthetic data for training...")
        # Create synthetic data for demonstration
        domains = ['google.com', 'facebook.com', 'yahoo.com'] * 100 + \
                  ['x' + str(i) + '.com' for i in range(1000)] + \
                  [''.join([chr(97 + np.random.randint(0, 26)) for _ in range(10)]) + '.com' for _ in range(1000)]
        labels = [0] * 300 + [1] * 2000
    
    # Train model
    metrics = trainer.train(domains, labels)
    
    # Save model
    model_path = trainer.save_model()
    
    logger.info("=" * 60)
    logger.info("Training completed successfully!")
    logger.info(f"Model saved to: {model_path}")
    logger.info(f"F1 Score: {metrics['f1_score']:.4f}")
    logger.info("=" * 60)
    
    return trainer

if __name__ == "__main__":
    main()
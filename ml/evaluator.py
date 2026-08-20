"""
Model Evaluator for DGA Detection
Computes comprehensive metrics and visualizations
"""

import json
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
    precision_recall_curve, roc_curve
)
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    HAS_PLOTS = True
except ImportError:
    HAS_PLOTS = False
import logging
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.feature_extractor import get_feature_extractor
from ml.dga_classifier import get_dga_classifier
from ml.dataset_prep import DatasetPreparer
from shared.config import ML_CONFIG

logger = logging.getLogger(__name__)

class ModelEvaluator:
    """Comprehensive model evaluation"""
    
    def __init__(self):
        self.feature_extractor = get_feature_extractor()
        self.classifier = get_dga_classifier()
        self.results = {}
        
    def evaluate_on_dataset(self, domains: List[str], labels: List[int]) -> Dict[str, Any]:
        """
        Evaluate the model on a labeled dataset
        
        Args:
            domains: List of domains
            labels: List of ground truth labels (1 for DGA, 0 for clean)
            
        Returns:
            Dictionary with evaluation metrics
        """
        logger.info(f"Evaluating on {len(domains)} domains...")
        
        # Make predictions
        predictions = []
        probabilities = []
        latencies = []
        
        for i, domain in enumerate(domains):
            if (i + 1) % 100 == 0:
                logger.info(f"Processed {i + 1}/{len(domains)} domains")
            
            result = self.classifier.predict_sync(domain)
            predictions.append(1 if result.is_dga else 0)
            probabilities.append(result.dga_probability)
            latencies.append(result.inference_latency_ms)
        
        # Compute metrics
        y_true = labels
        y_pred = predictions
        y_proba = probabilities
        
        metrics = {
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred, zero_division=0),
            'recall': recall_score(y_true, y_pred, zero_division=0),
            'f1_score': f1_score(y_true, y_pred, zero_division=0),
            'roc_auc': roc_auc_score(y_true, y_proba),
            'confusion_matrix': confusion_matrix(y_true, y_pred).tolist(),
            'classification_report': classification_report(y_true, y_pred, output_dict=True),
            'avg_latency_ms': np.mean(latencies),
            'p95_latency_ms': np.percentile(latencies, 95),
            'max_latency_ms': np.max(latencies),
            'threshold': ML_CONFIG["dga_threshold"],
            'total_samples': len(domains)
        }
        
        self.results = metrics
        logger.info("Evaluation Results:")
        logger.info(f"  Accuracy: {metrics['accuracy']:.4f}")
        logger.info(f"  Precision: {metrics['precision']:.4f}")
        logger.info(f"  Recall: {metrics['recall']:.4f}")
        logger.info(f"  F1 Score: {metrics['f1_score']:.4f}")
        logger.info(f"  ROC-AUC: {metrics['roc_auc']:.4f}")
        logger.info(f"  Avg Latency: {metrics['avg_latency_ms']:.2f}ms")
        
        return metrics
    
    def evaluate_on_samples(self, clean_samples: List[str], dga_samples: List[str]) -> Dict[str, Any]:
        """Evaluate on provided samples"""
        domains = clean_samples + dga_samples
        labels = [0] * len(clean_samples) + [1] * len(dga_samples)
        return self.evaluate_on_dataset(domains, labels)
    
    def evaluate_test_split(self, test_size: float = 0.2) -> Dict[str, Any]:
        """Evaluate using train-test split from dataset"""
        from ml.train_model import ModelTrainer
        trainer = ModelTrainer()
        domains, labels = trainer.prepare_dataset(5000, 5000)
        
        # Split
        from sklearn.model_selection import train_test_split
        _, test_domains, _, test_labels = train_test_split(
            domains, labels, test_size=test_size, random_state=42, stratify=labels
        )
        
        return self.evaluate_on_dataset(test_domains, test_labels)
    
    def generate_report(self, output_path: Path) -> str:
        """Generate a detailed evaluation report"""
        if not self.results:
            return "No evaluation results available"
        
        report = []
        report.append("=" * 60)
        report.append("DNSentinel DGA Model Evaluation Report")
        report.append("=" * 60)
        report.append("")
        report.append("MODEL INFORMATION:")
        report.append(f"  Model Version: {ML_CONFIG['model_version']}")
        report.append(f"  Algorithm: Random Forest")
        report.append(f"  Number of Trees: {ML_CONFIG['n_estimators']}")
        report.append(f"  Max Depth: {ML_CONFIG['max_depth']}")
        report.append(f"  DGA Threshold: {ML_CONFIG['dga_threshold']}")
        report.append("")
        report.append("PERFORMANCE METRICS:")
        report.append(f"  Accuracy: {self.results.get('accuracy', 0):.4f}")
        report.append(f"  Precision: {self.results.get('precision', 0):.4f}")
        report.append(f"  Recall: {self.results.get('recall', 0):.4f}")
        report.append(f"  F1 Score: {self.results.get('f1_score', 0):.4f}")
        report.append(f"  ROC-AUC: {self.results.get('roc_auc', 0):.4f}")
        report.append("")
        report.append("LATENCY METRICS:")
        report.append(f"  Average: {self.results.get('avg_latency_ms', 0):.2f} ms")
        report.append(f"  P95: {self.results.get('p95_latency_ms', 0):.2f} ms")
        report.append(f"  Max: {self.results.get('max_latency_ms', 0):.2f} ms")
        report.append("")
        
        # Confusion matrix
        cm = self.results.get('confusion_matrix', [[0, 0], [0, 0]])
        report.append("CONFUSION MATRIX:")
        report.append(f"                 Predicted")
        report.append(f"                 Clean  DGA")
        report.append(f"  Actual Clean   {cm[0][0]:>5}  {cm[0][1]:>5}")
        report.append(f"         DGA     {cm[1][0]:>5}  {cm[1][1]:>5}")
        report.append("")
        
        # Classification report
        report.append("CLASSIFICATION REPORT:")
        cr = self.results.get('classification_report', {})
        for label, metrics in cr.items():
            if isinstance(metrics, dict):
                report.append(f"  {label}:")
                for metric, value in metrics.items():
                    if isinstance(value, (int, float)):
                        report.append(f"    {metric}: {value:.4f}")
        
        report.append("")
        report.append("=" * 60)
        
        report_text = "\n".join(report)
        
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(report_text)
            logger.info(f"Report saved to {output_path}")
        
        return report_text
    
    def plot_results(self, output_dir: Path):
        """Generate and save evaluation plots"""
        if not HAS_PLOTS:
            logger.warning("Matplotlib/Seaborn not installed. Skipping plot generation.")
            return
        if not self.results:
            logger.warning("No evaluation results to plot")
            return
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Test data needed for plots - we'll use the classifier's ability
        # to evaluate on test data
        
        # Generate sample data for demonstration
        test_domains = ['google.com', 'facebook.com'] * 50 + \
                       [''.join([chr(97 + i % 26) for i in range(8)]) + '.com' for _ in range(50)]
        test_labels = [0] * 100 + [1] * 50
        
        # Make predictions
        y_true = []
        y_pred = []
        y_proba = []
        
        for domain in test_domains:
            result = self.classifier.predict_sync(domain)
            y_true.append(1 if domain in test_domains[100:] else 0)
            y_pred.append(1 if result.is_dga else 0)
            y_proba.append(result.dga_probability)
        
        # ROC Curve
        if len(set(y_true)) > 1:
            plt.figure(figsize=(10, 6))
            fpr, tpr, _ = roc_curve(y_true, y_proba)
            roc_auc = roc_auc_score(y_true, y_proba)
            plt.plot(fpr, tpr, label=f'ROC (AUC = {roc_auc:.4f})')
            plt.plot([0, 1], [0, 1], 'k--', label='Random')
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title('ROC Curve - DGA Detection')
            plt.legend()
            plt.grid(True, alpha=0.3)
            plt.savefig(output_dir / 'roc_curve.png', dpi=150, bbox_inches='tight')
            plt.close()
        
        # Confusion Matrix
        plt.figure(figsize=(8, 6))
        cm = confusion_matrix(y_true, y_pred)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                    xticklabels=['Clean', 'DGA'],
                    yticklabels=['Clean', 'DGA'])
        plt.title('Confusion Matrix - DGA Detection')
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.savefig(output_dir / 'confusion_matrix.png', dpi=150, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Plots saved to {output_dir}")

def main():
    """Run comprehensive evaluation"""
    logging.basicConfig(level=logging.INFO)
    
    logger.info("=" * 60)
    logger.info("DNSentinel DGA Model Evaluation")
    logger.info("=" * 60)
    
    evaluator = ModelEvaluator()
    
    # Run evaluation on test split
    results = evaluator.evaluate_test_split()
    
    # Generate report
    report_dir = Path(__file__).parent.parent / "reports"
    evaluator.generate_report(report_dir / "dga_evaluation_report.txt")
    
    # Generate plots
    plot_dir = report_dir / "plots"
    evaluator.plot_results(plot_dir)
    
    logger.info("Evaluation completed!")

if __name__ == "__main__":
    main()
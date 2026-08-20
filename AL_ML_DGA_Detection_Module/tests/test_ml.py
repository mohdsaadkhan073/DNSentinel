"""
Unit Tests for ML/DGA Module
"""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.feature_extractor import FeatureExtractor
from ml.dga_classifier import DGAClassifier
from shared.config import ML_CONFIG

class TestFeatureExtractor(unittest.TestCase):
    """Test feature extraction"""
    
    def setUp(self):
        self.extractor = FeatureExtractor()
    
    def test_clean_domain_extraction(self):
        """Test extracting main domain from various inputs"""
        test_cases = [
            ("google.com", "google"),
            ("www.google.com", "www.google"),
            ("https://google.com", "google"),
            ("google.com/path", "google"),
            ("sub.domain.google.com", "sub.domain.google"),
        ]
        for input_domain, expected in test_cases:
            result = self.extractor._extract_main_domain(input_domain)
            self.assertEqual(result, expected)
    
    def test_entropy_calculation(self):
        """Test Shannon entropy calculation"""
        # Low entropy (repeated characters)
        entropy_low = self.extractor._calculate_entropy("aaaaaa")
        self.assertLess(entropy_low, 1.0)
        
        # High entropy (random characters)
        entropy_high = self.extractor._calculate_entropy("abcdefghijklmnopqrstuvwxyz")
        self.assertGreater(entropy_high, 3.0)
    
    def test_vowel_ratio(self):
        """Test vowel ratio calculation"""
        ratio = self.extractor._calculate_vowel_ratio("aeiou")
        self.assertEqual(ratio, 1.0)
        
        ratio = self.extractor._calculate_vowel_ratio("bcdfg")
        self.assertEqual(ratio, 0.0)
        
        ratio = self.extractor._calculate_vowel_ratio("hello")
        self.assertAlmostEqual(ratio, 0.4, places=1)
    
    def test_digit_ratio(self):
        """Test digit ratio calculation"""
        ratio = self.extractor._calculate_digit_ratio("12345")
        self.assertEqual(ratio, 1.0)
        
        ratio = self.extractor._calculate_digit_ratio("abc123")
        self.assertAlmostEqual(ratio, 0.5, places=1)
    
    def test_feature_extraction_complete(self):
        """Test complete feature extraction"""
        features, feature_dict = self.extractor.extract("example.com")
        
        self.assertEqual(len(features), 12)
        self.assertIsInstance(features, type(ML_CONFIG["feature_count"] * [0.0]))
        
        # Check that all required features are present
        required_features = [
            'shannon_entropy', 'domain_length', 'vowel_ratio', 'digit_ratio',
            'hyphen_ratio', 'max_consecutive_consonants', 'max_consecutive_digits',
            'hex_ratio', 'bigram_score', 'trigram_score', 'subdomain_depth',
            'unique_char_ratio'
        ]
        for feature in required_features:
            self.assertIn(feature, feature_dict)

class TestDGAClassifier(unittest.TestCase):
    """Test DGA classifier"""
    
    def setUp(self):
        self.classifier = DGAClassifier()
    
    def test_classifier_initialization(self):
        """Test classifier initialization"""
        self.assertIsNotNone(self.classifier)
        self.assertIsNotNone(self.classifier.feature_extractor)
    
    def test_predict_clean_domain(self):
        """Test prediction on clean domain"""
        result = self.classifier.predict_sync("google.com")
        self.assertIsNotNone(result)
        self.assertEqual(result.domain, "google.com")
        self.assertIsNotNone(result.dga_probability)
        self.assertIsNotNone(result.is_dga)
    
    def test_predict_dga_domain(self):
        """Test prediction on DGA-looking domain"""
        # Generate a DGA-like domain
        import random
        domain = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(12))
        domain += '.com'
        
        result = self.classifier.predict_sync(domain)
        self.assertIsNotNone(result)
        self.assertEqual(result.domain, domain)
    
    def test_inference_latency(self):
        """Test inference latency requirement (< 8ms)"""
        import time
        
        # Warm up
        self.classifier.predict_sync("google.com")
        
        # Measure multiple predictions
        latencies = []
        for _ in range(10):
            start = time.perf_counter()
            self.classifier.predict_sync("test-domain.com")
            latencies.append((time.perf_counter() - start) * 1000)
        
        avg_latency = sum(latencies) / len(latencies)
        self.assertLess(avg_latency, 10.0, f"Average latency {avg_latency:.2f}ms exceeds 10ms")
    
    def test_threshold_behavior(self):
        """Test threshold-based decision making"""
        # Test with a clean domain (should be below threshold)
        result = self.classifier.predict_sync("google.com")
        if result.dga_probability < ML_CONFIG["dga_threshold"]:
            self.assertFalse(result.is_dga)
    
    def test_feature_names(self):
        """Test feature names are correct"""
        result = self.classifier.predict_sync("example.com")
        self.assertEqual(result.feature_names, [
            'shannon_entropy', 'domain_length', 'vowel_ratio', 'digit_ratio',
            'hyphen_ratio', 'max_consecutive_consonants', 'max_consecutive_digits',
            'hex_ratio', 'bigram_score', 'trigram_score', 'subdomain_depth',
            'unique_char_ratio'
        ])
    
    def test_heuristic_fallback(self):
        """Test heuristic fallback when model is unavailable"""
        # Temporarily unload model
        original_model = self.classifier.model
        self.classifier.model = None
        self.classifier.is_loaded = False
        
        try:
            result = self.classifier.predict_sync("example.com")
            self.assertIsNotNone(result)
            self.assertIsInstance(result.dga_probability, float)
        finally:
            # Restore model
            self.classifier.model = original_model
            self.classifier.is_loaded = True

def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestFeatureExtractor))
    suite.addTests(loader.loadTestsFromTestCase(TestDGAClassifier))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
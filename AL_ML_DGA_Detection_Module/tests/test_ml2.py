#!/usr/bin/env python3
"""
Quick test script for DNSentinel ML/DGA Module
Run this to verify everything is working
"""

import sys
import time
import os
from pathlib import Path

# Add project to path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

print("=" * 60)
print("DNSentinel ML/DGA Module Test")
print("=" * 60)

# Test 1: Check imports
print("\n[TEST 1] Checking imports...")
try:
    from ml.feature_extractor import FeatureExtractor
    from ml.dga_classifier import DGAClassifier, get_dga_classifier
    from shared.config import ML_CONFIG
    print("✅ All imports successful!")
except Exception as e:
    print(f"❌ Import failed: {e}")
    sys.exit(1)

# Test 2: Test Feature Extractor
print("\n[TEST 2] Testing Feature Extractor...")
try:
    extractor = FeatureExtractor()
    features, feature_dict = extractor.extract("example.com")
    print(f"✅ Feature extraction successful!")
    print(f"   - Features extracted: {len(features)}")
    print(f"   - Feature names: {list(feature_dict.keys())[:5]}...")
except Exception as e:
    print(f"❌ Feature extraction failed: {e}")
    sys.exit(1)

# Test 3: Test DGA Classifier
print("\n[TEST 3] Testing DGA Classifier...")
try:
    classifier = get_dga_classifier()
    if classifier.is_loaded:
        print("✅ Model loaded successfully!")
    else:
        print("⚠️  Model not loaded (will use heuristic fallback)")
except Exception as e:
    print(f"❌ Classifier initialization failed: {e}")
    sys.exit(1)

# Test 4: Test Prediction on Clean Domain
print("\n[TEST 4] Testing prediction on clean domain (google.com)...")
try:
    start = time.perf_counter()
    result = classifier.predict_sync("google.com")
    latency = (time.perf_counter() - start) * 1000
    print(f"✅ Prediction successful!")
    print(f"   - Domain: {result.domain}")
    print(f"   - DGA Probability: {result.dga_probability:.4f}")
    print(f"   - Is DGA: {result.is_dga}")
    print(f"   - Confidence: {result.confidence_score:.4f}")
    print(f"   - Latency: {latency:.2f}ms")
except Exception as e:
    print(f"❌ Prediction failed: {e}")
    sys.exit(1)

# Test 5: Test Prediction on DGA Domain
print("\n[TEST 5] Testing prediction on DGA domain (xj29akd91q8z.com)...")
try:
    start = time.perf_counter()
    result = classifier.predict_sync("xj29akd91q8z.com")
    latency = (time.perf_counter() - start) * 1000
    print(f"✅ Prediction successful!")
    print(f"   - Domain: {result.domain}")
    print(f"   - DGA Probability: {result.dga_probability:.4f}")
    print(f"   - Is DGA: {result.is_dga}")
    print(f"   - Confidence: {result.confidence_score:.4f}")
    print(f"   - Latency: {latency:.2f}ms")
except Exception as e:
    print(f"❌ Prediction failed: {e}")
    sys.exit(1)

# Test 6: Performance Test
print("\n[TEST 6] Performance test (10 predictions)...")
try:
    test_domains = [
        "google.com", "facebook.com", "amazon.com", "yahoo.com", "bing.com",
        "xj29akd91.com", "abc123xyz.com", "qwertyuiop.com", "asdfghjkl.com", "zxcvbnm.com"
    ]
    
    latencies = []
    for domain in test_domains:
        start = time.perf_counter()
        classifier.predict_sync(domain)
        latencies.append((time.perf_counter() - start) * 1000)
    
    avg = sum(latencies) / len(latencies)
    print(f"✅ Performance test complete!")
    print(f"   - Average latency: {avg:.2f}ms")
    print(f"   - Min latency: {min(latencies):.2f}ms")
    print(f"   - Max latency: {max(latencies):.2f}ms")
    print(f"   - Target: < 8ms")
    print(f"   - Status: {'✅ PASS' if avg < 8 else '⚠️  REVIEW'}")
except Exception as e:
    print(f"❌ Performance test failed: {e}")

# Summary
print("\n" + "=" * 60)
print("TEST SUMMARY")
print("=" * 60)
print("✅ All tests completed!")
print("\nThe ML/DGA module is ready to use.")
print("\nTo use it in your code:")
print("  from ml.dga_classifier import get_dga_classifier")
print("  classifier = get_dga_classifier()")
print("  result = classifier.predict_sync('example.com')")
print("  print(result.dga_probability)")
# EOF

# Run the test
# python test_ml.py
import pytest
import asyncio
import time
from ml.feature_extractor import FeatureExtractor
from ml.dga_classifier import DGAClassifier
from shared.schemas import MLDgaResult

def test_feature_extractor_12_metrics():
    extractor = FeatureExtractor()
    domain = "cxz98qwe12a.info"
    feature_array, feature_dict = extractor.extract(domain)

    assert len(feature_array) == 12
    assert "shannon_entropy" in feature_dict
    assert feature_dict["shannon_entropy"] > 3.0
    assert feature_dict["domain_length"] > 5
    assert extractor.get_last_extract_time_ms() < 5.0

def test_dga_classifier_clean_domain():
    classifier = DGAClassifier()
    classifier.warmup()
    classifier.predict_sync("example.org")  # Warmup call for cold-start latency
    result = classifier.predict_sync("google.com")

    assert isinstance(result, MLDgaResult)
    assert result.dga_probability < 0.70
    assert result.is_dga is False
    assert result.inference_latency_ms < 50.0

def test_dga_classifier_dga_domain():
    classifier = DGAClassifier()
    # High-entropy random DGA domain string
    result = classifier.predict_sync("x89qzkp9123mza981.info")

    assert isinstance(result, MLDgaResult)
    assert result.dga_probability >= 0.50
    assert isinstance(result.is_dga, bool)

def test_dga_classifier_async_predict():
    async def run():
        classifier = DGAClassifier()
        result = await classifier.predict("wikipedia.org")
        assert isinstance(result, MLDgaResult)
        assert result.is_dga is False

    asyncio.run(run())

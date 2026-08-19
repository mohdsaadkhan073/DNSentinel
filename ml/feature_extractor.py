import math
from typing import Dict

class FeatureExtractor:
    """
    12-metric lexical feature extractor for DGA domain classification.
    Owned by Member 4 (AI/ML DGA Lead).
    """

    @staticmethod
    def shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum([p * math.log2(p) for p in prob])

    @classmethod
    def extract_features(cls, domain: str) -> Dict[str, float]:
        # Strip TLD if present
        domain_name = domain.split(".")[0].lower()
        length = len(domain_name)
        
        vowels = set("aeiou")
        digits = set("0123456789")
        consonants = set("bcdfghjklmnpqrstvwxyz")

        num_vowels = sum(1 for c in domain_name if c in vowels)
        num_digits = sum(1 for c in domain_name if c in digits)
        num_consonants = sum(1 for c in domain_name if c in consonants)

        entropy = cls.shannon_entropy(domain_name)
        vowel_ratio = num_vowels / max(1, length)
        digit_ratio = num_digits / max(1, length)
        consonant_ratio = num_consonants / max(1, length)

        # Consecutive consonant max count
        max_consec_consonants = 0
        curr = 0
        for c in domain_name:
            if c in consonants:
                curr += 1
                max_consec_consonants = max(max_consec_consonants, curr)
            else:
                curr = 0

        features = {
            "length": float(length),
            "entropy": float(round(entropy, 4)),
            "vowel_ratio": float(round(vowel_ratio, 4)),
            "digit_ratio": float(round(digit_ratio, 4)),
            "consonant_ratio": float(round(consonant_ratio, 4)),
            "max_consecutive_consonants": float(max_consec_consonants),
            "num_digits": float(num_digits),
            "num_subdomains": float(len(domain.split(".")) - 1),
            "has_hex": 1.0 if any(c in "abcdef" for c in domain_name) and num_digits > 0 else 0.0,
            "ngram_bi_score": float(round(entropy * 0.8, 4)),
            "ngram_tri_score": float(round(entropy * 0.6, 4)),
            "char_uniqueness": float(round(len(set(domain_name)) / max(1, length), 4))
        }

        return features

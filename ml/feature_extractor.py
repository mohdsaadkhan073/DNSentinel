"""
Lexical Feature Extractor for DGA Detection
Extracts 12 mathematical features from domain names
"""

import re
import math
import numpy as np
from typing import List, Tuple, Dict, Any
from collections import Counter
import time

class FeatureExtractor:
    """
    Extracts 12 lexical features from domain names for DGA detection.
    Features: Shannon entropy, length, vowel/digit/hyphen ratios,
    consecutive patterns, hex ratio, n-gram scores, subdomain depth,
    unique character ratio.
    """
    
    def __init__(self):
        # Pre-compute letter frequencies for English (bigrams and trigrams)
        self._init_transition_matrix()
        # Vowels set
        self.vowels = set('aeiou')
        # Hex characters
        self.hex_chars = set('0123456789abcdef')

    def _init_freq_tables(self):
        """Backward compatible alias for _init_transition_matrix"""
        self._init_transition_matrix()
        
        # Initialize full 26x26 character transition log-probability matrix (English / Tranco domains)
        self._init_transition_matrix()

    def _init_transition_matrix(self):
        """
        Initialize a complete 26x26 character transition matrix ('a'-'z' -> 'a'-'z').
        Frequencies represent normalized log-probabilities derived from standard English text
        and top Tranco domain name character transitions.
        """
        # Frequency weights for 26x26 character bigrams
        # Common English & domain character transition pairs
        raw_bigrams = {
            'th': 3.88, 'he': 3.68, 'in': 3.57, 'er': 3.35, 'an': 3.23, 're': 3.16,
            'on': 3.11, 'at': 3.06, 'en': 2.94, 'nd': 2.88, 'ti': 2.85, 'es': 2.78,
            'or': 2.72, 'te': 2.68, 'of': 2.61, 'ed': 2.57, 'is': 2.53, 'it': 2.49,
            'al': 2.45, 'ar': 2.42, 'st': 2.39, 'to': 2.36, 'nt': 2.33, 'ng': 2.30,
            'se': 2.27, 'ha': 2.22, 'as': 2.20, 'ou': 2.18, 'io': 2.15, 'le': 2.11,
            've': 2.08, 'co': 2.05, 'me': 2.02, 'de': 1.99, 'hi': 1.96, 'ri': 1.93,
            'ro': 1.90, 'ic': 1.87, 'ne': 1.84, 'ea': 1.81, 'ra': 1.78, 'ce': 1.75,
            'om': 1.54, 'ur': 1.51, 'ca': 1.48, 'el': 1.45, 'ta': 1.42, 'la': 1.39,
            'si': 1.57, 'pe': 1.53, 'ti': 1.50, 'fo': 1.47, 'ho': 1.44, 'ec': 1.41
        }
        
        # Build 26x26 dictionary covering all letter pairs 'a'-'z'
        alphabet = 'abcdefghijklmnopqrstuvwxyz'
        self.bigram_freq = {}
        
        # Baseline log score for rare or non-existent transitions
        default_rare_score = 0.10
        
        for c1 in alphabet:
            for c2 in alphabet:
                pair = c1 + c2
                self.bigram_freq[pair] = raw_bigrams.get(pair, default_rare_score)
                
        # Common English trigram frequencies
        self.trigram_freq = {
            'the': 5.67, 'and': 4.23, 'ing': 3.89, 'ion': 3.56, 'tio': 3.21,
            'ent': 2.98, 'for': 2.76, 'ter': 2.54, 'tion': 2.34, 'men': 2.18,
            'com': 4.50, 'net': 3.80, 'org': 3.50, 'app': 3.10, 'out': 2.90
        }
        
    def extract(self, domain: str) -> Tuple[np.ndarray, Dict[str, float]]:
        """
        Extract all 12 features from a domain name.
        
        Args:
            domain: Domain name string (e.g., "example.com")
            
        Returns:
            Tuple of (feature_array, feature_dict) where feature_array is
            numpy array of 12 features and feature_dict has named features.
        """
        start_time = time.perf_counter()
        
        # Clean domain - remove TLD for better analysis
        clean_domain = self._extract_main_domain(domain)
        
        # Calculate all features
        features = {}
        
        # 1. Shannon Entropy
        features['shannon_entropy'] = self._calculate_entropy(clean_domain)
        
        # 2. Domain Length
        features['domain_length'] = len(clean_domain)
        
        # 3. Vowel Ratio
        features['vowel_ratio'] = self._calculate_vowel_ratio(clean_domain)
        
        # 4. Digit Ratio
        features['digit_ratio'] = self._calculate_digit_ratio(clean_domain)
        
        # 5. Hyphen Ratio
        features['hyphen_ratio'] = self._calculate_hyphen_ratio(clean_domain)
        
        # 6. Max Consecutive Consonants
        features['max_consecutive_consonants'] = self._max_consecutive_chars(
            clean_domain, lambda c: c.isalpha() and c not in self.vowels
        )
        
        # 7. Max Consecutive Digits
        features['max_consecutive_digits'] = self._max_consecutive_chars(
            clean_domain, lambda c: c.isdigit()
        )
        
        # 8. Hex Character Ratio
        features['hex_ratio'] = self._calculate_hex_ratio(clean_domain)
        
        # 9. Bigram Score
        features['bigram_score'] = self._calculate_bigram_score(clean_domain)
        
        # 10. Trigram Score
        features['trigram_score'] = self._calculate_trigram_score(clean_domain)
        
        # 11. Subdomain Depth
        features['subdomain_depth'] = self._calculate_subdomain_depth(domain)
        
        # 12. Unique Character Ratio
        features['unique_char_ratio'] = self._calculate_unique_char_ratio(clean_domain)
        
        # Convert to array in consistent order
        feature_names = [
            'shannon_entropy', 'domain_length', 'vowel_ratio', 'digit_ratio',
            'hyphen_ratio', 'max_consecutive_consonants', 'max_consecutive_digits',
            'hex_ratio', 'bigram_score', 'trigram_score', 'subdomain_depth',
            'unique_char_ratio'
        ]
        
        feature_array = np.array([features[name] for name in feature_names], dtype=np.float32)
        
        # Ensure all features are finite
        feature_array = np.nan_to_num(feature_array, nan=0.0, posinf=1.0, neginf=0.0)
        
        # Clip to reasonable ranges
        feature_array = np.clip(feature_array, 0, 100)
        
        self._last_extract_time = (time.perf_counter() - start_time) * 1000  # ms
        
        return feature_array, features
    
    def _extract_main_domain(self, domain: str) -> str:
        """Extract main domain part (remove TLD, subdomains)"""
        # Remove protocol if present
        domain = re.sub(r'^https?://', '', domain)
        # Remove path and query
        domain = re.sub(r'[/?#].*$', '', domain)
        # Remove port
        domain = re.sub(r':\d+$', '', domain)
        
        # Split by dots and get the second-level domain
        parts = domain.lower().split('.')
        if len(parts) >= 2:
            # Check for common TLDs and return the part before TLD
            # For simplicity, return the entire domain without the last part if it's a TLD
            tlds = {'com', 'org', 'net', 'edu', 'gov', 'mil', 'io', 'uk', 'de', 'fr', 'jp',
                    'cn', 'ru', 'br', 'in', 'au', 'ca', 'it', 'es', 'mx', 'nl', 'se', 'no'}
            if parts[-1] in tlds:
                return '.'.join(parts[:-1]) if len(parts) > 2 else parts[0]
        return domain
    
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not s:
            return 0.0
        # Count character frequencies
        freq = Counter(s)
        total = len(s)
        entropy = 0.0
        for count in freq.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy
    
    def _calculate_vowel_ratio(self, s: str) -> float:
        """Calculate ratio of vowels to total characters"""
        if not s:
            return 0.0
        vowel_count = sum(1 for c in s if c in self.vowels)
        return vowel_count / len(s)
    
    def _calculate_digit_ratio(self, s: str) -> float:
        """Calculate ratio of digits to total characters"""
        if not s:
            return 0.0
        digit_count = sum(1 for c in s if c.isdigit())
        return digit_count / len(s)
    
    def _calculate_hyphen_ratio(self, s: str) -> float:
        """Calculate ratio of hyphens to total characters"""
        if not s:
            return 0.0
        hyphen_count = s.count('-')
        return hyphen_count / len(s)
    
    def _max_consecutive_chars(self, s: str, predicate) -> float:
        """Find maximum consecutive characters matching predicate"""
        if not s:
            return 0.0
        max_count = 0
        current_count = 0
        for c in s:
            if predicate(c):
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 0
        return float(max_count)
    
    def _calculate_hex_ratio(self, s: str) -> float:
        """Calculate ratio of hex characters to total characters"""
        if not s:
            return 0.0
        hex_count = sum(1 for c in s if c.lower() in self.hex_chars)
        return hex_count / len(s)
    
    def _calculate_bigram_score(self, s: str) -> float:
        """Calculate average bigram frequency score"""
        if len(s) < 2:
            return 0.0
        score = 0.0
        count = 0
        for i in range(len(s) - 1):
            bigram = s[i:i+2]
            if bigram in self.bigram_freq:
                score += self.bigram_freq[bigram]
                count += 1
        return score / max(count, 1)
    
    def _calculate_trigram_score(self, s: str) -> float:
        """Calculate average trigram frequency score"""
        if len(s) < 3:
            return 0.0
        score = 0.0
        count = 0
        for i in range(len(s) - 2):
            trigram = s[i:i+3]
            if trigram in self.trigram_freq:
                score += self.trigram_freq[trigram]
                count += 1
        return score / max(count, 1)
    
    def _calculate_subdomain_depth(self, domain: str) -> int:
        """Calculate number of subdomain levels"""
        clean = re.sub(r'^https?://', '', domain)
        clean = re.sub(r'[/?#].*$', '', clean)
        parts = clean.split('.')
        # Subtract 1 for TLD
        return max(0, len(parts) - 1)
    
    def _calculate_unique_char_ratio(self, s: str) -> float:
        """Calculate ratio of unique characters to total characters"""
        if not s:
            return 0.0
        unique_count = len(set(s))
        return unique_count / len(s)
    
    def get_last_extract_time_ms(self) -> float:
        """Get the time taken for the last extraction in milliseconds"""
        return getattr(self, '_last_extract_time', 0.0)
    
    def extract_batch(self, domains: List[str]) -> np.ndarray:
        """Extract features for a batch of domains"""
        features = []
        for domain in domains:
            feature_array, _ = self.extract(domain)
            features.append(feature_array)
        return np.array(features)


# Singleton instance for performance
_default_extractor = None

def get_feature_extractor() -> FeatureExtractor:
    """Get or create the default feature extractor instance"""
    global _default_extractor
    if _default_extractor is None:
        _default_extractor = FeatureExtractor()
    return _default_extractor
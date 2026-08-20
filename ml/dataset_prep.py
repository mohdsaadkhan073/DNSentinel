"""
Dataset Preparation for DGA Detection Training
"""

import os
import json
import csv
import random
import requests
import zipfile
import io
import logging
from typing import List, Tuple, Optional
from pathlib import Path
from urllib.parse import urlparse
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DATA_DIR

logger = logging.getLogger(__name__)

class DatasetPreparer:
    """Prepare clean and DGA datasets for model training"""
    
    def __init__(self):
        self.data_dir = DATA_DIR
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Known DGA families for synthetic generation
        self.dga_families = {
            'conficker': self._gen_conficker,
            'zeus': self._gen_zeus,
            'cryptolocker': self._gen_cryptolocker,
            'dga_simple': self._gen_simple_dga,
            'dga_advanced': self._gen_advanced_dga,
            'banjori': self._gen_banjori,
            'goznym': self._gen_goznym,
        }
        
        # Clean domains (common domains)
        self.common_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.io', '.uk', '.de', '.fr']
        
    def build_dataset(self, clean_count: int = 10000, dga_count: int = 10000) -> Tuple[List[str], List[int]]:
        """
        Build the complete dataset
        
        Returns:
            Tuple of (domains, labels) where label=1 for DGA, 0 for clean
        """
        logger.info("Building dataset...")
        
        # Get clean domains
        clean_domains = self.get_clean_domains(clean_count)
        
        # Get DGA domains
        dga_domains = self.get_dga_domains(dga_count)
        
        # Combine and label
        domains = clean_domains + dga_domains
        labels = [0] * len(clean_domains) + [1] * len(dga_domains)
        
        # Shuffle
        combined = list(zip(domains, labels))
        random.shuffle(combined)
        domains, labels = zip(*combined)
        
        logger.info(f"Dataset ready: {len(domains)} domains ({sum(labels)} DGA, {len(domains) - sum(labels)} clean)")
        return list(domains), list(labels)
    
    def get_clean_domains(self, count: int) -> List[str]:
        """Get clean domain names"""
        logger.info(f"Getting {count} clean domains...")
        
        clean_domains = []
        
        # Try to load from Tranco or similar
        try:
            clean_domains = self._load_tranco_domains(count)
            if len(clean_domains) >= count:
                return clean_domains[:count]
        except Exception as e:
            logger.warning(f"Could not load Tranco domains: {e}")
        
        # Fallback: generate clean domains
        logger.info("Generating clean domains from common words...")
        common_words = [
            'google', 'facebook', 'amazon', 'microsoft', 'apple', 'netflix', 'twitter',
            'instagram', 'youtube', 'github', 'stackoverflow', 'wikipedia', 'reddit',
            'linkedin', 'spotify', 'dropbox', 'slack', 'zoom', 'salesforce', 'adobe',
            'nike', 'adidas', 'puma', 'target', 'walmart', 'bestbuy', 'homedepot',
            'lowes', 'costco', 'kroger', 'wholefoods', 'starbucks', 'mcdonalds',
            'burgerking', 'tacobell', 'pizzahut', 'dominos', 'subway', 'chickfila',
            'sony', 'samsung', 'lg', 'panasonic', 'philips', 'canon', 'nikon',
            'oracle', 'ibm', 'cisco', 'vmware', 'dell', 'hp', 'lenovo', 'acer'
        ]
        
        # Add numbers and variations
        while len(clean_domains) < count:
            word = random.choice(common_words)
            if random.random() < 0.2:
                word += str(random.randint(1, 999))
            tld = random.choice(self.common_tlds)
            domain = word + tld
            if domain not in clean_domains:
                clean_domains.append(domain)
        
        return clean_domains[:count]
    
    def get_dga_domains(self, count: int) -> List[str]:
        """Get DGA domain names"""
        logger.info(f"Getting {count} DGA domains...")
        
        dga_domains = []
        
        # Try to load from known DGA dataset
        try:
            dga_domains = self._load_netlab_dga(count)
            if len(dga_domains) >= count:
                return dga_domains[:count]
        except Exception as e:
            logger.warning(f"Could not load Netlab DGA data: {e}")
        
        # Generate DGA domains using multiple algorithms
        logger.info("Generating DGA domains synthetically...")
        
        # Use multiple DGA generators
        generators = [
            self._gen_conficker,
            self._gen_zeus,
            self._gen_cryptolocker,
            self._gen_simple_dga,
            self._gen_advanced_dga,
            self._gen_banjori,
            self._gen_goznym,
        ]
        
        while len(dga_domains) < count:
            gen = random.choice(generators)
            domain = gen()
            # Ensure domain is valid and not too long
            if domain and len(domain) < 30 and '.' in domain:
                if domain not in dga_domains:
                    dga_domains.append(domain)
        
        return dga_domains[:count]
    
    def _load_tranco_domains(self, count: int) -> List[str]:
        """Load top domains from Tranco list"""
        cache_path = self.data_dir / "tranco_top_1m.csv"
        
        # Try to read from cache
        if cache_path.exists():
            with open(cache_path, 'r') as f:
                reader = csv.reader(f)
                return [row[1] for row in reader if len(row) > 1][:count]
        
        # Download from Tranco
        try:
            url = "https://tranco-list.eu/top-1m.csv.zip"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                    # Find the CSV file in the zip
                    csv_file = [f for f in z.namelist() if f.endswith('.csv')][0]
                    with z.open(csv_file) as f:
                        reader = csv.reader(io.TextIOWrapper(f))
                        domains = []
                        for row in reader:
                            if len(row) > 1:
                                domains.append(row[1])
                            if len(domains) >= count:
                                break
                        
                        # Cache for future use
                        with open(cache_path, 'w') as cf:
                            writer = csv.writer(cf)
                            for i, domain in enumerate(domains):
                                writer.writerow([i+1, domain])
                        
                        return domains
        except Exception as e:
            logger.warning(f"Failed to download Tranco list: {e}")
        
        return []
    
    def _load_netlab_dga(self, count: int) -> List[str]:
        """Load DGA domains from Netlab 360 dataset"""
        cache_path = self.data_dir / "netlab_dga_domains.txt"
        
        if cache_path.exists():
            with open(cache_path, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
                return domains[:count]
        
        # Try to fetch from Netlab
        try:
            # Netlab provides DGA domains through their API
            # Using the archived dataset
            url = "https://data.netlab.360.com/dga/dga-data/"
            response = requests.get(url, timeout=10)
            # If successful, parse and cache
            # For now, we'll use synthetic generation
            return []
        except Exception as e:
            logger.warning(f"Failed to load Netlab DGA: {e}")
            return []
    
    # DGA Generation Algorithms
    
    def _gen_conficker(self) -> str:
        """Generate Conficker-like DGA domain"""
        # Conficker uses date-based generation
        seed = random.randint(0, 0xFFFFFFFF)
        # Simplified generation
        length = random.randint(6, 10)
        domain = ''.join(chr(97 + ((seed >> i) & 1) * random.randint(0, 25) % 26) for i in range(length))
        tld = random.choice(['com', 'org', 'net', 'info'])
        return domain + '.' + tld
    
    def _gen_zeus(self) -> str:
        """Generate Zeus-like DGA domain"""
        # Zeus uses simple random strings with numbers
        length = random.randint(6, 12)
        domain = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(length))
        tld = random.choice(['com', 'org', 'net', 'biz', 'info'])
        return domain + '.' + tld
    
    def _gen_cryptolocker(self) -> str:
        """Generate CryptoLocker-like DGA domain"""
        # CryptoLocker uses longer random domains
        length = random.randint(8, 15)
        domain = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(length))
        tld = random.choice(['com', 'org', 'net', 'ru', 'de', 'uk'])
        return domain + '.' + tld
    
    def _gen_simple_dga(self) -> str:
        """Generate simple DGA domains"""
        # Simple random strings with numbers
        length = random.randint(6, 12)
        domain = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(length))
        tld = random.choice(['com', 'org', 'net', 'xyz', 'club'])
        return domain + '.' + tld
    
    def _gen_advanced_dga(self) -> str:
        """Generate more sophisticated DGA-like domains"""
        # Use Markov-like patterns with high entropy
        chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
        # Start with random seed
        length = random.randint(8, 16)
        domain = ''
        for _ in range(length):
            # Tendency for long sequences of consonants
            if len(domain) > 0 and domain[-1] in 'bcdfghjklmnpqrstvwxyz':
                # Sometimes break with a vowel
                if random.random() < 0.3:
                    domain += random.choice('aeiou')
                else:
                    domain += random.choice('bcdfghjklmnpqrstvwxyz')
            else:
                domain += random.choice(chars)
        tld = random.choice(['com', 'org', 'net', 'info'])
        return domain + '.' + tld
    
    def _gen_banjori(self) -> str:
        """Generate Banjori-like DGA domain"""
        # Banjori uses combination of two random strings
        part1_length = random.randint(4, 7)
        part2_length = random.randint(4, 7)
        part1 = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(part1_length))
        part2 = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(part2_length))
        domain = part1 + part2
        tld = random.choice(['com', 'org', 'net', 'ru', 'cn'])
        return domain + '.' + tld
    
    def _gen_goznym(self) -> str:
        """Generate Goznym-like DGA domain"""
        # Goznym uses dictionary words with suffixes
        words = ['home', 'world', 'live', 'news', 'site', 'blog', 'shop', 'game', 'life', 'love',
                 'nice', 'good', 'best', 'free', 'easy', 'safe', 'fast', 'cool', 'fresh', 'real']
        word = random.choice(words)
        if random.random() < 0.5:
            word += str(random.randint(1, 999))
        tld = random.choice(['com', 'org', 'net', 'io', 'co'])
        return word + '.' + tld

if __name__ == "__main__":
    # Test dataset preparation
    preparer = DatasetPreparer()
    domains, labels = preparer.build_dataset(100, 100)
    print(f"Generated {len(domains)} domains")
    print(f"DGA count: {sum(labels)}")
    print(f"Clean count: {len(domains) - sum(labels)}")
    print("\nSample DGA domains:")
    for d, l in zip(domains[:20], labels[:20]):
        if l == 1:
            print(f"  {d}")
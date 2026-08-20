import json
import re
from typing import List, Dict, Any, Optional
from threat_intel.ioc_store import normalize_domain

def extract_domains_from_pattern(pattern: str) -> List[str]:
    """
    Regex helper to extract domain names from STIX pattern strings.
    Handles:
    - [domain-name:value = 'evil.com']
    - [domain-name:value = "evil.com"]
    - [domain-name:value IN ('evil1.com', 'evil2.com')]
    """
    if not pattern:
        return []
        
    domains = []
    
    # 1. Match equality constraints (both single and double quotes)
    eq_matches = re.findall(r"domain-name:value\s*=\s*['\"]([^'\"]+)['\"]", pattern)
    for m in eq_matches:
        domains.append(m)
        
    # 2. Match IN lists: domain-name:value IN ('domain1.com', 'domain2.com')
    in_matches = re.findall(r"domain-name:value\s+IN\s+\((.*?)\)", pattern, re.IGNORECASE)
    for m in in_matches:
        # Split by comma and clean up quotes/spaces
        items = re.split(r"\s*,\s*", m)
        for item in items:
            cleaned = item.strip("'\" ")
            if cleaned:
                domains.append(cleaned)
                
    return domains

def map_threat_category(obj: Dict[str, Any]) -> str:
    """
    Map STIX indicator type, name, or description to standard categories.
    Standard Categories:
    - Command & Control (C2)
    - Phishing
    - Botnet
    - Spyware
    - Malware Host
    - Malicious Domain (Fallback)
    """
    indicator_types = obj.get("indicator_types", [])
    name = obj.get("name", "").lower()
    description = obj.get("description", "").lower()
    
    # Combine keywords to classify
    keywords = " ".join([t.lower() for t in indicator_types] + [name, description])
    
    if "c2" in keywords or "command-and-control" in keywords or "command and control" in keywords:
        return "Command & Control (C2)"
    elif "phish" in keywords or "credential" in keywords or "login-secure" in keywords:
        return "Phishing"
    elif "bot" in keywords or "ddos" in keywords:
        return "Botnet"
    elif "spyware" in keywords or "trojan" in keywords or "adware" in keywords or "ransomware" in keywords:
        return "Spyware"
    elif "malware" in keywords or "virus" in keywords or "worm" in keywords:
        return "Malware Host"
        
    return "Malicious Domain"

class STIXParser:
    """
    STIX 2.1 JSON Threat Feed Parser.
    Owned by Member 3 (Threat Intel Lead).
    """

    @staticmethod
    def parse_stix_json(stix_content: str, default_source: str = "STIX 2.1 Feed") -> List[Dict[str, Any]]:
        """
        Parses STIX 2.1 JSON bundle content and extracts threat indicators.
        Returns a list of dicts:
        {
            "domain": str (normalized),
            "category": str (mapped threat category),
            "confidence": float,
            "source": str,
            "details": str,
            "timestamp": str
        }
        """
        extracted_iocs = []
        seen_domains = {}  # For deduplication: domain -> indicator dict
        
        if not stix_content:
            return []

        try:
            bundle = json.loads(stix_content)
            
            # Simple check for objects array
            objects = bundle.get("objects", [])
            for obj in objects:
                # 1. Ignore unsupported object types (only indicators are relevant)
                if obj.get("type") != "indicator":
                    continue
                
                pattern = obj.get("pattern", "")
                # 2. Ignore indicators without domain patterns
                if "domain-name:value" not in pattern:
                    continue
                
                # Extract domain values from pattern string
                domains = extract_domains_from_pattern(pattern)
                if not domains:
                    continue
                
                # Extract metadata fields
                confidence = float(obj.get("confidence", 80.0))
                category = map_threat_category(obj)
                
                # Use specified source feed name or fallback to object creator
                source = obj.get("created_by_ref", default_source)
                details = obj.get("description") or obj.get("name", "STIX Indicator")
                timestamp = obj.get("created") or obj.get("modified") or ""
                
                for raw_domain in domains:
                    normalized = normalize_domain(raw_domain)
                    if not normalized:
                        continue
                    
                    ioc_entry = {
                        "domain": normalized,
                        "category": category,
                        "confidence": confidence,
                        "source": source,
                        "details": details,
                        "timestamp": timestamp
                    }
                    
                    # Deduplication check: Keep highest confidence
                    if normalized in seen_domains:
                        existing = seen_domains[normalized]
                        if ioc_entry["confidence"] > existing["confidence"]:
                            seen_domains[normalized] = ioc_entry
                    else:
                        seen_domains[normalized] = ioc_entry
                        
            extracted_iocs = list(seen_domains.values())
            
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            # Gracefully handle malformed/invalid STIX JSON inputs
            pass
            
        return extracted_iocs

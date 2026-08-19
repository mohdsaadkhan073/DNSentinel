import json
from typing import List, Dict, Any

class STIXParser:
    """
    STIX 2.1 JSON Threat Feed Parser.
    Owned by Member 3 (Threat Intel Lead).
    """

    @staticmethod
    def parse_stix_json(stix_content: str) -> List[Dict[str, Any]]:
        extracted_iocs = []
        try:
            bundle = json.loads(stix_content)
            objects = bundle.get("objects", [])
            for obj in objects:
                if obj.get("type") == "indicator":
                    pattern = obj.get("pattern", "")
                    if "domain-name:value" in pattern:
                        # Extract domain value from pattern string
                        domain = pattern.split("=")[-1].strip(" '[]\"")
                        extracted_iocs.append({
                            "domain": domain,
                            "category": obj.get("name", "STIX Indicator")
                        })
        except Exception:
            pass
        return extracted_iocs

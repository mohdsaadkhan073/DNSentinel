import time
import json
import requests
from typing import List, Dict, Any, Tuple, Optional
from threat_intel.stix_parser import STIXParser

class TAXIIClient:
    """
    TAXII 2.1 REST API Client.
    Supports discovery, collection selection, Range-header pagination, 
    authentication, and robust error fallback.
    Owned by Member 3 (Threat Intel Lead).
    """

    def __init__(
        self,
        server_url: str = "https://cti-taxii.mitre.org",
        api_root_path: str = "stix",
        collection_id: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_token: Optional[str] = None,
        timeout: int = 10
    ):
        """
        Configure the TAXII 2.1 client. Configuration parameters are not hardcoded.
        """
        self.server_url = server_url.rstrip("/")
        # format api_root_path correctly (ensure leading slash, strip trailing)
        clean_root = api_root_path.strip("/")
        self.api_root_path = f"/{clean_root}" if clean_root else ""
        
        self.collection_id = collection_id
        self.username = username
        self.password = password
        self.auth_token = auth_token
        self.timeout = timeout
        
        # Build request headers
        self.headers = {
            "Accept": "application/taxii+json;version=2.1",
            "User-Agent": "EliteCore-DNSentinel/2.0"
        }
        if self.auth_token:
            self.headers["Authorization"] = f"Bearer {self.auth_token}"

    @property
    def auth(self):
        if self.username and self.password is not None:
            return (self.username, self.password)
        return None

    def discover_api_roots(self) -> List[str]:
        """
        Queries the Server Discovery endpoint to obtain available API Roots.
        """
        url = f"{self.server_url}/taxii2/"
        try:
            response = requests.get(url, headers=self.headers, auth=self.auth, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            return data.get("api_roots", [])
        except requests.exceptions.HTTPError as e:
            if e.response.status_code in (401, 403):
                raise PermissionError("TAXII discovery authentication failed")
            raise RuntimeError(f"TAXII discovery HTTP error: {e}")
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"TAXII connection failure during discovery: {e}")

    def get_collections(self, api_root_url: str) -> List[Dict[str, Any]]:
        """
        Lists available collections for a specific API root.
        """
        base = api_root_url if api_root_url.endswith("/") else f"{api_root_url}/"
        url = f"{base}collections/"
        try:
            response = requests.get(url, headers=self.headers, auth=self.auth, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            return data.get("collections", [])
        except requests.exceptions.HTTPError as e:
            if e.response.status_code in (401, 403):
                raise PermissionError("TAXII collections authentication failed")
            raise RuntimeError(f"TAXII collections HTTP error: {e}")
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"TAXII connection failure during collections: {e}")

    def fetch_collection_objects(
        self, 
        api_root_url: str, 
        collection_id: str, 
        start_index: int = 0, 
        limit: int = 100
    ) -> Dict[str, Any]:
        """
        Fetches indicator objects from a specified collection.
        Implements range-based pagination using the standard Range header.
        """
        base = api_root_url if api_root_url.endswith("/") else f"{api_root_url}/"
        url = f"{base}collections/{collection_id}/objects/"
        
        headers = self.headers.copy()
        end_index = start_index + limit - 1
        headers["Range"] = f"items {start_index}-{end_index}"
        
        try:
            response = requests.get(
                url, 
                params={"type": "indicator"}, 
                headers=headers, 
                auth=self.auth, 
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code in (401, 403):
                raise PermissionError("TAXII fetch objects authentication failed")
            elif e.response.status_code == 416:
                # Range Not Satisfiable: end of list or empty collection
                return {"type": "bundle", "objects": []}
            raise RuntimeError(f"TAXII fetch objects HTTP error: {e}")
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"TAXII connection failure during object fetch: {e}")

    def poll_and_parse_feed(
        self, 
        api_root_url: Optional[str] = None, 
        collection_id: Optional[str] = None
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Polls the endpoint, paginates through all available objects, 
        extracts domains via STIXParser, and records execution metrics.
        Returns:
            (list of parsed indicators, status metadata dict)
        """
        start_time = time.perf_counter()
        
        root = api_root_url or f"{self.server_url}{self.api_root_path}"
        coll_id = collection_id or self.collection_id
        
        status_info = {
            "status": "FAILED",
            "count": 0,
            "error_message": None,
            "latency_ms": 0.0
        }
        
        if not coll_id:
            latency = (time.perf_counter() - start_time) * 1000.0
            status_info.update({
                "error_message": "TAXII Collection ID is not configured",
                "latency_ms": round(latency, 2)
            })
            return [], status_info
            
        all_objects = []
        limit = 100
        start = 0
        
        try:
            while True:
                bundle_data = self.fetch_collection_objects(
                    api_root_url=root,
                    collection_id=coll_id,
                    start_index=start,
                    limit=limit
                )
                
                # Check for objects or results
                objects = bundle_data.get("objects", [])
                if not objects:
                    break
                    
                all_objects.extend(objects)
                
                # Less items than limit implies pagination completed
                if len(objects) < limit:
                    break
                    
                start += limit
                
            # Wrap all fetched objects in a unified STIX 2.1 Bundle
            full_bundle = {
                "type": "bundle",
                "id": "bundle--temp",
                "objects": all_objects
            }
            
            # Feed parser executes normalization inside STIXParser
            parsed_iocs = STIXParser.parse_stix_json(
                json.dumps(full_bundle), 
                default_source=f"TAXII: {coll_id[:8]}"
            )
            
            latency = (time.perf_counter() - start_time) * 1000.0
            
            status_info.update({
                "status": "SUCCESS",
                "count": len(parsed_iocs),
                "latency_ms": round(latency, 2)
            })
            
            return parsed_iocs, status_info
            
        except Exception as e:
            latency = (time.perf_counter() - start_time) * 1000.0
            status_info.update({
                "status": "FAILED",
                "count": 0,
                "error_message": str(e),
                "latency_ms": round(latency, 2)
            })
            return [], status_info

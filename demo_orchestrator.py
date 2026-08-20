import sys
# Ensure current directory is on python path
sys.path.append('.')

from core.orchestrator import Orchestrator
from threat_intel.ioc_store import IOCStore
from shared.schemas import DNSQuery

def main():
    # Initialize store and orchestrator
    print("[Demo] Initializing in-memory IOC store and orchestrator...")
    store = IOCStore()
    orchestrator = Orchestrator(ioc_store=store)
    print(f"[Demo] Store initialized with {store.total_iocs()} indicators.")
    print("=" * 60)

    domains = [
        "bad-c2.com",
        "google.com",
        "sub.bad-c2.com",
        "BAD-C2.COM"
    ]

    for idx, domain in enumerate(domains, 1):
        print(f"Case {idx}: Domain = {domain}")
        query = DNSQuery(
            query_id=f"demo-q-{idx}",
            domain=domain,
            client_ip="192.168.1.5"
        )
        
        decision = orchestrator.process_query(query)
        intel = decision.intel_result
        
        print(f"  Threat Intel Matched : {intel.matched}")
        print(f"  Action Decision      : {decision.action.value}")
        print(f"  Composite Risk Score : {decision.composite_risk_score}")
        if intel.matched:
            print(f"  Threat Category      : {intel.threat_category}")
            print(f"  Confidence Score     : {intel.intel_score}")
            print(f"  Source Feed          : {intel.source_feed}")
        print(f"  Rationale            : {decision.rationale}")
        print("-" * 60)

if __name__ == "__main__":
    main()

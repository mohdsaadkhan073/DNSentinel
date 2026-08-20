import os
import time
import numpy as np
from threat_intel.ioc_store import IOCStore
from threat_intel.threat_db import ThreatDB

def run_benchmark():
    db_path = "benchmark_threat_intelligence.db"
    
    # Ensure clean database setup for benchmark
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass

    print("=" * 60)
    print("ELITECORE DNSENTINEL - MEMBER 3 PERFORMANCE BENCHMARK")
    print("=" * 60)
    print("[Benchmark] Initializing SQLite ThreatDB and seeding 50,000+ IOCs...")
    
    # Measure database instantiation and loading time
    start_init = time.perf_counter()
    store = IOCStore(db_path=db_path)
    init_time_ms = (time.perf_counter() - start_init) * 1000.0
    
    total_iocs = store.total_iocs()
    print(f"[Benchmark] Total IOCs loaded: {total_iocs}")
    print(f"[Benchmark] Startup loading time (disk-to-memory): {init_time_ms:.2f} ms")
    
    # Fetch a few domains from DB to test random lookups
    db = ThreatDB(db_path)
    iocs = db.load_all_iocs()
    synth_domains = [d for d in iocs.keys() if d.startswith("synth-")]
    
    # Test cases setup
    test_cases = {
        "Exact Malicious Domain (bad-c2.com)": "bad-c2.com",
        "Exact Clean Domain (google.com)": "google.com",
        "Subdomain Block Match (sub.bad-c2.com)": "sub.bad-c2.com",
        "Random Synthetic Domain Lookup": synth_domains[0] if synth_domains else "synth-botnet-node-10.net"
    }

    iterations = 10000
    
    for name, domain in test_cases.items():
        print("-" * 60)
        print(f"Benchmarking Lookup: {name} (domain: {domain})")
        print(f"Running {iterations} iterations...")
        
        latencies = []
        
        # Warmup loop
        for _ in range(100):
            store.lookup(domain)
            
        start_run = time.perf_counter()
        for _ in range(iterations):
            t0 = time.perf_counter()
            store.lookup(domain)
            latencies.append((time.perf_counter() - t0) * 1000.0) # in milliseconds
            
        elapsed_total = (time.perf_counter() - start_run)
        
        # Calculate statistics
        latencies = np.array(latencies)
        avg_latency = np.mean(latencies)
        min_latency = np.min(latencies)
        max_latency = np.max(latencies)
        p95 = np.percentile(latencies, 95)
        p99 = np.percentile(latencies, 99)
        throughput = iterations / elapsed_total
        
        print(f"  Average Latency : {avg_latency:.4f} ms")
        print(f"  Minimum Latency : {min_latency:.4f} ms")
        print(f"  Maximum Latency : {max_latency:.4f} ms")
        print(f"  95th Percentile : {p95:.4f} ms")
        print(f"  99th Percentile : {p99:.4f} ms")
        print(f"  Throughput      : {throughput:.2f} queries/sec")

    # Cleanup benchmark database
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass
    print("=" * 60)
    print("BENCHMARK COMPLETED")
    print("=" * 60)

if __name__ == "__main__":
    run_benchmark()

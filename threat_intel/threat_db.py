import sqlite3
import os
import time
from typing import Dict, Any, List, Tuple, Optional

class ThreatDB:
    """
    SQLite Threat Database Manager for offline persistence, metadata tracking, and seeding.
    Owned by Member 3 (Threat Intel Lead).
    """
    def __init__(self, db_path: str = "threat_intelligence.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """
        Initialize sqlite tables. Implements schema migration safely.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create threat_iocs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_iocs (
                domain TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                confidence REAL NOT NULL,
                source_feed TEXT NOT NULL,
                details TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create feed_health table (with basic fields first)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS feed_health (
                feed_name TEXT PRIMARY KEY,
                last_sync TIMESTAMP,
                status TEXT NOT NULL,
                indicator_count INTEGER DEFAULT 0,
                error_message TEXT,
                latency_ms REAL
            )
        """)
        conn.commit()

        # Database Schema Migration: add advanced health columns if missing
        try:
            cursor.execute("SELECT last_attempt FROM feed_health LIMIT 1")
        except sqlite3.OperationalError:
            # Columns do not exist, perform alter table
            cursor.execute("ALTER TABLE feed_health ADD COLUMN last_attempt TIMESTAMP")
            cursor.execute("ALTER TABLE feed_health ADD COLUMN consecutive_failures INTEGER DEFAULT 0")
            conn.commit()
            
        conn.close()

    def seed_database_if_empty(self, target_count: int = 50000):
        """
        Pre-seeds the database with 50,000+ realistic synthetic domains if it is empty.
        Uses single transactional block for high-speed write (~1s total).
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM threat_iocs")
        count = cursor.fetchone()[0]
        
        if count == 0:
            # Begin explicit transaction
            conn.execute("BEGIN TRANSACTION")
            
            # 1. Critical default/manual test IOCs
            defaults = [
                ("bad-c2.com", "Command & Control (C2)", 100.0, "demo_seed", "Synthetic development/demo IOC"),
                ("malware-command-center.org", "Malware Host", 100.0, "demo_seed", "Synthetic development/demo IOC"),
                ("phishing-login-secure.net", "Phishing", 100.0, "demo_seed", "Synthetic development/demo IOC"),
                ("evil-tracker.info", "Spyware", 100.0, "demo_seed", "Synthetic development/demo IOC"),
                ("botnet-c2-node.xyz", "Botnet", 100.0, "demo_seed", "Synthetic development/demo IOC")
            ]
            for domain, category, conf, source, details in defaults:
                cursor.execute("""
                    INSERT OR REPLACE INTO threat_iocs (domain, category, confidence, source_feed, details)
                    VALUES (?, ?, ?, ?, ?)
                """, (domain, category, conf, source, details))
            
            # 2. Bulk synthetic IOC generation (must be clearly marked as synthetic/demo)
            categories = ["Command & Control (C2)", "Malware Host", "Phishing", "Spyware", "Botnet"]
            tlds = ["com", "net", "org", "xyz", "info", "ru", "cn", "cc"]
            
            remaining = target_count - len(defaults)
            batch = []
            
            for i in range(1, remaining + 1):
                category = categories[i % len(categories)]
                tld = tlds[i % len(tlds)]
                cat_label = category.split()[0].lower().strip(" &()")
                domain = f"synth-{cat_label}-node-{i}.{tld}"
                
                batch.append((domain, category, 85.0 + (i % 15), "demo_seed", "Synthetic development/demo IOC"))
                
                if len(batch) >= 5000:
                    cursor.executemany("""
                        INSERT OR IGNORE INTO threat_iocs (domain, category, confidence, source_feed, details)
                        VALUES (?, ?, ?, ?, ?)
                    """, batch)
                    batch = []
            
            if batch:
                cursor.executemany("""
                    INSERT OR IGNORE INTO threat_iocs (domain, category, confidence, source_feed, details)
                    VALUES (?, ?, ?, ?, ?)
                """, batch)
            
            conn.commit()
            
        conn.close()

    def load_all_iocs(self) -> Dict[str, Dict[str, Any]]:
        """
        Fetch all IOC records to construct the in-memory cache.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT domain, category, confidence, source_feed, details FROM threat_iocs")
        
        store = {}
        for domain, category, confidence, source, details in cursor.fetchall():
            store[domain] = {
                "category": category,
                "confidence": confidence,
                "source": source,
                "details": details
            }
        
        conn.close()
        return store

    def add_iocs_batch(self, iocs: List[Tuple[str, str, float, str, str]]):
        """
        Insert or replace a batch of IOCs. Implements transaction safety with automated rollback.
        iocs: List of tuples (domain, category, confidence, source_feed, details)
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            conn.execute("BEGIN TRANSACTION")
            cursor.executemany("""
                INSERT OR REPLACE INTO threat_iocs (domain, category, confidence, source_feed, details)
                VALUES (?, ?, ?, ?, ?)
            """, iocs)
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise RuntimeError(f"Database batch update failed: transaction rolled back. Detail: {e}")
        finally:
            conn.close()

    def update_feed_health(self, feed_name: str, status: str, count: int, error_msg: Optional[str] = None, latency_ms: float = 0.0):
        """
        Log feed health and synchronization telemetry. Handles consecutive failures and last successful sync tracking.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Retrieve previous consecutive failures and last successful sync
        cursor.execute("SELECT consecutive_failures, last_sync FROM feed_health WHERE feed_name = ?", (feed_name,))
        row = cursor.fetchone()
        
        prev_failures = 0
        prev_sync = None
        if row:
            prev_failures = row[0] or 0
            prev_sync = row[1]
            
        consecutive_failures = 0
        last_sync = prev_sync
        current_time = time.strftime('%Y-%m-%d %H:%M:%S')
        
        if status in ("SUCCESS", "healthy/success"):
            consecutive_failures = 0
            last_sync = current_time
        else:
            consecutive_failures = prev_failures + 1

        cursor.execute("""
            INSERT OR REPLACE INTO feed_health (
                feed_name, last_sync, last_attempt, status, 
                indicator_count, error_message, latency_ms, consecutive_failures
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (feed_name, last_sync, current_time, status, count, error_msg, latency_ms, consecutive_failures))
        
        conn.commit()
        conn.close()

    def get_feed_health(self) -> List[Dict[str, Any]]:
        """
        Retrieve all current feed health logs.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT feed_name, last_sync, last_attempt, status, 
                   indicator_count, error_message, latency_ms, consecutive_failures 
            FROM feed_health
        """)
        
        health_list = []
        for name, last_sync, last_attempt, status, count, error, latency, failures in cursor.fetchall():
            health_list.append({
                "feed_name": name,
                "last_sync": last_sync,
                "last_attempt": last_attempt,
                "status": status,
                "indicator_count": count,
                "error_message": error,
                "latency_ms": latency,
                "consecutive_failures": failures
            })
        conn.close()
        return health_list

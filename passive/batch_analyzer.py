from typing import List, Dict, Any
from shared.schemas import SecurityDecision, ActionDecision

class BatchAnalyzer:
    """
    Forensic Batch Upload Processor.
    Owned by Member 5.
    """

    def __init__(self, orchestrator=None):
        self.orchestrator = orchestrator

    def analyze_batch(self, queries: list) -> Dict[str, Any]:
        decisions: List[SecurityDecision] = []
        total = len(queries)
        blocked = 0
        suspicious = 0
        allowed = 0

        for q in queries:
            if self.orchestrator:
                d = self.orchestrator.process_query(q)
            else:
                # Basic fallback
                d = SecurityDecision(
                    decision_id=q.query_id,
                    query=q,
                    action=ActionDecision.ALLOW,
                    composite_risk_score=10.0,
                    intel_result=None,
                    ml_result=None,
                    tunnel_result=None,
                    latency_ms=1.0,
                    rationale="Allowed"
                )
            
            decisions.append(d)
            if d.action == ActionDecision.BLOCK:
                blocked += 1
            elif d.action == ActionDecision.SUSPICIOUS:
                suspicious += 1
            else:
                allowed += 1

        return {
            "total_queries": total,
            "blocked_count": blocked,
            "suspicious_count": suspicious,
            "allowed_count": allowed,
            "decisions": decisions
        }

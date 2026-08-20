import math
from shared.schemas import (
    ThreatIntelResult,
    MLDgaResult,
    TunnelResult,
    ActionDecision
)
from shared.config import (
    RISK_THRESHOLD_BLOCK,
    RISK_THRESHOLD_SUSPICIOUS,
    WEIGHT_THREAT_INTEL,
    WEIGHT_ML_DGA,
    WEIGHT_TUNNEL,
    WEIGHT_BEHAVIOR
)

class RiskEngine:
    """
    Canonical Risk Engine for EliteCore DNS Security Platform.
    Calculates unified risk score based on Threat Intel, ML DGA, Tunneling, and Behavioral inputs.
    """

    @staticmethod
    def calculate_risk(
        intel: ThreatIntelResult,
        ml: MLDgaResult,
        tunnel: TunnelResult,
        behavior_score: float = 0.0
    ) -> tuple[float, ActionDecision, str]:
        """
        Calculates composite risk score and outputs (score, ActionDecision, rationale).
        """
        intel_score = 100.0 if intel.matched else intel.intel_score
        ml_score = ml.dga_probability * 100.0
        tunnel_score = tunnel.tunnel_score

        # Canonical Risk Formula:
        # RiskScore = Min(100, round(1.0 * Intel + 0.40 * ML + 0.35 * Tunnel + 0.25 * Behavior))
        raw_score = (
            (WEIGHT_THREAT_INTEL * intel_score) +
            (WEIGHT_ML_DGA * ml_score) +
            (WEIGHT_TUNNEL * tunnel_score) +
            (WEIGHT_BEHAVIOR * behavior_score)
        )
        
        composite_score = min(100.0, float(round(raw_score, 2)))

        # Decision Boundaries
        if intel.matched or composite_score >= RISK_THRESHOLD_BLOCK:
            decision = ActionDecision.BLOCK
            if intel.matched:
                rationale = f"Blocked: Direct Threat Intel match ({intel.threat_category or 'Malicious Indicator'})."
            else:
                rationale = f"Blocked: High composite risk score ({composite_score:.1f} >= {RISK_THRESHOLD_BLOCK})."
        elif tunnel.is_tunnel or composite_score >= RISK_THRESHOLD_SUSPICIOUS:
            decision = ActionDecision.SUSPICIOUS
            if tunnel.is_tunnel:
                rationale = f"Suspicious: DNS Tunneling activity flagged ({tunnel.reason or 'Behavioral anomaly'})."
            else:
                rationale = f"Suspicious: Moderate risk score ({composite_score:.1f}). Flagged for monitoring."
        else:
            decision = ActionDecision.ALLOW
            rationale = f"Allowed: Low risk score ({composite_score:.1f}). Domain clean."

        return composite_score, decision, rationale

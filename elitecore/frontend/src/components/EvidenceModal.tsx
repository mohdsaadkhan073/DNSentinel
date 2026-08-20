import type { CSSProperties } from "react";
import type { SecurityDecision } from "../types/security";
import StatusBadge from "./StatusBadge";
import RiskGauge from "./RiskGauge";
import { CloseIcon, ShieldIcon, BugIcon, AlertTriangleIcon, PrinterIcon } from "./icons";
import { mockNetworkSegment } from "../utils/network";

interface EvidenceModalProps {
  decision: SecurityDecision | null;
  loading: boolean;
  onClose: () => void;
}

export default function EvidenceModal({ decision, loading, onClose }: EvidenceModalProps) {
  if (!decision && !loading) return null;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <button className="modal__close" onClick={onClose} aria-label="Close">
          <CloseIcon />
        </button>

        {loading || !decision ? (
          <div className="modal__loading">Loading evidence...</div>
        ) : (
          <>
            <div className="modal__header">
              <div>
                <div className="modal__label">DOMAIN</div>
                <div className="modal__domain">{decision.domain}</div>
              </div>
              <StatusBadge decision={decision.decision} />
            </div>

            <div className="modal__source">
              <span className="modal__source-ip">{decision.client_ip}</span>
              <span className="modal__source-sep">&middot;</span>
              <span>{mockNetworkSegment(decision.client_ip)}</span>
              <span className="modal__source-sep">&middot;</span>
              <span>{decision.query_type} record</span>
            </div>

            <RiskGauge score={decision.risk_score} />

            <div className="evidence-grid">
              <div className="evidence-card" style={{ "--tone-color": "var(--accent-2)" } as CSSProperties}>
                <ShieldIcon className="evidence-card__icon" />
                <div className="evidence-card__title">Threat Intel</div>
                <div className="evidence-card__metric">{Math.round(decision.evidence.threat_intel.confidence * 100)}%</div>
                <div className="evidence-card__meta">
                  {decision.evidence.threat_intel.matched ? decision.evidence.threat_intel.category : "no match"}
                </div>
              </div>

              <div className="evidence-card" style={{ "--tone-color": "var(--amber)" } as CSSProperties}>
                <BugIcon className="evidence-card__icon" />
                <div className="evidence-card__title">ML / DGA</div>
                <div className="evidence-card__metric">{Math.round(decision.evidence.dga.probability * 100)}%</div>
                <div className="evidence-card__meta">{decision.evidence.dga.classification}</div>
              </div>

              <div className="evidence-card" style={{ "--tone-color": "var(--red)" } as CSSProperties}>
                <AlertTriangleIcon className="evidence-card__icon" />
                <div className="evidence-card__title">Tunneling</div>
                <div className="evidence-card__metric">{Math.round(decision.evidence.tunneling.rate * 100)}%</div>
                <div className="evidence-card__meta">{decision.evidence.tunneling.detected ? "detected" : "clear"}</div>
              </div>
            </div>

            <div className="evidence-rationale">
              <h4>Why was this flagged?</h4>
              <p>{decision.rationale}</p>
            </div>

            <button className="btn modal__print-btn" onClick={() => window.print()}>
              <PrinterIcon />
              Print / Export Report
            </button>
          </>
        )}
      </div>
    </div>
  );
}

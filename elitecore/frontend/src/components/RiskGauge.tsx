// Semi-circle risk gauge, thresholds mirror backend/config.py (RISK_LOW_MAX=29,
// RISK_MEDIUM_MAX=59, RISK_HIGH_MAX=79).
const RADIUS = 80;
const ARC_LENGTH = Math.PI * RADIUS;

function tier(risk: number): { label: string; color: string } {
  if (risk <= 29) return { label: "LOW", color: "var(--green)" };
  if (risk <= 59) return { label: "MEDIUM", color: "var(--amber)" };
  if (risk <= 79) return { label: "HIGH", color: "var(--orange)" };
  return { label: "CRITICAL", color: "var(--red)" };
}

export default function RiskGauge({ score }: { score: number }) {
  const clamped = Math.max(0, Math.min(100, score));
  const { label, color } = tier(clamped);
  const offset = ARC_LENGTH * (1 - clamped / 100);

  return (
    <div className="risk-gauge">
      <svg viewBox="0 0 200 112" className="risk-gauge__svg">
        <path d="M20,100 A80,80 0 0 1 180,100" className="risk-gauge__track" />
        <path
          d="M20,100 A80,80 0 0 1 180,100"
          className="risk-gauge__value"
          style={{
            stroke: color,
            strokeDasharray: ARC_LENGTH,
            strokeDashoffset: offset,
          }}
        />
      </svg>
      <div className="risk-gauge__readout">
        <span className="risk-gauge__number">{clamped}</span>
        <span className="risk-gauge__scale">/ 100</span>
      </div>
      <div className="risk-gauge__tier" style={{ color }}>
        {label}
      </div>
    </div>
  );
}

import type { DNSQuerySummary } from "../types/security";
import { SirenIcon } from "./icons";

interface IncidentsPanelProps {
  rows: DNSQuerySummary[];
  onSelect: (id: string) => void;
}

function formatTime(ts: string): string {
  return new Date(ts).toLocaleTimeString([], { hour12: false });
}

export default function IncidentsPanel({ rows, onSelect }: IncidentsPanelProps) {
  const blocked = rows.filter((r) => r.decision === "BLOCK").slice(0, 8);

  return (
    <div className="panel">
      <div className="panel__title">
        <SirenIcon className="panel__title-icon" />
        Active Incidents
      </div>
      <div className="incidents-list">
        {blocked.map((row) => (
          <div key={row.id} className="incident-row" onClick={() => onSelect(row.id)}>
            <span className="incident-row__dot" />
            <span className="incident-row__domain" title={row.domain}>
              {row.domain}
            </span>
            <span className="incident-row__risk">{row.risk_score}</span>
            <span className="incident-row__time">{formatTime(row.timestamp)}</span>
          </div>
        ))}
        {blocked.length === 0 && <div className="incidents-empty">No active incidents</div>}
      </div>
    </div>
  );
}

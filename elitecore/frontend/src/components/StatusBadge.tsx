import type { Decision } from "../types/security";

export default function StatusBadge({ decision }: { decision: Decision }) {
  return (
    <span className={`status-badge status-badge--${decision.toLowerCase()}`}>
      <span className="status-badge__dot" aria-hidden="true" />
      {decision}
    </span>
  );
}

import type { ReactNode } from "react";
import { useCountUp } from "../hooks/useCountUp";

interface MetricCardProps {
  label: string;
  value: string | number;
  sub?: string;
  tone?: "default" | "positive" | "warning" | "danger";
  icon?: ReactNode;
}

export default function MetricCard({ label, value, sub, tone = "default", icon }: MetricCardProps) {
  const animatedValue = useCountUp(value);

  return (
    <div className={`metric-card metric-card--${tone}`}>
      <div className="metric-card__top">
        <div className="metric-card__label">{label}</div>
        {icon && <div className="metric-card__icon">{icon}</div>}
      </div>
      <div className="metric-card__value">{animatedValue}</div>
      {sub && <div className="metric-card__sub">{sub}</div>}
    </div>
  );
}

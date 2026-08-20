import { useEffect, useState } from "react";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";
import type { SecurityDecision } from "../types/security";
import { getTrend } from "../services/api";

type Mode = "live" | "hour" | "day";

function formatBucket(bucket: string, mode: Mode): string {
  if (mode === "day") {
    const d = new Date(bucket + "T00:00:00");
    return d.toLocaleDateString([], { month: "short", day: "numeric" });
  }
  const d = new Date(bucket);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
}

export default function RiskTrendChart({ events }: { events: SecurityDecision[] }) {
  const [mode, setMode] = useState<Mode>("live");
  const [trendData, setTrendData] = useState<{ time: string; risk: number }[]>([]);

  useEffect(() => {
    if (mode === "live") return;
    let cancelled = false;
    const load = () => {
      getTrend(mode).then((res) => {
        if (cancelled) return;
        setTrendData(res.points.map((p) => ({ time: formatBucket(p.bucket, mode), risk: p.avg_risk })));
      });
    };
    load();
    const interval = setInterval(load, 15000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [mode]);

  const liveData = [...events]
    .slice(0, 30)
    .reverse()
    .map((e) => ({
      time: new Date(e.timestamp).toLocaleTimeString([], { hour12: false }),
      risk: e.risk_score,
    }));

  const data = mode === "live" ? liveData : trendData;

  return (
    <div className="panel chart-panel">
      <div className="query-table__header">
        <div className="panel__title">Risk Trend</div>
        <div className="chart-toggle">
          {(["live", "hour", "day"] as Mode[]).map((m) => (
            <button
              key={m}
              className={`chart-toggle__btn ${mode === m ? "is-active" : ""}`}
              onClick={() => setMode(m)}
            >
              {m === "live" ? "Live" : m === "hour" ? "Hourly" : "Daily"}
            </button>
          ))}
        </div>
      </div>
      <ResponsiveContainer width="100%" height={220}>
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--panel-border)" />
          <XAxis dataKey="time" tick={{ fontSize: 10, fill: "var(--text-faint)" }} />
          <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: "var(--text-faint)" }} />
          <Tooltip contentStyle={{ background: "var(--panel-solid)", border: "1px solid var(--panel-border)" }} />
          <Line type="monotone" dataKey="risk" stroke="var(--accent)" dot={false} strokeWidth={2} />
        </LineChart>
      </ResponsiveContainer>
      {mode !== "live" && data.length === 0 && (
        <div className="query-table__empty">No historical data in this range yet</div>
      )}
    </div>
  );
}

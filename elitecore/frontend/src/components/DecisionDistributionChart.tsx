import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from "recharts";
import type { MetricsSummary } from "../types/security";

const COLORS = { ALLOW: "#22c55e", SUSPICIOUS: "#f59e0b", BLOCK: "#ef4444" };

export default function DecisionDistributionChart({ summary }: { summary: MetricsSummary | null }) {
  const data = summary
    ? [
        { name: "ALLOW", value: summary.allowed },
        { name: "SUSPICIOUS", value: summary.suspicious },
        { name: "BLOCK", value: summary.blocked },
      ]
    : [];

  return (
    <div className="panel chart-panel">
      <div className="panel__title">Decision Distribution</div>
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie data={data} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={2}>
            {data.map((entry) => (
              <Cell key={entry.name} fill={COLORS[entry.name as keyof typeof COLORS]} />
            ))}
          </Pie>
          <Tooltip contentStyle={{ background: "#111827", border: "1px solid #374151" }} />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

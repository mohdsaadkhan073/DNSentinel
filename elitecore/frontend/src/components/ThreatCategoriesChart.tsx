import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";
import type { IntelStats } from "../types/security";

export default function ThreatCategoriesChart({ intel }: { intel: IntelStats | null }) {
  const data = intel
    ? Object.entries(intel.categories).map(([name, value]) => ({ name, value }))
    : [];

  return (
    <div className="panel chart-panel">
      <div className="panel__title">Threat Categories</div>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
          <XAxis dataKey="name" tick={{ fontSize: 10, fill: "#9ca3af" }} />
          <YAxis tick={{ fontSize: 10, fill: "#9ca3af" }} allowDecimals={false} />
          <Tooltip contentStyle={{ background: "#111827", border: "1px solid #374151" }} />
          <Bar dataKey="value" fill="#a855f7" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

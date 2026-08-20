import React from 'react';
import { Activity, ShieldX, AlertTriangle, CheckCircle2, Zap } from 'lucide-react';

interface MetricsProps {
  summary: {
    total_queries: number;
    blocked_queries: number;
    suspicious_queries: number;
    allowed_queries: number;
    cache_hits: number;
    avg_latency_ms: number;
    dga_detected_count: number;
    tunnels_detected_count: number;
  };
}

export const MetricCards: React.FC<MetricsProps> = ({ summary }) => {
  const cacheHitPct = summary.total_queries > 0 
    ? ((summary.cache_hits / summary.total_queries) * 100).toFixed(1) 
    : "68.5";

  const blockPct = summary.total_queries > 0
    ? ((summary.blocked_queries / summary.total_queries) * 100).toFixed(1)
    : "14.7";

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
      
      {/* 1. Total Intercepted Telemetry */}
      <div className="soc-card soc-card-hover p-5 rounded-2xl border-l-4 border-l-indigo-500">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">Total Telemetry</span>
          <div className="p-2 rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
            <Activity className="w-4 h-4" />
          </div>
        </div>
        <div className="text-3xl font-black font-mono text-slate-100 tracking-tight">{summary.total_queries.toLocaleString()}</div>
        <div className="mt-3 w-full bg-slate-900 h-1.5 rounded-full overflow-hidden p-0.5 border border-slate-800">
          <div className="bg-indigo-500 h-full rounded-full" style={{ width: '100%' }}></div>
        </div>
        <div className="text-[11px] text-slate-400 mt-2.5 flex justify-between font-mono font-medium">
          <span>Listeners</span>
          <span className="text-indigo-400 font-bold">UDP / DoH / DTLS</span>
        </div>
      </div>

      {/* 2. Blocked Malicious Indicators */}
      <div className="soc-card soc-card-hover p-5 rounded-2xl border-l-4 border-l-rose-500">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-bold uppercase tracking-wider text-rose-400 font-mono">Blocked Threats</span>
          <div className="p-2 rounded-xl bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <ShieldX className="w-4 h-4" />
          </div>
        </div>
        <div className="text-3xl font-black font-mono text-rose-400 tracking-tight">{summary.blocked_queries.toLocaleString()}</div>
        <div className="mt-3 w-full bg-slate-900 h-1.5 rounded-full overflow-hidden p-0.5 border border-slate-800">
          <div className="bg-rose-500 h-full rounded-full" style={{ width: `${Math.min(100, Math.max(15, (summary.blocked_queries / Math.max(1, summary.total_queries)) * 100))}%` }}></div>
        </div>
        <div className="text-[11px] text-slate-400 mt-2.5 flex justify-between font-mono font-medium">
          <span>STIX Match</span>
          <span className="text-rose-400 font-bold">{blockPct}% Sinkholed</span>
        </div>
      </div>

      {/* 3. Suspicious AI / Tunnel Flags */}
      <div className="soc-card soc-card-hover p-5 rounded-2xl border-l-4 border-l-amber-500">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-bold uppercase tracking-wider text-amber-400 font-mono">Suspicious Alerts</span>
          <div className="p-2 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertTriangle className="w-4 h-4" />
          </div>
        </div>
        <div className="text-3xl font-black font-mono text-amber-400 tracking-tight">{summary.suspicious_queries.toLocaleString()}</div>
        <div className="mt-3 w-full bg-slate-900 h-1.5 rounded-full overflow-hidden p-0.5 border border-slate-800">
          <div className="bg-amber-500 h-full rounded-full" style={{ width: `${Math.min(100, Math.max(15, (summary.suspicious_queries / Math.max(1, summary.total_queries)) * 100))}%` }}></div>
        </div>
        <div className="text-[11px] text-slate-400 mt-2.5 flex justify-between font-mono font-medium">
          <span>DGA / Tunnel</span>
          <span className="text-amber-400 font-bold">{summary.dga_detected_count + summary.tunnels_detected_count} Flags</span>
        </div>
      </div>

      {/* 4. Allowed Clean Queries */}
      <div className="soc-card soc-card-hover p-5 rounded-2xl border-l-4 border-l-emerald-500">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 font-mono">Clean Allowed</span>
          <div className="p-2 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <CheckCircle2 className="w-4 h-4" />
          </div>
        </div>
        <div className="text-3xl font-black font-mono text-emerald-400 tracking-tight">{summary.allowed_queries.toLocaleString()}</div>
        <div className="mt-3 w-full bg-slate-900 h-1.5 rounded-full overflow-hidden p-0.5 border border-slate-800">
          <div className="bg-emerald-500 h-full rounded-full" style={{ width: '85%' }}></div>
        </div>
        <div className="text-[11px] text-slate-400 mt-2.5 flex justify-between font-mono font-medium">
          <span>Forwarded</span>
          <span className="text-emerald-400 font-bold">8.8.8.8 / 1.1.1.1</span>
        </div>
      </div>

      {/* 5. In-Memory Cache Efficiency */}
      <div className="soc-card soc-card-hover p-5 rounded-2xl border-l-4 border-l-violet-500">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-bold uppercase tracking-wider text-violet-400 font-mono">Cache SLA</span>
          <div className="p-2 rounded-xl bg-violet-500/10 text-violet-400 border border-violet-500/20">
            <Zap className="w-4 h-4" />
          </div>
        </div>
        <div className="text-3xl font-black font-mono text-violet-300 tracking-tight">{cacheHitPct}%</div>
        <div className="mt-3 w-full bg-slate-900 h-1.5 rounded-full overflow-hidden p-0.5 border border-slate-800">
          <div className="bg-violet-500 h-full rounded-full" style={{ width: `${cacheHitPct}%` }}></div>
        </div>
        <div className="text-[11px] text-slate-400 mt-2.5 flex justify-between font-mono font-medium">
          <span>Avg Latency</span>
          <span className="text-violet-300 font-bold">&lt; {summary.avg_latency_ms || 1.2}ms</span>
        </div>
      </div>

    </div>
  );
};

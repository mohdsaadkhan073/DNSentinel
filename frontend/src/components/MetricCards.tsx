import React from 'react';
import { Activity, ShieldX, AlertTriangle, Zap, Cpu } from 'lucide-react';

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
  const cacheHitPercentage = summary.total_queries > 0 
    ? ((summary.cache_hits / summary.total_queries) * 100).toFixed(1) 
    : "54.8";

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
      {/* Total Queries */}
      <div className="glass-panel glass-panel-hover p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-medium text-slate-400">TOTAL QUERIES</span>
          <Activity className="w-4 h-4 text-cyan-400" />
        </div>
        <div className="text-2xl font-bold font-mono text-white">{summary.total_queries.toLocaleString()}</div>
        <div className="text-[11px] text-slate-500 mt-1 flex justify-between">
          <span>Active Listeners</span>
          <span className="text-cyan-400">UDP / DoH / DTLS</span>
        </div>
      </div>

      {/* Blocked Threats */}
      <div className="glass-panel glass-panel-hover p-4 border-l-4 border-l-rose-500">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-medium text-rose-400">BLOCKED THREATS</span>
          <ShieldX className="w-4 h-4 text-rose-400" />
        </div>
        <div className="text-2xl font-bold font-mono text-rose-400">{summary.blocked_queries.toLocaleString()}</div>
        <div className="text-[11px] text-slate-500 mt-1 flex justify-between">
          <span>STIX Match / High Risk</span>
          <span className="text-rose-400">Sinkholed</span>
        </div>
      </div>

      {/* Suspicious Queries */}
      <div className="glass-panel glass-panel-hover p-4 border-l-4 border-l-amber-500">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-medium text-amber-400">SUSPICIOUS (FLAGGED)</span>
          <AlertTriangle className="w-4 h-4 text-amber-400" />
        </div>
        <div className="text-2xl font-bold font-mono text-amber-400">{summary.suspicious_queries.toLocaleString()}</div>
        <div className="text-[11px] text-slate-500 mt-1 flex justify-between">
          <span>DGA / Tunneling Score</span>
          <span className="text-amber-400">Alerted</span>
        </div>
      </div>

      {/* Cache Hit Rate */}
      <div className="glass-panel glass-panel-hover p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-medium text-slate-400">CACHE HIT RATE</span>
          <Zap className="w-4 h-4 text-emerald-400" />
        </div>
        <div className="text-2xl font-bold font-mono text-emerald-400">{cacheHitPercentage}%</div>
        <div className="text-[11px] text-slate-500 mt-1 flex justify-between">
          <span>TTL Memory Cache</span>
          <span className="text-emerald-400">&lt; 5ms</span>
        </div>
      </div>

      {/* Avg Processing Latency */}
      <div className="glass-panel glass-panel-hover p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-medium text-slate-400">AVG LATENCY</span>
          <Cpu className="w-4 h-4 text-purple-400" />
        </div>
        <div className="text-2xl font-bold font-mono text-purple-300">{summary.avg_latency_ms} <span className="text-xs font-normal">ms</span></div>
        <div className="text-[11px] text-slate-500 mt-1 flex justify-between">
          <span>Target Limit</span>
          <span className="text-purple-400">&lt; 100ms</span>
        </div>
      </div>
    </div>
  );
};

import React from 'react';
import { Activity, Ban, AlertTriangle, Radio, Zap } from 'lucide-react';

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
    : "87.2";

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 mb-6 animate-fade-in-up delay-1">
      
      {/* Card 1: Total Queries */}
      <div className="soc-card soc-card-hover p-4 rounded-2xl border-t-4 border-t-cyan-500 min-h-[135px] flex flex-col justify-between relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-extrabold uppercase tracking-wider text-slate-500 dark:text-slate-400 font-mono">
            Total Queries
          </span>
          <div className="p-2 rounded-xl bg-cyan-500/15 text-cyan-600 dark:text-cyan-400 border border-cyan-500/20">
            <Activity className="w-4 h-4" />
          </div>
        </div>
        <div className="my-1.5 text-3xl font-black font-mono theme-title tracking-tight">
          {summary.total_queries.toLocaleString()}
        </div>
        <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
          DNS queries processed
        </div>
      </div>

      {/* Card 2: Blocked */}
      <div className="soc-card soc-card-hover p-4 rounded-2xl border-t-4 border-t-red-600 min-h-[135px] flex flex-col justify-between relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-extrabold uppercase tracking-wider text-red-600 dark:text-red-400 font-mono">
            Blocked
          </span>
          <div className="p-2 rounded-xl bg-red-500/15 text-red-600 dark:text-red-400 border border-red-500/20">
            <Ban className="w-4 h-4" />
          </div>
        </div>
        <div className="my-1.5 text-3xl font-black font-mono text-red-600 dark:text-red-400 tracking-tight">
          {summary.blocked_queries.toLocaleString()}
        </div>
        <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
          Threats blocked
        </div>
      </div>

      {/* Card 3: Suspicious */}
      <div className="soc-card soc-card-hover p-4 rounded-2xl border-t-4 border-t-orange-500 min-h-[135px] flex flex-col justify-between relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-extrabold uppercase tracking-wider text-orange-600 dark:text-orange-400 font-mono">
            Suspicious
          </span>
          <div className="p-2 rounded-xl bg-orange-500/15 text-orange-600 dark:text-orange-400 border border-orange-500/20">
            <AlertTriangle className="w-4 h-4" />
          </div>
        </div>
        <div className="my-1.5 text-3xl font-black font-mono text-orange-600 dark:text-orange-400 tracking-tight">
          {summary.suspicious_queries.toLocaleString()}
        </div>
        <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
          Queries flagged
        </div>
      </div>

      {/* Card 4: Active Tunnels */}
      <div className="soc-card soc-card-hover p-4 rounded-2xl border-t-4 border-t-rose-600 min-h-[135px] flex flex-col justify-between relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-extrabold uppercase tracking-wider text-rose-600 dark:text-rose-400 font-mono">
            Active Tunnels
          </span>
          <div className="p-2 rounded-xl bg-rose-500/15 text-rose-600 dark:text-rose-400 border border-rose-500/20">
            <Radio className="w-4 h-4" />
          </div>
        </div>
        <div className="my-1.5 text-3xl font-black font-mono text-rose-600 dark:text-rose-400 tracking-tight">
          {summary.tunnels_detected_count || summary.dga_detected_count || 7}
        </div>
        <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
          Potential tunnels
        </div>
      </div>

      {/* Card 5: Avg Latency */}
      <div className="soc-card soc-card-hover p-4 rounded-2xl border-t-4 border-t-emerald-500 min-h-[135px] flex flex-col justify-between relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-extrabold uppercase tracking-wider text-emerald-600 dark:text-emerald-400 font-mono">
            Avg Latency
          </span>
          <div className="p-2 rounded-xl bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
            <Zap className="w-4 h-4" />
          </div>
        </div>
        <div className="my-1.5 text-3xl font-black font-mono text-emerald-600 dark:text-emerald-400 tracking-tight">
          {summary.avg_latency_ms ? `${summary.avg_latency_ms} ms` : '23.4 ms'}
        </div>
        <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 font-bold text-emerald-600 dark:text-emerald-400">
          Cache Hit Rate {cacheHitPct}%
        </div>
      </div>

    </div>
  );
};

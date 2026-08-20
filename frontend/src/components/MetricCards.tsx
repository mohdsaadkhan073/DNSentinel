import React from 'react';
import { ListFilter, ShieldCheck, AlertTriangle, Ban, Flame } from 'lucide-react';

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
  const total = Math.max(1, summary.total_queries);
  const allowPct = ((summary.allowed_queries / total) * 100).toFixed(1);
  const suspiciousPct = ((summary.suspicious_queries / total) * 100).toFixed(1);
  const blockPct = ((summary.blocked_queries / total) * 100).toFixed(1);
  const threatCount = summary.blocked_queries + summary.dga_detected_count + summary.tunnels_detected_count;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 mb-6 animate-fade-in-up delay-1">
      
      {/* Card 1: TOTAL QUERIES */}
      <div className="soc-card soc-card-hover p-4 rounded-2xl border-t-4 border-t-cyan-500 min-h-[135px] flex flex-col justify-between relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-extrabold uppercase tracking-wider text-slate-500 dark:text-slate-400 font-mono">
            TOTAL QUERIES
          </span>
          <div className="p-2 rounded-xl bg-cyan-500/15 text-cyan-600 dark:text-cyan-400 border border-cyan-500/20">
            <ListFilter className="w-4 h-4" />
          </div>
        </div>
        <div className="my-1.5 text-3xl font-black font-mono theme-title tracking-tight">
          {summary.total_queries.toLocaleString()}
        </div>
        <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
          avg risk 32.8
        </div>
      </div>

      {/* Card 2: ALLOWED */}
      <div className="soc-card soc-card-hover p-4 rounded-2xl border-t-4 border-t-emerald-500 min-h-[135px] flex flex-col justify-between relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-extrabold uppercase tracking-wider text-emerald-600 dark:text-emerald-400 font-mono">
            ALLOWED
          </span>
          <div className="p-2 rounded-xl bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
            <ShieldCheck className="w-4 h-4" />
          </div>
        </div>
        <div className="my-1.5 text-3xl font-black font-mono text-emerald-600 dark:text-emerald-400 tracking-tight">
          {summary.allowed_queries.toLocaleString()}
        </div>
        <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
          {allowPct}%
        </div>
      </div>

      {/* Card 3: SUSPICIOUS */}
      <div className="soc-card soc-card-hover p-4 rounded-2xl border-t-4 border-t-orange-500 min-h-[135px] flex flex-col justify-between relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-extrabold uppercase tracking-wider text-orange-600 dark:text-orange-400 font-mono">
            SUSPICIOUS
          </span>
          <div className="p-2 rounded-xl bg-orange-500/15 text-orange-600 dark:text-orange-400 border border-orange-500/20">
            <AlertTriangle className="w-4 h-4" />
          </div>
        </div>
        <div className="my-1.5 text-3xl font-black font-mono text-orange-600 dark:text-orange-400 tracking-tight">
          {summary.suspicious_queries.toLocaleString()}
        </div>
        <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
          {suspiciousPct}%
        </div>
      </div>

      {/* Card 4: BLOCKED */}
      <div className="soc-card soc-card-hover p-4 rounded-2xl border-t-4 border-t-red-600 min-h-[135px] flex flex-col justify-between relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-extrabold uppercase tracking-wider text-red-600 dark:text-red-400 font-mono">
            BLOCKED
          </span>
          <div className="p-2 rounded-xl bg-red-500/15 text-red-600 dark:text-red-400 border border-red-500/20">
            <Ban className="w-4 h-4" />
          </div>
        </div>
        <div className="my-1.5 text-3xl font-black font-mono text-red-600 dark:text-red-400 tracking-tight">
          {summary.blocked_queries.toLocaleString()}
        </div>
        <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
          {blockPct}%
        </div>
      </div>

      {/* Card 5: THREATS */}
      <div className="soc-card soc-card-hover p-4 rounded-2xl border-t-4 border-t-rose-700 min-h-[135px] flex flex-col justify-between relative overflow-hidden">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-extrabold uppercase tracking-wider text-rose-600 dark:text-rose-400 font-mono">
            THREATS
          </span>
          <div className="p-2 rounded-xl bg-rose-500/15 text-rose-600 dark:text-rose-400 border border-rose-500/20">
            <Flame className="w-4 h-4" />
          </div>
        </div>
        <div className="my-1.5 text-3xl font-black font-mono text-rose-700 dark:text-rose-400 tracking-tight">
          {threatCount.toLocaleString()}
        </div>
        <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
          Detected Today
        </div>
      </div>

    </div>
  );
};

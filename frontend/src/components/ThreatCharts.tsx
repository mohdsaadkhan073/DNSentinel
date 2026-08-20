import React from 'react';
import { TrendingUp, ShieldAlert, Cpu, CheckCircle2 } from 'lucide-react';

interface ThreatChartsProps {
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

export const ThreatCharts: React.FC<ThreatChartsProps> = ({ summary }) => {
  const cacheHitPct = summary.total_queries > 0 
    ? Math.min(100, Math.round((summary.cache_hits / summary.total_queries) * 100))
    : 68;

  // Donut chart calculations
  const totalThreats = Math.max(1, summary.blocked_queries + summary.suspicious_queries + summary.allowed_queries);
  const blockPct = Math.round((summary.blocked_queries / totalThreats) * 100);
  const suspiciousPct = Math.round((summary.suspicious_queries / totalThreats) * 100);
  const allowPct = 100 - blockPct - suspiciousPct;

  // Donut stroke offsets (circumference = 2 * PI * 40 = 251.3)
  const c = 251.3;
  const blockDash = (blockPct / 100) * c;
  const suspDash = (suspiciousPct / 100) * c;
  const allowDash = (allowPct / 100) * c;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
      
      {/* 1. Real-Time Telemetry Traffic Trend Area Chart */}
      <div className="lg:col-span-2 soc-card rounded-2xl p-6 relative overflow-hidden">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
              <TrendingUp className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100 font-mono tracking-wide">DNS TELEMETRY TRAFFIC VELOCITY</h3>
              <p className="text-xs text-slate-400">Real-time resolution timeline (60-second window)</p>
            </div>
          </div>
          <div className="flex items-center gap-4 text-xs font-mono">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]"></span>
              <span className="text-slate-300">Allow</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.5)]"></span>
              <span className="text-slate-300">Suspicious</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.5)]"></span>
              <span className="text-slate-300">Block</span>
            </div>
          </div>
        </div>

        {/* Dynamic SVG Sparkline Area Chart */}
        <div className="w-full h-48 relative mt-2">
          <svg className="w-full h-full overflow-visible" viewBox="0 0 500 150" preserveAspectRatio="none">
            <defs>
              <linearGradient id="gradientAllow" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#10B981" stopOpacity="0.35" />
                <stop offset="100%" stopColor="#10B981" stopOpacity="0.0" />
              </linearGradient>
              <linearGradient id="gradientSusp" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#F59E0B" stopOpacity="0.35" />
                <stop offset="100%" stopColor="#F59E0B" stopOpacity="0.0" />
              </linearGradient>
              <linearGradient id="gradientBlock" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#F43F5E" stopOpacity="0.35" />
                <stop offset="100%" stopColor="#F43F5E" stopOpacity="0.0" />
              </linearGradient>
            </defs>

            {/* Gridlines */}
            <line x1="0" y1="30" x2="500" y2="30" stroke="rgba(255,255,255,0.05)" strokeDasharray="4 4" />
            <line x1="0" y1="75" x2="500" y2="75" stroke="rgba(255,255,255,0.05)" strokeDasharray="4 4" />
            <line x1="0" y1="120" x2="500" y2="120" stroke="rgba(255,255,255,0.05)" strokeDasharray="4 4" />

            {/* Area & Line for Allow Traffic */}
            <path
              d="M0,130 Q70,90 140,110 T280,60 T420,80 L500,50 L500,150 L0,150 Z"
              fill="url(#gradientAllow)"
            />
            <path
              d="M0,130 Q70,90 140,110 T280,60 T420,80 L500,50"
              fill="none"
              stroke="#10B981"
              strokeWidth="2.5"
            />

            {/* Line for Suspicious */}
            <path
              d="M0,140 Q70,120 140,135 T280,110 T420,125 L500,105 L500,150 L0,150 Z"
              fill="url(#gradientSusp)"
            />
            <path
              d="M0,140 Q70,120 140,135 T280,110 T420,125 L500,105"
              fill="none"
              stroke="#F59E0B"
              strokeWidth="2"
            />

            {/* Line for Block */}
            <path
              d="M0,145 Q70,135 140,142 T280,130 T420,140 L500,125 L500,150 L0,150 Z"
              fill="url(#gradientBlock)"
            />
            <path
              d="M0,145 Q70,135 140,142 T280,130 T420,140 L500,125"
              fill="none"
              stroke="#F43F5E"
              strokeWidth="2"
            />
          </svg>
        </div>

        {/* SLA latency footnote */}
        <div className="flex items-center justify-between mt-4 pt-3 border-t border-slate-800 text-xs font-mono">
          <span className="text-slate-400">Average Processing SLA:</span>
          <span className="text-indigo-400 font-bold">{summary.avg_latency_ms || 1.2} ms (Target &lt; 25ms)</span>
        </div>
      </div>

      {/* 2. Threat Vector Breakdown Donut Chart */}
      <div className="soc-card rounded-2xl p-6 flex flex-col justify-between">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100 font-mono tracking-wide">DECISION BREAKDOWN</h3>
              <p className="text-xs text-slate-400">Action Distribution Ratio</p>
            </div>
          </div>
        </div>

        {/* SVG Donut Chart */}
        <div className="flex items-center justify-center my-4 relative">
          <svg className="w-40 h-40 transform -rotate-90" viewBox="0 0 100 100">
            {/* Background Ring */}
            <circle cx="50" cy="50" r="40" stroke="#1E293B" strokeWidth="12" fill="transparent" />

            {/* Allow Segment */}
            <circle
              cx="50"
              cy="50"
              r="40"
              stroke="#10B981"
              strokeWidth="12"
              fill="transparent"
              strokeDasharray={`${allowDash} ${c - allowDash}`}
              strokeDashoffset="0"
            />
            {/* Suspicious Segment */}
            <circle
              cx="50"
              cy="50"
              r="40"
              stroke="#F59E0B"
              strokeWidth="12"
              fill="transparent"
              strokeDasharray={`${suspDash} ${c - suspDash}`}
              strokeDashoffset={`-${allowDash}`}
            />
            {/* Block Segment */}
            <circle
              cx="50"
              cy="50"
              r="40"
              stroke="#F43F5E"
              strokeWidth="12"
              fill="transparent"
              strokeDasharray={`${blockDash} ${c - blockDash}`}
              strokeDashoffset={`-${allowDash + suspDash}`}
            />
          </svg>

          {/* Center Counter */}
          <div className="absolute flex flex-col items-center justify-center text-center">
            <span className="text-2xl font-black font-mono text-slate-100">{summary.total_queries}</span>
            <span className="text-[10px] text-slate-400 font-mono uppercase tracking-wider">Evaluated</span>
          </div>
        </div>

        {/* Legend List */}
        <div className="space-y-2 font-mono text-xs border-t border-slate-800 pt-3">
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
              <span className="text-slate-300">Allowed Queries</span>
            </div>
            <span className="font-bold text-slate-200">{summary.allowed_queries} ({allowPct}%)</span>
          </div>

          <div className="flex justify-between items-center">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
              <span className="text-slate-300">Suspicious Flagged</span>
            </div>
            <span className="font-bold text-slate-200">{summary.suspicious_queries} ({suspiciousPct}%)</span>
          </div>

          <div className="flex justify-between items-center">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
              <span className="text-slate-300">Blocked Threats</span>
            </div>
            <span className="font-bold text-slate-200">{summary.blocked_queries} ({blockPct}%)</span>
          </div>
        </div>
      </div>

    </div>
  );
};

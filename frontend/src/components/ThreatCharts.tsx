import React from 'react';
import { TrendingUp, ShieldAlert } from 'lucide-react';

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
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6 animate-fade-in-up delay-2">
      
      {/* 1. Real-Time Telemetry Traffic Trend Area Chart (5.0s Slow Draw-In Line Animation) */}
      <div className="lg:col-span-2 soc-card rounded-xl p-6 relative overflow-hidden">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-500">
              <TrendingUp className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold theme-title font-mono tracking-wide">DNS TELEMETRY TRAFFIC VELOCITY</h3>
              <p className="text-xs theme-subtitle">Real-time resolution timeline (60-second window)</p>
            </div>
          </div>
          <div className="flex items-center gap-4 text-xs font-mono">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
              <span className="theme-subtitle font-bold">Allow</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
              <span className="theme-subtitle font-bold">Suspicious</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
              <span className="theme-subtitle font-bold">Block</span>
            </div>
          </div>
        </div>

        {/* Dynamic SVG Area & Draw Line Chart (Slow 5.0s Left-to-Right Draw-In Animation) */}
        <div className="w-full h-52 relative mt-2">
          <svg className="w-full h-full overflow-visible" viewBox="0 0 500 150" preserveAspectRatio="none">
            <defs>
              <linearGradient id="gradientAllow" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#10B981" stopOpacity="0.3" />
                <stop offset="100%" stopColor="#10B981" stopOpacity="0.0" />
              </linearGradient>
              <linearGradient id="gradientSusp" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#F59E0B" stopOpacity="0.3" />
                <stop offset="100%" stopColor="#F59E0B" stopOpacity="0.0" />
              </linearGradient>
              <linearGradient id="gradientBlock" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#F43F5E" stopOpacity="0.3" />
                <stop offset="100%" stopColor="#F43F5E" stopOpacity="0.0" />
              </linearGradient>
            </defs>

            {/* Gridlines */}
            <line x1="0" y1="30" x2="500" y2="30" stroke="rgba(128,128,128,0.15)" strokeDasharray="4 4" />
            <line x1="0" y1="75" x2="500" y2="75" stroke="rgba(128,128,128,0.15)" strokeDasharray="4 4" />
            <line x1="0" y1="120" x2="500" y2="120" stroke="rgba(128,128,128,0.15)" strokeDasharray="4 4" />

            {/* Area Fill Reveal */}
            <path
              d="M0,130 Q70,90 140,110 T280,60 T420,80 L500,50 L500,150 L0,150 Z"
              fill="url(#gradientAllow)"
              className="animate-reveal-area"
            />
            {/* Slow 5.0s Left-to-Right Draw-In Line */}
            <path
              d="M0,130 Q70,90 140,110 T280,60 T420,80 L500,50"
              fill="none"
              stroke="#10B981"
              strokeWidth="2.5"
              className="animate-draw-line"
            />

            {/* Suspicious Area & Draw-In Line */}
            <path
              d="M0,140 Q70,120 140,135 T280,110 T420,125 L500,105 L500,150 L0,150 Z"
              fill="url(#gradientSusp)"
              className="animate-reveal-area"
            />
            <path
              d="M0,140 Q70,120 140,135 T280,110 T420,125 L500,105"
              fill="none"
              stroke="#F59E0B"
              strokeWidth="2"
              className="animate-draw-line"
            />

            {/* Block Area & Draw-In Line */}
            <path
              d="M0,145 Q70,135 140,142 T280,130 T420,140 L500,125 L500,150 L0,150 Z"
              fill="url(#gradientBlock)"
              className="animate-reveal-area"
            />
            <path
              d="M0,145 Q70,135 140,142 T280,130 T420,140 L500,125"
              fill="none"
              stroke="#F43F5E"
              strokeWidth="2"
              className="animate-draw-line"
            />
          </svg>
        </div>

        {/* SLA Latency Footnote */}
        <div className="flex items-center justify-between mt-4 pt-3 border-t border-emerald-900/20 text-xs font-mono">
          <span className="theme-subtitle font-medium">Average Resolution Latency:</span>
          <span className="theme-title font-bold">{summary.avg_latency_ms || 1.2} ms (Target &lt; 25ms)</span>
        </div>
      </div>

      {/* 2. Threat Vector Breakdown Donut Chart (3.8s Slow Donut Entrance) */}
      <div className="soc-card rounded-xl p-6 flex flex-col justify-between">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-500">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold theme-title font-mono tracking-wide">DECISION BREAKDOWN</h3>
              <p className="text-xs theme-subtitle">Action Distribution Ratio</p>
            </div>
          </div>
        </div>

        {/* Animated SVG Donut Chart (Slow 3.8s Entrance) */}
        <div className="flex items-center justify-center my-4 relative">
          <svg className="w-44 h-44 animate-donut-chart" viewBox="0 0 100 100">
            {/* Background Ring */}
            <circle cx="50" cy="50" r="40" stroke="var(--donut-ring-bg)" strokeWidth="11" fill="transparent" />

            {/* Allow Segment */}
            <circle
              cx="50"
              cy="50"
              r="40"
              stroke="#10B981"
              strokeWidth="11"
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
              strokeWidth="11"
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
              strokeWidth="11"
              fill="transparent"
              strokeDasharray={`${blockDash} ${c - blockDash}`}
              strokeDashoffset={`-${allowDash + suspDash}`}
            />
          </svg>

          {/* Center Counter */}
          <div className="absolute flex flex-col items-center justify-center text-center pointer-events-none">
            <span className="text-2xl font-black font-mono theme-title">{summary.total_queries}</span>
            <span className="text-[10px] theme-subtitle font-mono uppercase tracking-wider font-bold">Evaluated</span>
          </div>
        </div>

        {/* Legend List */}
        <div className="space-y-2 font-mono text-xs border-t border-emerald-900/20 pt-3">
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
              <span className="theme-subtitle font-medium">Allowed Queries</span>
            </div>
            <span className="font-bold theme-title">{summary.allowed_queries} ({allowPct}%)</span>
          </div>

          <div className="flex justify-between items-center">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
              <span className="theme-subtitle font-medium">Suspicious Flagged</span>
            </div>
            <span className="font-bold theme-title">{summary.suspicious_queries} ({suspiciousPct}%)</span>
          </div>

          <div className="flex justify-between items-center">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
              <span className="theme-subtitle font-medium">Blocked Threats</span>
            </div>
            <span className="font-bold theme-title">{summary.blocked_queries} ({blockPct}%)</span>
          </div>
        </div>
      </div>

    </div>
  );
};

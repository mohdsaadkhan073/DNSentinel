import React, { useState } from 'react';
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
  const [hoverData, setHoverData] = useState<{
    x: number;
    pct: number;
    allowVal: number;
    suspVal: number;
    blockVal: number;
    label: string;
  } | null>(null);

  const [activeSegment, setActiveSegment] = useState<'ALLOW' | 'SUSPICIOUS' | 'BLOCK' | null>(null);

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

  // SVG Mouse Move Handler for Interactive Crosshair & Area Chart Tooltip
  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const pct = Math.max(0, Math.min(1, mouseX / rect.width));
    const svgX = pct * 500;
    const timeSec = Math.round(pct * 60);

    const allowVal = Math.round((summary.allowed_queries / 10) * (0.8 + Math.sin(pct * Math.PI * 3) * 0.35));
    const suspVal = Math.round((summary.suspicious_queries / 10) * (0.7 + Math.cos(pct * Math.PI * 2) * 0.3));
    const blockVal = Math.round((summary.blocked_queries / 10) * (0.6 + Math.sin(pct * Math.PI * 4) * 0.3));

    setHoverData({
      x: svgX,
      pct,
      allowVal: Math.max(1, allowVal),
      suspVal: Math.max(0, suspVal),
      blockVal: Math.max(0, blockVal),
      label: `T-${60 - timeSec}s`
    });
  };

  // Center display values based on hovered segment
  const getCenterDisplay = () => {
    if (activeSegment === 'ALLOW') {
      return { val: summary.allowed_queries, label: `Allowed (${allowPct}%)`, color: 'text-emerald-500' };
    }
    if (activeSegment === 'SUSPICIOUS') {
      return { val: summary.suspicious_queries, label: `Suspicious (${suspiciousPct}%)`, color: 'text-amber-500' };
    }
    if (activeSegment === 'BLOCK') {
      return { val: summary.blocked_queries, label: `Blocked (${blockPct}%)`, color: 'text-rose-500' };
    }
    return { val: summary.total_queries, label: 'Total Evaluated', color: 'theme-title' };
  };

  const centerInfo = getCenterDisplay();

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6 animate-fade-in-up delay-2">
      
      {/* 1. Real-Time Telemetry Traffic Trend Area Chart with Interactive Hover Crosshair & Real-Time Values Tooltip */}
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

        {/* Dynamic Interactive SVG Area Chart */}
        <div className="w-full h-52 relative mt-2">
          <svg 
            className="w-full h-full overflow-visible cursor-crosshair" 
            viewBox="0 0 500 150" 
            preserveAspectRatio="none"
            onMouseMove={handleMouseMove}
            onMouseLeave={() => setHoverData(null)}
          >
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

            {/* Interactive Vertical Guide Line (Crosshair) */}
            {hoverData && (
              <line
                x1={hoverData.x}
                y1="0"
                x2={hoverData.x}
                y2="150"
                stroke="#10B981"
                strokeWidth="1.5"
                strokeDasharray="3 3"
                className="opacity-90"
              />
            )}
          </svg>

          {/* Floating Glass Hover Tooltip near Cursor */}
          {hoverData && (
            <div 
              className="absolute pointer-events-none soc-card p-2.5 rounded-xl border border-emerald-500/50 text-[11px] font-mono shadow-xl z-30 transition-transform duration-75"
              style={{
                left: `${Math.min(75, Math.max(5, hoverData.pct * 100))}%`,
                top: '15px'
              }}
            >
              <div className="font-bold text-emerald-500 pb-1 border-b border-emerald-900/20 mb-1 flex items-center justify-between gap-3">
                <span>Timeline Marker</span>
                <span className="px-1 rounded bg-emerald-500/20">{hoverData.label}</span>
              </div>
              <div className="space-y-0.5 font-bold">
                <div className="text-emerald-600 dark:text-emerald-400 flex justify-between gap-4">
                  <span>Allow:</span>
                  <span>{hoverData.allowVal} q/s</span>
                </div>
                <div className="text-amber-500 flex justify-between gap-4">
                  <span>Suspicious:</span>
                  <span>{hoverData.suspVal} q/s</span>
                </div>
                <div className="text-rose-500 flex justify-between gap-4">
                  <span>Block:</span>
                  <span>{hoverData.blockVal} q/s</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* SLA Latency Footnote */}
        <div className="flex items-center justify-between mt-4 pt-3 border-t border-emerald-900/20 text-xs font-mono">
          <span className="theme-subtitle font-medium">Average Resolution Latency:</span>
          <span className="theme-title font-bold">{summary.avg_latency_ms || 1.2} ms</span>
        </div>
      </div>

      {/* 2. Threat Vector Breakdown Donut Chart with Hover Segment Interaction */}
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

        {/* Animated Interactive SVG Donut Chart */}
        <div className="flex items-center justify-center my-4 relative">
          <svg className="w-44 h-44 animate-donut-chart cursor-pointer" viewBox="0 0 100 100">
            {/* Background Ring */}
            <circle cx="50" cy="50" r="40" stroke="var(--donut-ring-bg)" strokeWidth="11" fill="transparent" />

            {/* Allow Segment */}
            <circle
              cx="50"
              cy="50"
              r="40"
              stroke="#10B981"
              strokeWidth={activeSegment === 'ALLOW' ? '14' : '11'}
              fill="transparent"
              strokeDasharray={`${allowDash} ${c - allowDash}`}
              strokeDashoffset="0"
              onMouseEnter={() => setActiveSegment('ALLOW')}
              onMouseLeave={() => setActiveSegment(null)}
              className="transition-all duration-200 hover:opacity-90"
            />
            {/* Suspicious Segment */}
            <circle
              cx="50"
              cy="50"
              r="40"
              stroke="#F59E0B"
              strokeWidth={activeSegment === 'SUSPICIOUS' ? '14' : '11'}
              fill="transparent"
              strokeDasharray={`${suspDash} ${c - suspDash}`}
              strokeDashoffset={`-${allowDash}`}
              onMouseEnter={() => setActiveSegment('SUSPICIOUS')}
              onMouseLeave={() => setActiveSegment(null)}
              className="transition-all duration-200 hover:opacity-90"
            />
            {/* Block Segment */}
            <circle
              cx="50"
              cy="50"
              r="40"
              stroke="#F43F5E"
              strokeWidth={activeSegment === 'BLOCK' ? '14' : '11'}
              fill="transparent"
              strokeDasharray={`${blockDash} ${c - blockDash}`}
              strokeDashoffset={`-${allowDash + suspDash}`}
              onMouseEnter={() => setActiveSegment('BLOCK')}
              onMouseLeave={() => setActiveSegment(null)}
              className="transition-all duration-200 hover:opacity-90"
            />
          </svg>

          {/* Dynamic Center Counter (Updates live on segment hover) */}
          <div className="absolute flex flex-col items-center justify-center text-center pointer-events-none transition-all">
            <span className={`text-2xl font-black font-mono transition-colors ${centerInfo.color}`}>
              {centerInfo.val}
            </span>
            <span className="text-[10px] theme-subtitle font-mono uppercase tracking-wider font-bold mt-0.5">
              {centerInfo.label}
            </span>
          </div>
        </div>

        {/* Legend List (Hoverable) */}
        <div className="space-y-2 font-mono text-xs border-t border-emerald-900/20 pt-3">
          <div 
            onMouseEnter={() => setActiveSegment('ALLOW')}
            onMouseLeave={() => setActiveSegment(null)}
            className={`flex justify-between items-center p-1.5 rounded-lg cursor-pointer transition-colors ${
              activeSegment === 'ALLOW' ? 'bg-emerald-500/10 font-bold' : 'hover:bg-emerald-500/5'
            }`}
          >
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
              <span className="theme-subtitle font-medium">Allowed Queries</span>
            </div>
            <span className="font-bold text-emerald-600 dark:text-emerald-400">{summary.allowed_queries} ({allowPct}%)</span>
          </div>

          <div 
            onMouseEnter={() => setActiveSegment('SUSPICIOUS')}
            onMouseLeave={() => setActiveSegment(null)}
            className={`flex justify-between items-center p-1.5 rounded-lg cursor-pointer transition-colors ${
              activeSegment === 'SUSPICIOUS' ? 'bg-amber-500/10 font-bold' : 'hover:bg-amber-500/5'
            }`}
          >
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
              <span className="theme-subtitle font-medium">Suspicious Flagged</span>
            </div>
            <span className="font-bold text-amber-500">{summary.suspicious_queries} ({suspiciousPct}%)</span>
          </div>

          <div 
            onMouseEnter={() => setActiveSegment('BLOCK')}
            onMouseLeave={() => setActiveSegment(null)}
            className={`flex justify-between items-center p-1.5 rounded-lg cursor-pointer transition-colors ${
              activeSegment === 'BLOCK' ? 'bg-rose-500/10 font-bold' : 'hover:bg-rose-500/5'
            }`}
          >
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
              <span className="theme-subtitle font-medium">Blocked Threats</span>
            </div>
            <span className="font-bold text-rose-500">{summary.blocked_queries} ({blockPct}%)</span>
          </div>
        </div>

      </div>

    </div>
  );
};

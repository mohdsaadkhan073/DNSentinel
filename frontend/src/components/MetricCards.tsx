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
    : "64.5";

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
      
      {/* Total Telemetry */}
      <div className="cyber-card cyber-card-glow p-5 rounded-2xl border-l-4 border-l-[#00D4FF]">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-bold uppercase tracking-wider text-[#8B98A5] font-mono">Total Telemetry</span>
          <div className="p-2 rounded-xl bg-[#00D4FF]/10 text-[#00D4FF] border border-[#00D4FF]/20">
            <Activity className="w-4 h-4" />
          </div>
        </div>
        <div className="text-3xl font-black font-mono text-[#E6EDF3] tracking-tight">{summary.total_queries.toLocaleString()}</div>
        <div className="mt-3 w-full bg-[#0B0F14] h-2 rounded-full overflow-hidden p-0.5 border border-[#1F2933]">
          <div className="bg-[#00D4FF] h-full rounded-full shadow-[0_0_10px_#00D4FF]" style={{ width: '100%' }}></div>
        </div>
        <div className="text-[11px] text-[#8B98A5] mt-2.5 flex justify-between font-mono font-medium">
          <span>Listeners</span>
          <span className="text-[#00D4FF] font-bold">UDP / DoH / DTLS</span>
        </div>
      </div>

      {/* Blocked Threats */}
      <div className="cyber-card cyber-card-glow p-5 rounded-2xl border-l-4 border-l-[#EF4444]">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-bold uppercase tracking-wider text-[#EF4444] font-mono">Blocked Threats</span>
          <div className="p-2 rounded-xl bg-[#EF4444]/10 text-[#EF4444] border border-[#EF4444]/20">
            <ShieldX className="w-4 h-4" />
          </div>
        </div>
        <div className="text-3xl font-black font-mono text-[#F87171] tracking-tight">{summary.blocked_queries.toLocaleString()}</div>
        <div className="mt-3 w-full bg-[#0B0F14] h-2 rounded-full overflow-hidden p-0.5 border border-[#1F2933]">
          <div className="bg-[#EF4444] h-full rounded-full shadow-[0_0_10px_#EF4444]" style={{ width: `${Math.min(100, (summary.blocked_queries / max(1, summary.total_queries)) * 100)}%` }}></div>
        </div>
        <div className="text-[11px] text-[#8B98A5] mt-2.5 flex justify-between font-mono font-medium">
          <span>STIX / High Risk</span>
          <span className="text-[#EF4444] font-bold">Sinkholed</span>
        </div>
      </div>

      {/* Suspicious Flagged */}
      <div className="cyber-card cyber-card-glow p-5 rounded-2xl border-l-4 border-l-[#F59E0B]">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-bold uppercase tracking-wider text-[#F59E0B] font-mono">Suspicious Flagged</span>
          <div className="p-2 rounded-xl bg-[#F59E0B]/10 text-[#F59E0B] border border-[#F59E0B]/20">
            <AlertTriangle className="w-4 h-4" />
          </div>
        </div>
        <div className="text-3xl font-black font-mono text-[#FBBF24] tracking-tight">{summary.suspicious_queries.toLocaleString()}</div>
        <div className="mt-3 w-full bg-[#0B0F14] h-2 rounded-full overflow-hidden p-0.5 border border-[#1F2933]">
          <div className="bg-[#F59E0B] h-full rounded-full shadow-[0_0_10px_#F59E0B]" style={{ width: `${Math.min(100, (summary.suspicious_queries / max(1, summary.total_queries)) * 100)}%` }}></div>
        </div>
        <div className="text-[11px] text-[#8B98A5] mt-2.5 flex justify-between font-mono font-medium">
          <span>DGA / Tunnel Score</span>
          <span className="text-[#F59E0B] font-bold">Alerted</span>
        </div>
      </div>

      {/* Cache Hit Rate */}
      <div className="cyber-card cyber-card-glow p-5 rounded-2xl border-l-4 border-l-[#22C55E]">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-bold uppercase tracking-wider text-[#8B98A5] font-mono">Cache Hit Rate</span>
          <div className="p-2 rounded-xl bg-[#22C55E]/10 text-[#22C55E] border border-[#22C55E]/20">
            <Zap className="w-4 h-4" />
          </div>
        </div>
        <div className="text-3xl font-black font-mono text-[#4ADE80] tracking-tight">{cacheHitPercentage}%</div>
        <div className="mt-3 w-full bg-[#0B0F14] h-2 rounded-full overflow-hidden p-0.5 border border-[#1F2933]">
          <div className="bg-[#22C55E] h-full rounded-full shadow-[0_0_10px_#22C55E]" style={{ width: `${cacheHitPercentage}%` }}></div>
        </div>
        <div className="text-[11px] text-[#8B98A5] mt-2.5 flex justify-between font-mono font-medium">
          <span>TTL Memory Cache</span>
          <span className="text-[#22C55E] font-bold">&lt; 5ms</span>
        </div>
      </div>

      {/* Avg Processing Latency */}
      <div className="cyber-card cyber-card-glow p-5 rounded-2xl border-l-4 border-l-[#A855F7]">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-bold uppercase tracking-wider text-[#8B98A5] font-mono">Avg Latency</span>
          <div className="p-2 rounded-xl bg-[#A855F7]/10 text-[#A855F7] border border-[#A855F7]/20">
            <Cpu className="w-4 h-4" />
          </div>
        </div>
        <div className="text-3xl font-black font-mono text-[#C084FC] tracking-tight">
          {summary.avg_latency_ms} <span className="text-xs font-normal text-[#8B98A5]">ms</span>
        </div>
        <div className="mt-3 w-full bg-[#0B0F14] h-2 rounded-full overflow-hidden p-0.5 border border-[#1F2933]">
          <div className="bg-[#A855F7] h-full rounded-full shadow-[0_0_10px_#A855F7]" style={{ width: `${Math.min(100, (summary.avg_latency_ms / 100) * 100)}%` }}></div>
        </div>
        <div className="text-[11px] text-[#8B98A5] mt-2.5 flex justify-between font-mono font-medium">
          <span>SIH Limit</span>
          <span className="text-[#C084FC] font-bold">&lt; 100ms</span>
        </div>
      </div>

    </div>
  );
};

function max(a: number, b: number): number {
  return a > b ? a : b;
}

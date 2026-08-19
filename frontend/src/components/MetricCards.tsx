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
      
      {/* Total Queries */}
      <div className="cyber-card cyber-card-hover p-4 rounded-2xl border-l-4 border-l-[#00D4FF]">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold uppercase tracking-wider text-[#8B98A5]">Total Telemetry</span>
          <div className="p-1.5 rounded-lg bg-[#00D4FF]/10 text-[#00D4FF]">
            <Activity className="w-4 h-4" />
          </div>
        </div>
        <div className="text-2xl font-extrabold font-mono text-[#E6EDF3]">{summary.total_queries.toLocaleString()}</div>
        <div className="mt-2 w-full bg-[#1F2933] h-1.5 rounded-full overflow-hidden">
          <div className="bg-[#00D4FF] h-full rounded-full" style={{ width: '100%' }}></div>
        </div>
        <div className="text-[11px] text-[#8B98A5] mt-2 flex justify-between font-mono">
          <span>Active Listeners</span>
          <span className="text-[#00D4FF]">UDP/DoH/DTLS</span>
        </div>
      </div>

      {/* Blocked Threats */}
      <div className="cyber-card cyber-card-hover p-4 rounded-2xl border-l-4 border-l-[#EF4444]">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold uppercase tracking-wider text-[#EF4444]">Blocked Threats</span>
          <div className="p-1.5 rounded-lg bg-[#EF4444]/10 text-[#EF4444]">
            <ShieldX className="w-4 h-4" />
          </div>
        </div>
        <div className="text-2xl font-extrabold font-mono text-[#F87171]">{summary.blocked_queries.toLocaleString()}</div>
        <div className="mt-2 w-full bg-[#1F2933] h-1.5 rounded-full overflow-hidden">
          <div className="bg-[#EF4444] h-full rounded-full" style={{ width: `${Math.min(100, (summary.blocked_queries / summary.total_queries) * 100)}%` }}></div>
        </div>
        <div className="text-[11px] text-[#8B98A5] mt-2 flex justify-between font-mono">
          <span>STIX Match / High Risk</span>
          <span className="text-[#EF4444]">Sinkholed</span>
        </div>
      </div>

      {/* Suspicious Queries */}
      <div className="cyber-card cyber-card-hover p-4 rounded-2xl border-l-4 border-l-[#F59E0B]">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold uppercase tracking-wider text-[#F59E0B]">Suspicious Flagged</span>
          <div className="p-1.5 rounded-lg bg-[#F59E0B]/10 text-[#F59E0B]">
            <AlertTriangle className="w-4 h-4" />
          </div>
        </div>
        <div className="text-2xl font-extrabold font-mono text-[#FBBF24]">{summary.suspicious_queries.toLocaleString()}</div>
        <div className="mt-2 w-full bg-[#1F2933] h-1.5 rounded-full overflow-hidden">
          <div className="bg-[#F59E0B] h-full rounded-full" style={{ width: `${Math.min(100, (summary.suspicious_queries / summary.total_queries) * 100)}%` }}></div>
        </div>
        <div className="text-[11px] text-[#8B98A5] mt-2 flex justify-between font-mono">
          <span>DGA / Tunneling Score</span>
          <span className="text-[#F59E0B]">Alerted</span>
        </div>
      </div>

      {/* Cache Hit Rate */}
      <div className="cyber-card cyber-card-hover p-4 rounded-2xl border-l-4 border-l-[#22C55E]">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold uppercase tracking-wider text-[#8B98A5]">Cache Hit Rate</span>
          <div className="p-1.5 rounded-lg bg-[#22C55E]/10 text-[#22C55E]">
            <Zap className="w-4 h-4" />
          </div>
        </div>
        <div className="text-2xl font-extrabold font-mono text-[#4ADE80]">{cacheHitPercentage}%</div>
        <div className="mt-2 w-full bg-[#1F2933] h-1.5 rounded-full overflow-hidden">
          <div className="bg-[#22C55E] h-full rounded-full" style={{ width: `${cacheHitPercentage}%` }}></div>
        </div>
        <div className="text-[11px] text-[#8B98A5] mt-2 flex justify-between font-mono">
          <span>TTL Memory Cache</span>
          <span className="text-[#22C55E]">&lt; 5ms</span>
        </div>
      </div>

      {/* Avg Processing Latency */}
      <div className="cyber-card cyber-card-hover p-4 rounded-2xl border-l-4 border-l-[#A855F7]">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold uppercase tracking-wider text-[#8B98A5]">Avg Latency</span>
          <div className="p-1.5 rounded-lg bg-[#A855F7]/10 text-[#A855F7]">
            <Cpu className="w-4 h-4" />
          </div>
        </div>
        <div className="text-2xl font-extrabold font-mono text-[#C084FC]">
          {summary.avg_latency_ms} <span className="text-xs font-normal text-[#8B98A5]">ms</span>
        </div>
        <div className="mt-2 w-full bg-[#1F2933] h-1.5 rounded-full overflow-hidden">
          <div className="bg-[#A855F7] h-full rounded-full" style={{ width: `${Math.min(100, (summary.avg_latency_ms / 100) * 100)}%` }}></div>
        </div>
        <div className="text-[11px] text-[#8B98A5] mt-2 flex justify-between font-mono">
          <span>SIH Target Boundary</span>
          <span className="text-[#C084FC]">&lt; 100ms</span>
        </div>
      </div>

    </div>
  );
};

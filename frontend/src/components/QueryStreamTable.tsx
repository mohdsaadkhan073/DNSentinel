import React, { useState } from 'react';
import { Eye, Radio, Search, ShieldAlert } from 'lucide-react';

export interface SecurityDecisionItem {
  decision_id: string;
  query: {
    domain: string;
    client_ip: string;
    protocol: string;
    qtype?: string;
    timestamp?: string;
  };
  action: 'ALLOW' | 'BLOCK' | 'SUSPICIOUS';
  composite_risk_score: number;
  intel_result?: {
    matched: boolean;
    threat_category?: string;
    intel_score: number;
  };
  ml_result?: {
    is_dga: boolean;
    dga_probability: number;
  };
  tunnel_result?: {
    is_tunnel: boolean;
    tunnel_score: number;
    entropy: number;
  };
  latency_ms: number;
  cache_hit?: boolean;
  resolved_ip?: string;
  rationale: string;
}

interface TableProps {
  queries: SecurityDecisionItem[];
  onSelectDecision: (item: SecurityDecisionItem) => void;
}

export const QueryStreamTable: React.FC<TableProps> = ({ queries, onSelectDecision }) => {
  const [filterAction, setFilterAction] = useState<'ALL' | 'BLOCK' | 'SUSPICIOUS' | 'ALLOW'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const filteredQueries = queries.filter((q) => {
    const matchesFilter = filterAction === 'ALL' || q.action === filterAction;
    const matchesSearch = q.query.domain.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          q.query.client_ip.includes(searchQuery);
    return matchesFilter && matchesSearch;
  });

  return (
    <div className="cyber-card rounded-2xl p-6 border-[#1F2933]">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
        <div>
          <h2 className="text-lg font-black text-[#E6EDF3] flex items-center gap-2.5 font-mono tracking-tight">
            <Radio className="w-5 h-5 text-[#00D4FF] animate-pulse" />
            Live Security Decision Telemetry Stream
          </h2>
          <p className="text-xs text-[#8B98A5] mt-1 font-medium">Real-time DNS query decisions evaluated across Threat Intel, ML DGA & Tunneling</p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Search Input */}
          <div className="relative">
            <Search className="w-4 h-4 text-[#8B98A5] absolute left-3.5 top-3" />
            <input 
              type="text"
              placeholder="Filter domain or client IP..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10 pr-4 py-2 rounded-xl bg-[#0B0F14] border border-[#1F2933] text-xs text-[#E6EDF3] focus:outline-none focus:border-[#00D4FF] w-56 transition-all shadow-inner font-mono"
            />
          </div>

          {/* Filter Pills */}
          <div className="flex items-center p-1 rounded-xl bg-[#0B0F14] border border-[#1F2933] text-xs font-mono">
            <button 
              onClick={() => setFilterAction('ALL')}
              className={`px-3 py-1.5 rounded-lg transition-all font-semibold ${filterAction === 'ALL' ? 'bg-[#1F2933] text-[#00D4FF] shadow-[0_0_10px_rgba(0,212,255,0.2)]' : 'text-[#8B98A5] hover:text-[#E6EDF3]'}`}
            >
              All ({queries.length})
            </button>
            <button 
              onClick={() => setFilterAction('BLOCK')}
              className={`px-3 py-1.5 rounded-lg transition-all font-semibold ${filterAction === 'BLOCK' ? 'bg-[#EF4444]/20 text-[#EF4444] border border-[#EF4444]/30' : 'text-[#8B98A5] hover:text-[#EF4444]'}`}
            >
              Blocked
            </button>
            <button 
              onClick={() => setFilterAction('SUSPICIOUS')}
              className={`px-3 py-1.5 rounded-lg transition-all font-semibold ${filterAction === 'SUSPICIOUS' ? 'bg-[#F59E0B]/20 text-[#F59E0B] border border-[#F59E0B]/30' : 'text-[#8B98A5] hover:text-[#F59E0B]'}`}
            >
              Suspicious
            </button>
            <button 
              onClick={() => setFilterAction('ALLOW')}
              className={`px-3 py-1.5 rounded-lg transition-all font-semibold ${filterAction === 'ALLOW' ? 'bg-[#22C55E]/20 text-[#4ADE80] border border-[#22C55E]/30' : 'text-[#8B98A5] hover:text-[#4ADE80]'}`}
            >
              Allowed
            </button>
          </div>
        </div>
      </div>

      {/* Stream Table Container */}
      <div className="overflow-x-auto rounded-xl border border-[#1F2933] bg-[#0B0F14]/50">
        <table className="w-full text-left text-xs text-[#E6EDF3]">
          <thead className="bg-[#0B0F14] text-[#8B98A5] font-mono uppercase text-[10px] tracking-wider border-b border-[#1F2933]">
            <tr>
              <th className="py-4 px-4 font-extrabold">Event ID</th>
              <th className="py-4 px-4 font-extrabold">Target Domain</th>
              <th className="py-4 px-4 font-extrabold">Client IP</th>
              <th className="py-4 px-4 font-extrabold">Protocol</th>
              <th className="py-4 px-4 font-extrabold text-center">Status</th>
              <th className="py-4 px-4 font-extrabold text-center">Risk Score</th>
              <th className="py-4 px-4 font-extrabold text-right">Latency</th>
              <th className="py-4 px-4 font-extrabold text-center">Explainable Evidence</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1F2933]/60 font-mono">
            {filteredQueries.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-10 text-center text-[#8B98A5]">
                  No telemetry logs matching your current filters.
                </td>
              </tr>
            ) : (
              filteredQueries.map((item) => {
                const isBlock = item.action === 'BLOCK';
                const isSuspicious = item.action === 'SUSPICIOUS';
                
                let badgeClass = 'badge-allow';
                if (isBlock) badgeClass = 'badge-block';
                if (isSuspicious) badgeClass = 'badge-suspicious';

                return (
                  <tr key={item.decision_id} className="hover:bg-[#1F2933]/50 transition-colors">
                    <td className="py-3.5 px-4 text-[#8B98A5] font-mono text-[11px]">
                      {item.decision_id.slice(0, 8)}
                    </td>
                    <td className="py-3.5 px-4 font-bold text-white max-w-[220px] truncate">
                      {item.query.domain}
                    </td>
                    <td className="py-3.5 px-4 text-[#E6EDF3] font-medium">
                      {item.query.client_ip}
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="px-2.5 py-1 rounded-md bg-[#111820] text-[#8B98A5] border border-[#1F2933] text-[10px] font-bold">
                        {item.query.protocol}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-center">
                      <span className={`px-3 py-1 rounded-full text-[10px] font-extrabold tracking-wider ${badgeClass}`}>
                        {item.action}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-center">
                      <span className={`font-black text-xs ${isBlock ? 'text-[#EF4444]' : isSuspicious ? 'text-[#F59E0B]' : 'text-[#4ADE80]'}`}>
                        {item.composite_risk_score.toFixed(1)} / 100
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-right text-[#8B98A5] font-medium">
                      {item.latency_ms} ms
                    </td>
                    <td className="py-3.5 px-4 text-center">
                      <button
                        onClick={() => onSelectDecision(item)}
                        className="px-3.5 py-1.5 rounded-xl bg-[#00D4FF]/10 hover:bg-[#00D4FF]/20 text-[#00D4FF] border border-[#00D4FF]/30 text-[11px] font-bold flex items-center gap-1.5 mx-auto transition-all shadow-[0_0_12px_rgba(0,212,255,0.15)]"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        Inspect Rationale
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

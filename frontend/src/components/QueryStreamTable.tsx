import React, { useState } from 'react';
import { Eye, Radio, Search, ShieldAlert, CheckCircle2, AlertTriangle, ShieldX } from 'lucide-react';

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
          <h2 className="text-lg font-bold text-[#E6EDF3] flex items-center gap-2 font-mono">
            <Radio className="w-5 h-5 text-[#00D4FF] animate-pulse" />
            Live Security Decision Telemetry Stream
          </h2>
          <p className="text-xs text-[#8B98A5] mt-0.5">Real-time DNS query decisions evaluated across Threat Intel, ML DGA & Tunneling</p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-4 h-4 text-[#8B98A5] absolute left-3 top-2.5" />
            <input 
              type="text"
              placeholder="Search domain or IP..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9 pr-4 py-1.5 rounded-xl bg-[#0B0F14] border border-[#1F2933] text-xs text-[#E6EDF3] focus:outline-none focus:border-[#00D4FF] w-48 transition-all"
            />
          </div>

          {/* Filter Pills */}
          <div className="flex items-center p-1 rounded-xl bg-[#0B0F14] border border-[#1F2933] text-xs font-mono">
            <button 
              onClick={() => setFilterAction('ALL')}
              className={`px-3 py-1 rounded-lg transition-all ${filterAction === 'ALL' ? 'bg-[#1F2933] text-[#00D4FF] font-bold' : 'text-[#8B98A5]'}`}
            >
              All ({queries.length})
            </button>
            <button 
              onClick={() => setFilterAction('BLOCK')}
              className={`px-3 py-1 rounded-lg transition-all ${filterAction === 'BLOCK' ? 'bg-[#EF4444]/20 text-[#EF4444] font-bold' : 'text-[#8B98A5]'}`}
            >
              Blocked
            </button>
            <button 
              onClick={() => setFilterAction('SUSPICIOUS')}
              className={`px-3 py-1 rounded-lg transition-all ${filterAction === 'SUSPICIOUS' ? 'bg-[#F59E0B]/20 text-[#F59E0B] font-bold' : 'text-[#8B98A5]'}`}
            >
              Suspicious
            </button>
            <button 
              onClick={() => setFilterAction('ALLOW')}
              className={`px-3 py-1 rounded-lg transition-all ${filterAction === 'ALLOW' ? 'bg-[#22C55E]/20 text-[#22C55E] font-bold' : 'text-[#8B98A5]'}`}
            >
              Allowed
            </button>
          </div>
        </div>
      </div>

      {/* Stream Table */}
      <div className="overflow-x-auto rounded-xl border border-[#1F2933]">
        <table className="w-full text-left text-xs text-[#E6EDF3]">
          <thead className="bg-[#0B0F14] text-[#8B98A5] font-mono uppercase text-[10px] tracking-wider border-b border-[#1F2933]">
            <tr>
              <th className="py-3.5 px-4">Event ID</th>
              <th className="py-3.5 px-4">Target Domain</th>
              <th className="py-3.5 px-4">Client IP</th>
              <th className="py-3.5 px-4">Protocol</th>
              <th className="py-3.5 px-4 text-center">Security Status</th>
              <th className="py-3.5 px-4 text-center">Risk Score</th>
              <th className="py-3.5 px-4 text-right">Latency</th>
              <th className="py-3.5 px-4 text-center">Explainable Evidence</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1F2933]/60 font-mono">
            {filteredQueries.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-[#8B98A5]">
                  No matching telemetry records found.
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
                  <tr key={item.decision_id} className="hover:bg-[#1F2933]/40 transition-colors">
                    <td className="py-3 px-4 text-[#8B98A5] font-mono text-[11px]">
                      {item.decision_id.slice(0, 8)}
                    </td>
                    <td className="py-3 px-4 font-bold text-white max-w-[220px] truncate">
                      {item.query.domain}
                    </td>
                    <td className="py-3 px-4 text-[#E6EDF3]">
                      {item.query.client_ip}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded-md bg-[#0B0F14] text-[#8B98A5] border border-[#1F2933] text-[10px] font-semibold">
                        {item.query.protocol}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-center">
                      <span className={`px-3 py-1 rounded-full text-[10px] font-extrabold tracking-wider ${badgeClass}`}>
                        {item.action}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-center">
                      <span className={`font-extrabold text-xs ${isBlock ? 'text-[#EF4444]' : isSuspicious ? 'text-[#F59E0B]' : 'text-[#22C55E]'}`}>
                        {item.composite_risk_score.toFixed(1)} / 100
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right text-[#8B98A5]">
                      {item.latency_ms} ms
                    </td>
                    <td className="py-3 px-4 text-center">
                      <button
                        onClick={() => onSelectDecision(item)}
                        className="px-3 py-1.5 rounded-xl bg-[#00D4FF]/10 hover:bg-[#00D4FF]/20 text-[#00D4FF] border border-[#00D4FF]/30 text-[11px] font-medium flex items-center gap-1.5 mx-auto transition-all shadow-[0_0_10px_rgba(0,212,255,0.1)]"
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

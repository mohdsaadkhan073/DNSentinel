import React from 'react';
import { Eye, ShieldAlert, Cpu, Radio } from 'lucide-react';

export interface SecurityDecisionItem {
  decision_id: str;
  query: {
    domain: str;
    client_ip: str;
    protocol: str;
    qtype?: str;
    timestamp?: str;
  };
  action: 'ALLOW' | 'BLOCK' | 'SUSPICIOUS';
  composite_risk_score: number;
  intel_result?: {
    matched: boolean;
    threat_category?: str;
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
  resolved_ip?: str;
  rationale: str;
}

interface TableProps {
  queries: SecurityDecisionItem[];
  onSelectDecision: (item: SecurityDecisionItem) => void;
}

export const QueryStreamTable: React.FC<TableProps> = ({ queries, onSelectDecision }) => {
  return (
    <div className="glass-panel p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Radio className="w-4 h-4 text-cyan-400 animate-pulse" />
            Live Query Telemetry Stream
          </h2>
          <p className="text-xs text-slate-400">Real-time DNS query decisions evaluated across Threat Intel, ML DGA & Tunneling</p>
        </div>
        <span className="text-xs font-mono px-2.5 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700">
          Showing {queries.length} entries
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="bg-slate-900/80 text-slate-400 font-mono uppercase text-[10px] tracking-wider border-b border-slate-800">
            <tr>
              <th className="py-3 px-4">Timestamp / ID</th>
              <th className="py-3 px-4">Domain Name</th>
              <th className="py-3 px-4">Client IP</th>
              <th className="py-3 px-4">Proto</th>
              <th className="py-3 px-4 text-center">Status</th>
              <th className="py-3 px-4 text-center">Risk Score</th>
              <th className="py-3 px-4 text-right">Latency</th>
              <th className="py-3 px-4 text-center">Explainable Evidence</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {queries.map((item) => {
              const isBlock = item.action === 'BLOCK';
              const isSuspicious = item.action === 'SUSPICIOUS';
              
              let badgeClass = 'badge-allow';
              if (isBlock) badgeClass = 'badge-block';
              if (isSuspicious) badgeClass = 'badge-suspicious';

              return (
                <tr key={item.decision_id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                    {item.decision_id.slice(0, 8)}
                  </td>
                  <td className="py-3 px-4 font-semibold text-white max-w-[200px] truncate">
                    {item.query.domain}
                  </td>
                  <td className="py-3 px-4 text-slate-300">
                    {item.query.client_ip}
                  </td>
                  <td className="py-3 px-4">
                    <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 text-[10px]">
                      {item.query.protocol}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-center">
                    <span className={`px-2.5 py-1 rounded-full text-[11px] font-bold tracking-wider ${badgeClass}`}>
                      {item.action}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-center">
                    <span className={`font-bold ${isBlock ? 'text-rose-400' : isSuspicious ? 'text-amber-400' : 'text-emerald-400'}`}>
                      {item.composite_risk_score.toFixed(1)} / 100
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right text-slate-400">
                    {item.latency_ms} ms
                  </td>
                  <td className="py-3 px-4 text-center">
                    <button
                      onClick={() => onSelectDecision(item)}
                      className="px-2.5 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-[11px] font-medium flex items-center gap-1 mx-auto transition-all"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      Inspect Rationale
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};

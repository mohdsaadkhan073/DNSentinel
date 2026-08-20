import React, { useState } from 'react';
import { Search, Filter, Eye, ShieldX, AlertTriangle, CheckCircle2, Zap } from 'lucide-react';

export interface SecurityDecisionItem {
  decision_id: string;
  query: {
    domain: string;
    client_ip: string;
    protocol: string;
    qtype: string;
    timestamp?: string;
  };
  action: 'ALLOW' | 'SUSPICIOUS' | 'BLOCK';
  composite_risk_score: number;
  intel_result: any;
  ml_result: any;
  tunnel_result: any;
  latency_ms: number;
  cache_hit: boolean;
  resolved_ip: string;
  rationale: string;
  created_at?: string;
}

interface TableProps {
  queries: SecurityDecisionItem[];
  onSelectDecision: (decision: SecurityDecisionItem) => void;
}

export const QueryStreamTable: React.FC<TableProps> = ({ queries, onSelectDecision }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterAction, setFilterAction] = useState<string>('ALL');

  // Filter queries based on search term and action pills
  const filteredQueries = queries.filter(item => {
    const matchesSearch = 
      item.query.domain.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.query.client_ip.includes(searchTerm) ||
      (item.resolved_ip && item.resolved_ip.includes(searchTerm));

    if (filterAction === 'ALL') return matchesSearch;
    if (filterAction === 'CACHE') return matchesSearch && item.cache_hit;
    return matchesSearch && item.action === filterAction;
  });

  return (
    <div className="soc-card rounded-2xl overflow-hidden mb-6">
      
      {/* Table Header & Search/Filter Bar */}
      <div className="p-5 border-b border-slate-800 flex flex-col md:flex-row items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100 font-mono tracking-wide flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-indigo-500"></span>
            LIVE DNS TELEMETRY STREAM
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">Real-time threat engine inspection log</p>
        </div>

        <div className="flex flex-col sm:flex-row items-center gap-3 w-full md:w-auto">
          {/* Search Input Bar */}
          <div className="relative w-full sm:w-64">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
            <input
              type="text"
              placeholder="Search domain or IP..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500/50"
            />
          </div>

          {/* Filter Pills */}
          <div className="flex items-center gap-1 bg-slate-900/80 p-1 rounded-xl border border-slate-800 text-xs font-mono w-full sm:w-auto overflow-x-auto">
            {['ALL', 'BLOCK', 'SUSPICIOUS', 'ALLOW', 'CACHE'].map((action) => (
              <button
                key={action}
                onClick={() => setFilterAction(action)}
                className={`px-2.5 py-1 rounded-lg transition-all font-semibold ${
                  filterAction === action
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {action}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Stream Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-slate-900/50 border-b border-slate-800 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              <th className="py-3 px-4">Action</th>
              <th className="py-3 px-4">Domain</th>
              <th className="py-3 px-4">Client IP</th>
              <th className="py-3 px-4">Risk Score</th>
              <th className="py-3 px-4">Protocol</th>
              <th className="py-3 px-4">Latency</th>
              <th className="py-3 px-4">Resolved IP</th>
              <th className="py-3 px-4 text-right">Inspection</th>
            </tr>
          </thead>

          <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
            {filteredQueries.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-slate-500 italic">
                  No telemetry queries matched your filter.
                </td>
              </tr>
            ) : (
              filteredQueries.map((item, idx) => {
                let badgeStyle = "badge-allow";
                let actionIcon = <CheckCircle2 className="w-3.5 h-3.5" />;
                if (item.action === 'BLOCK') {
                  badgeStyle = "badge-block";
                  actionIcon = <ShieldX className="w-3.5 h-3.5" />;
                } else if (item.action === 'SUSPICIOUS') {
                  badgeStyle = "badge-suspicious";
                  actionIcon = <AlertTriangle className="w-3.5 h-3.5" />;
                }

                return (
                  <tr 
                    key={item.decision_id || idx}
                    className="hover:bg-slate-800/40 transition-colors"
                  >
                    {/* Action Badge */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className={`px-2.5 py-1 rounded-lg text-[11px] font-bold flex items-center gap-1.5 w-fit ${badgeStyle}`}>
                        {actionIcon}
                        <span>{item.action}</span>
                      </span>
                    </td>

                    {/* Domain */}
                    <td className="py-3.5 px-4 font-semibold text-slate-200">
                      <div className="max-w-[260px] truncate" title={item.query.domain}>
                        {item.query.domain}
                      </div>
                    </td>

                    {/* Client IP */}
                    <td className="py-3.5 px-4 text-slate-400 whitespace-nowrap">
                      {item.query.client_ip}
                    </td>

                    {/* Risk Score Progress */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <div className="w-16 bg-slate-900 h-2 rounded-full overflow-hidden border border-slate-800">
                          <div 
                            className={`h-full rounded-full ${
                              item.composite_risk_score >= 70 ? 'bg-rose-500' :
                              item.composite_risk_score >= 35 ? 'bg-amber-500' : 'bg-emerald-500'
                            }`}
                            style={{ width: `${Math.min(100, item.composite_risk_score)}%` }}
                          ></div>
                        </div>
                        <span className="font-bold text-slate-300">{item.composite_risk_score}</span>
                      </div>
                    </td>

                    {/* Protocol */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] font-bold">
                        {item.query.protocol || 'UDP'} ({item.query.qtype || 'A'})
                      </span>
                    </td>

                    {/* Latency & Cache */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-1.5 text-slate-300">
                        {item.cache_hit && (
                          <span className="p-1 rounded bg-violet-500/15 text-violet-300" title="In-Memory Cache Hit">
                            <Zap className="w-3 h-3" />
                          </span>
                        )}
                        <span>{item.latency_ms ? `${item.latency_ms} ms` : '< 1ms'}</span>
                      </div>
                    </td>

                    {/* Resolved IP */}
                    <td className="py-3.5 px-4 text-slate-400 whitespace-nowrap">
                      <span className={item.resolved_ip === '0.0.0.0' ? 'text-rose-400 font-bold' : ''}>
                        {item.resolved_ip || '8.8.8.8'}
                      </span>
                    </td>

                    {/* Inspect CTA */}
                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={() => onSelectDecision(item)}
                        className="btn-secondary px-2.5 py-1 rounded-lg text-xs font-semibold hover:border-indigo-500/50 hover:text-indigo-300 inline-flex items-center gap-1"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        <span>Inspect</span>
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

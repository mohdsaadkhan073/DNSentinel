import React, { useState } from 'react';
import { Search, Eye, ShieldX, AlertTriangle, CheckCircle2, Zap } from 'lucide-react';

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
  externalSearch?: string;
}

export const QueryStreamTable: React.FC<TableProps> = ({ queries, onSelectDecision, externalSearch = '' }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterAction, setFilterAction] = useState<string>('ALL');

  const activeSearch = (searchTerm || externalSearch).toLowerCase();

  // Filter queries based on search term and action pills
  const filteredQueries = queries.filter(item => {
    const matchesSearch = 
      item.query.domain.toLowerCase().includes(activeSearch) ||
      item.query.client_ip.includes(activeSearch) ||
      (item.resolved_ip && item.resolved_ip.includes(activeSearch));

    if (filterAction === 'ALL') return matchesSearch;
    if (filterAction === 'CACHE') return matchesSearch && item.cache_hit;
    return matchesSearch && item.action === filterAction;
  });

  return (
    <div className="soc-card rounded-2xl overflow-hidden mb-6 animate-fade-in-up delay-3">
      
      {/* Table Header & Search/Filter Bar */}
      <div className="p-5 border-b border-emerald-900/20 flex flex-col md:flex-row items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold theme-title font-mono tracking-wide flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
            LIVE DNS TELEMETRY STREAM
          </h2>
          <p className="text-xs theme-subtitle mt-0.5">Real-time threat engine inspection log</p>
        </div>

        <div className="flex flex-col sm:flex-row items-center gap-3 w-full md:w-auto">
          {/* Table Search Input Bar */}
          <div className="relative w-full sm:w-64">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
            <input
              type="text"
              placeholder="Filter stream table..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded-xl bg-[var(--input-bg)] border border-emerald-900/20 text-xs font-mono theme-title placeholder-slate-400 focus:outline-none focus:border-emerald-500"
            />
          </div>

          {/* Filter Pills */}
          <div className="flex items-center gap-1 bg-[var(--input-bg)] p-1 rounded-xl border border-emerald-900/20 text-xs font-mono w-full sm:w-auto overflow-x-auto">
            {['ALL', 'BLOCK', 'SUSPICIOUS', 'ALLOW', 'CACHE'].map((action) => (
              <button
                key={action}
                onClick={() => setFilterAction(action)}
                className={`px-2.5 py-1 rounded-lg transition-all font-semibold ${
                  filterAction === action
                    ? 'bg-emerald-600 text-white shadow-sm'
                    : 'theme-subtitle hover:text-emerald-500'
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
            <tr className="bg-[var(--table-head-bg)] border-b border-emerald-900/20 text-[11px] font-mono theme-subtitle uppercase tracking-wider">
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

          <tbody className="divide-y divide-emerald-900/20 font-mono text-xs">
            {filteredQueries.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-8 text-center theme-subtitle italic">
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
                    className="hover:bg-[var(--table-row-hover)] transition-colors"
                  >
                    {/* Action Badge */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className={`px-2.5 py-1 rounded-lg text-[11px] font-bold flex items-center gap-1.5 w-fit ${badgeStyle}`}>
                        {actionIcon}
                        <span>{item.action}</span>
                      </span>
                    </td>

                    {/* Domain */}
                    <td className="py-3.5 px-4 font-semibold theme-title">
                      <div className="max-w-[260px] truncate" title={item.query.domain}>
                        {item.query.domain}
                      </div>
                    </td>

                    {/* Client IP */}
                    <td className="py-3.5 px-4 theme-subtitle whitespace-nowrap">
                      {item.query.client_ip}
                    </td>

                    {/* Risk Score Progress */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <div className="w-16 bg-[var(--input-bg)] h-2 rounded-full overflow-hidden border border-emerald-900/20">
                          <div 
                            className={`h-full rounded-full ${
                              item.composite_risk_score >= 70 ? 'bg-rose-500' :
                              item.composite_risk_score >= 35 ? 'bg-amber-500' : 'bg-emerald-500'
                            }`}
                            style={{ width: `${Math.min(100, item.composite_risk_score)}%` }}
                          ></div>
                        </div>
                        <span className="font-bold theme-title">{item.composite_risk_score}</span>
                      </div>
                    </td>

                    {/* Protocol */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-[var(--input-bg)] theme-title text-[10px] font-bold border border-emerald-900/20">
                        {item.query.protocol || 'UDP'} ({item.query.qtype || 'A'})
                      </span>
                    </td>

                    {/* Latency & Cache */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-1.5 theme-title font-medium">
                        {item.cache_hit && (
                          <span className="p-1 rounded bg-amber-500/15 text-amber-600 dark:text-amber-300" title="In-Memory Cache Hit">
                            <Zap className="w-3 h-3" />
                          </span>
                        )}
                        <span>{item.latency_ms ? `${item.latency_ms} ms` : '< 1ms'}</span>
                      </div>
                    </td>

                    {/* Resolved IP */}
                    <td className="py-3.5 px-4 theme-subtitle whitespace-nowrap">
                      <span className={item.resolved_ip === '0.0.0.0' ? 'text-rose-500 font-bold' : ''}>
                        {item.resolved_ip || '8.8.8.8'}
                      </span>
                    </td>

                    {/* Inspect CTA */}
                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={() => onSelectDecision(item)}
                        className="btn-secondary px-2.5 py-1 rounded-lg text-xs font-semibold hover:border-emerald-500 inline-flex items-center gap-1"
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

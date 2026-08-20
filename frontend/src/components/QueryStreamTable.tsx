import React, { useState, useMemo } from 'react';
import { Search, Eye, ShieldX, AlertTriangle, CheckCircle2, Zap, ArrowUpDown, ChevronLeft, ChevronRight } from 'lucide-react';

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
  theme?: 'dark' | 'light';
}

type SortField = 'action' | 'domain' | 'client_ip' | 'composite_risk_score' | 'latency_ms' | 'resolved_ip';

export const QueryStreamTable: React.FC<TableProps> = ({ queries, onSelectDecision, externalSearch = '', theme = 'light' }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterAction, setFilterAction] = useState<string>('ALL');
  const [sortField, setSortField] = useState<SortField>('composite_risk_score');
  const [sortAsc, setSortAsc] = useState<boolean>(false);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(10);

  const activeSearch = (searchTerm || externalSearch).toLowerCase();

  // Filter queries based on search term and action pills
  const filteredQueries = useMemo(() => {
    return queries.filter(item => {
      const matchesSearch = 
        item.query.domain.toLowerCase().includes(activeSearch) ||
        item.query.client_ip.includes(activeSearch) ||
        (item.resolved_ip && item.resolved_ip.includes(activeSearch));

      if (filterAction === 'ALL') return matchesSearch;
      if (filterAction === 'CACHE') return matchesSearch && item.cache_hit;
      return matchesSearch && item.action === filterAction;
    });
  }, [queries, activeSearch, filterAction]);

  // Sort queries based on selected column
  const sortedQueries = useMemo(() => {
    return [...filteredQueries].sort((a, b) => {
      let valA: any = a[sortField as keyof SecurityDecisionItem];
      let valB: any = b[sortField as keyof SecurityDecisionItem];

      if (sortField === 'domain') {
        valA = a.query.domain.toLowerCase();
        valB = b.query.domain.toLowerCase();
      } else if (sortField === 'client_ip') {
        valA = a.query.client_ip;
        valB = b.query.client_ip;
      }

      if (valA < valB) return sortAsc ? -1 : 1;
      if (valA > valB) return sortAsc ? 1 : -1;
      return 0;
    });
  }, [filteredQueries, sortField, sortAsc]);

  // Pagination calculation
  const totalPages = Math.max(1, Math.ceil(sortedQueries.length / pageSize));
  const paginatedQueries = useMemo(() => {
    const startIndex = (currentPage - 1) * pageSize;
    return sortedQueries.slice(startIndex, startIndex + pageSize);
  }, [sortedQueries, currentPage, pageSize]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  const isLight = theme === 'light';

  return (
    <div className="soc-card rounded-2xl overflow-hidden mb-6 animate-fade-in-up delay-3">
      
      {/* Table Header & Search/Filter Bar */}
      <div className="p-5 border-b border-emerald-900/20 flex flex-col md:flex-row items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold theme-title font-mono tracking-wide flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
            LIVE DNS TELEMETRY STREAM
          </h2>
          <p className="text-xs theme-subtitle mt-0.5">Real-time threat engine inspection log ({sortedQueries.length} total events)</p>
        </div>

        <div className="flex flex-col sm:flex-row items-center gap-3 w-full md:w-auto">
          {/* Table Search Input Bar with Guaranteed Pure White in Light Mode */}
          <div className="relative w-full sm:w-64 flex items-center">
            <Search className="w-4 h-4 absolute left-3 text-slate-400 pointer-events-none shrink-0" />
            <input
              type="text"
              placeholder="Filter stream table..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setCurrentPage(1);
              }}
              style={
                isLight 
                  ? { backgroundColor: '#FFFFFF', color: '#0F172A', borderColor: '#CBD5E1' } 
                  : { backgroundColor: '#05120C', color: '#F8FAFC', borderColor: 'rgba(16, 185, 129, 0.8)' }
              }
              className="w-full pl-9 pr-3 py-1.5 rounded-xl text-xs font-mono placeholder-slate-400 focus:outline-none focus:border-emerald-500 transition-all shadow-sm"
            />
          </div>

          {/* Filter Pills */}
          <div className="flex items-center gap-1 bg-[var(--input-bg)] p-1 rounded-xl border border-emerald-900/20 text-xs font-mono w-full sm:w-auto overflow-x-auto">
            {['ALL', 'BLOCK', 'SUSPICIOUS', 'ALLOW', 'CACHE'].map((action) => (
              <button
                key={action}
                onClick={() => {
                  setFilterAction(action);
                  setCurrentPage(1);
                }}
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
            <tr className="bg-[var(--table-head-bg)] border-b border-emerald-900/20 text-[11px] font-mono theme-subtitle uppercase tracking-wider select-none">
              {/* ACTION Column (Middle Aligned) */}
              <th 
                onClick={() => handleSort('action')}
                className="py-3 px-4 text-center cursor-pointer hover:theme-title transition-colors"
              >
                <div className="flex items-center justify-center gap-1">
                  <span>Action</span>
                  <ArrowUpDown className="w-3 h-3 opacity-60" />
                </div>
              </th>

              {/* DOMAIN Column */}
              <th 
                onClick={() => handleSort('domain')}
                className="py-3 px-4 cursor-pointer hover:theme-title transition-colors"
              >
                <div className="flex items-center gap-1">
                  <span>Domain</span>
                  <ArrowUpDown className="w-3 h-3 opacity-60" />
                </div>
              </th>

              {/* CLIENT IP Column */}
              <th 
                onClick={() => handleSort('client_ip')}
                className="py-3 px-4 cursor-pointer hover:theme-title transition-colors"
              >
                <div className="flex items-center gap-1">
                  <span>Client IP</span>
                  <ArrowUpDown className="w-3 h-3 opacity-60" />
                </div>
              </th>

              {/* RISK SCORE Column */}
              <th 
                onClick={() => handleSort('composite_risk_score')}
                className="py-3 px-4 cursor-pointer hover:theme-title transition-colors"
              >
                <div className="flex items-center gap-1">
                  <span>Risk Score</span>
                  <ArrowUpDown className="w-3 h-3 opacity-60" />
                </div>
              </th>

              {/* PROTOCOL Column (Middle Aligned) */}
              <th className="py-3 px-4 text-center">
                Protocol
              </th>

              {/* LATENCY Column */}
              <th 
                onClick={() => handleSort('latency_ms')}
                className="py-3 px-4 cursor-pointer hover:theme-title transition-colors"
              >
                <div className="flex items-center gap-1">
                  <span>Latency</span>
                  <ArrowUpDown className="w-3 h-3 opacity-60" />
                </div>
              </th>

              {/* RESOLVED IP Column (Middle Aligned) */}
              <th 
                onClick={() => handleSort('resolved_ip')}
                className="py-3 px-4 text-center cursor-pointer hover:theme-title transition-colors"
              >
                <div className="flex items-center justify-center gap-1">
                  <span>Resolved IP</span>
                  <ArrowUpDown className="w-3 h-3 opacity-60" />
                </div>
              </th>

              {/* Inspect CTA Column */}
              <th className="py-3 px-4 text-right">Inspection</th>
            </tr>
          </thead>

          <tbody className="divide-y divide-emerald-900/20 font-mono text-xs">
            {paginatedQueries.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-8 text-center theme-subtitle italic">
                  No telemetry queries matched your filter.
                </td>
              </tr>
            ) : (
              paginatedQueries.map((item, idx) => {
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
                    onClick={() => onSelectDecision(item)}
                    className="hover:bg-[var(--table-row-hover)] cursor-pointer transition-colors group"
                    title="Click anywhere on row to view full inspection evidence"
                  >
                    {/* Action Badge (Middle Aligned) */}
                    <td className="py-3.5 px-4 whitespace-nowrap text-center">
                      <div className="flex justify-center">
                        <span className={`px-2.5 py-1 rounded-lg text-[11px] font-bold flex items-center gap-1.5 w-fit ${badgeStyle}`}>
                          {actionIcon}
                          <span>{item.action}</span>
                        </span>
                      </div>
                    </td>

                    {/* Domain */}
                    <td className="py-3.5 px-4 font-semibold theme-title group-hover:text-emerald-500 transition-colors">
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

                    {/* Protocol (Middle Aligned) */}
                    <td className="py-3.5 px-4 whitespace-nowrap text-center">
                      <span className="px-2 py-0.5 rounded bg-[var(--input-bg)] theme-title text-[10px] font-bold border border-emerald-900/20 inline-block">
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

                    {/* Resolved IP (Middle Aligned) */}
                    <td className="py-3.5 px-4 theme-subtitle whitespace-nowrap text-center">
                      <span className={item.resolved_ip === '0.0.0.0' ? 'text-rose-500 font-bold' : ''}>
                        {item.resolved_ip || '8.8.8.8'}
                      </span>
                    </td>

                    {/* Inspect CTA */}
                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectDecision(item);
                        }}
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

      {/* Pagination Footer */}
      <div className="p-4 border-t border-emerald-900/20 flex flex-col sm:flex-row items-center justify-between gap-3 font-mono text-xs">
        
        {/* Page Size Selector */}
        <div className="flex items-center gap-2">
          <span className="theme-subtitle">Rows per page:</span>
          <select
            value={pageSize}
            onChange={(e) => {
              setPageSize(Number(e.target.value));
              setCurrentPage(1);
            }}
            style={
              isLight 
                ? { backgroundColor: '#FFFFFF', color: '#0F172A', borderColor: '#CBD5E1' } 
                : { backgroundColor: '#05120C', color: '#F8FAFC', borderColor: 'rgba(16, 185, 129, 0.8)' }
            }
            className="px-2 py-1 rounded-lg font-bold focus:outline-none focus:border-emerald-500 shadow-sm"
          >
            <option value={10}>10</option>
            <option value={20}>20</option>
            <option value={50}>50</option>
          </select>
        </div>

        {/* Page Navigation Controls */}
        <div className="flex items-center gap-3">
          <span className="theme-subtitle">
            Page <strong className="theme-title">{currentPage}</strong> of <strong className="theme-title">{totalPages}</strong>
          </span>

          <div className="flex items-center gap-1">
            <button
              onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
              disabled={currentPage === 1}
              className={`p-1.5 rounded-lg btn-secondary ${currentPage === 1 ? 'opacity-40 cursor-not-allowed' : 'hover:border-emerald-500'}`}
              title="Previous Page"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>

            <button
              onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
              disabled={currentPage === totalPages}
              className={`p-1.5 rounded-lg btn-secondary ${currentPage === totalPages ? 'opacity-40 cursor-not-allowed' : 'hover:border-emerald-500'}`}
              title="Next Page"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>

      </div>

    </div>
  );
};

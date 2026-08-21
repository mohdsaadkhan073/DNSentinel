import React, { useState, useEffect, useMemo } from 'react';
import { Search, X, ShieldAlert, CheckCircle2, AlertTriangle, Eye, ArrowRight, LayoutDashboard, Activity, BarChart3, Network, UploadCloud, ShieldX } from 'lucide-react';
import { SecurityDecisionItem } from './QueryStreamTable';

interface SearchModalProps {
  isOpen: boolean;
  onClose: () => void;
  query: string;
  setQuery: (q: string) => void;
  queries: SecurityDecisionItem[];
  onSelectDecision: (decision: SecurityDecisionItem) => void;
  setActiveTab: (tab: string) => void;
}

export const SearchModal: React.FC<SearchModalProps> = ({
  isOpen,
  onClose,
  query,
  setQuery,
  queries,
  onSelectDecision,
  setActiveTab
}) => {
  const [filterType, setFilterType] = useState<'ALL' | 'DOMAINS' | 'IPS' | 'BLOCKED'>('ALL');

  // ESC key listener to close overlay
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (isOpen) onClose();
      }
    };
    if (isOpen) {
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  const activeSearch = query.trim().toLowerCase();

  // Search through security decision queries
  const matchedQueries = useMemo(() => {
    if (!activeSearch) return queries.slice(0, 8);
    return queries.filter(item => {
      const matchesSearch =
        item.query.domain.toLowerCase().includes(activeSearch) ||
        item.query.client_ip.toLowerCase().includes(activeSearch) ||
        (item.resolved_ip && item.resolved_ip.toLowerCase().includes(activeSearch)) ||
        (item.decision_id && item.decision_id.toLowerCase().includes(activeSearch)) ||
        (item.action && item.action.toLowerCase().includes(activeSearch)) ||
        (item.query.protocol && item.query.protocol.toLowerCase().includes(activeSearch)) ||
        (item.rationale && item.rationale.toLowerCase().includes(activeSearch));

      if (filterType === 'ALL') return matchesSearch;
      if (filterType === 'DOMAINS') return matchesSearch && item.query.domain.toLowerCase().includes(activeSearch);
      if (filterType === 'IPS') return matchesSearch && item.query.client_ip.toLowerCase().includes(activeSearch);
      if (filterType === 'BLOCKED') return matchesSearch && item.action === 'BLOCK';
      return matchesSearch;
    });
  }, [queries, activeSearch, filterType]);

  // Search through unique Client IPs
  const matchedIps = useMemo(() => {
    if (!activeSearch) return [];
    const uniqueIps = new Set<string>();
    queries.forEach(q => {
      if (q.query.client_ip.toLowerCase().includes(activeSearch)) {
        uniqueIps.add(q.query.client_ip);
      }
    });
    return Array.from(uniqueIps).slice(0, 4);
  }, [queries, activeSearch]);

  // System shortcut navigation items
  const systemShortcuts = [
    { label: "Dashboard", tab: "DASHBOARD", icon: LayoutDashboard, category: "Navigation" },
    { label: "Live DNS Stream", tab: "LIVE_DNS", icon: Activity, category: "Navigation" },
    { label: "Threat Engine Analytics", tab: "ANALYTICS", icon: BarChart3, category: "Navigation" },
    { label: "Domain Inspector", tab: "DOMAIN_INSPECTOR", icon: Search, category: "Tools" },
    { label: "Source IP Analytics", tab: "SOURCE_IPS", icon: Network, category: "Analytics" },
    { label: "Upload PCAP / Zeek Logs", tab: "PCAP_ZEEK", icon: UploadCloud, category: "Forensics" }
  ].filter(s => !activeSearch || s.label.toLowerCase().includes(activeSearch));

  if (!isOpen) return null;

  return (
    <div 
      className="fixed inset-0 z-50 flex items-start justify-center pt-16 sm:pt-24 px-4 bg-slate-950/80 backdrop-blur-md animate-section-fade"
      onClick={onClose}
    >
      <div 
        className="soc-card rounded-2xl w-full max-w-3xl overflow-hidden flex flex-col border border-emerald-500/40 shadow-2xl animate-section-fade font-mono"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search Modal Input Header */}
        <div className="p-4 border-b border-emerald-900/30 flex items-center gap-3 bg-[var(--input-bg)]">
          <Search className="w-5 h-5 text-emerald-500 shrink-0 animate-pulse" />
          <input
            type="text"
            autoFocus
            placeholder="Search domain, IP address, decision ID, or command..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full bg-transparent text-sm theme-title placeholder-slate-400 outline-none font-medium"
          />
          {query && (
            <button 
              onClick={() => setQuery('')}
              className="p-1 rounded-lg theme-subtitle hover:theme-title transition-colors text-xs font-bold"
              title="Clear input"
            >
              Clear
            </button>
          )}
          <button 
            onClick={onClose}
            className="p-1.5 rounded-xl theme-subtitle hover:text-rose-400 hover:bg-rose-500/15 transition-all shrink-0 border border-transparent hover:border-rose-500/30"
            title="Close modal (Esc)"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Quick Filter Pills Bar */}
        <div className="px-4 py-2 border-b border-emerald-900/20 bg-[var(--input-bg)] flex items-center justify-between gap-2 text-xs overflow-x-auto">
          <div className="flex items-center gap-1.5">
            {(['ALL', 'DOMAINS', 'IPS', 'BLOCKED'] as const).map((t) => (
              <button
                key={t}
                onClick={() => setFilterType(t)}
                className={`px-2.5 py-1 rounded-lg text-[11px] font-bold transition-all ${
                  filterType === t
                    ? 'bg-emerald-600 text-white shadow-sm'
                    : 'theme-subtitle hover:text-emerald-400'
                }`}
              >
                {t}
              </button>
            ))}
          </div>

          <span className="text-[11px] theme-subtitle shrink-0">
            {matchedQueries.length} matches found
          </span>
        </div>

        {/* Search Results Body */}
        <div className="max-h-[60vh] overflow-y-auto p-4 space-y-5 divide-y divide-emerald-900/20">

          {/* 1. Matched Client IPs (if typing an IP) */}
          {matchedIps.length > 0 && (
            <div className="space-y-2 pt-2 first:pt-0">
              <h4 className="text-[11px] font-bold theme-subtitle uppercase tracking-wider flex items-center gap-1.5">
                <Network className="w-3.5 h-3.5 text-cyan-400" />
                <span>Matched Client IPs</span>
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {matchedIps.map((ip) => (
                  <div
                    key={ip}
                    onClick={() => {
                      setActiveTab('SOURCE_IPS');
                      onClose();
                    }}
                    className="p-2.5 rounded-xl border border-emerald-900/20 bg-[var(--input-bg)] hover:border-emerald-500/60 cursor-pointer transition-all flex items-center justify-between group"
                  >
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                      <span className="text-xs font-bold theme-title group-hover:text-emerald-400">{ip}</span>
                    </div>
                    <span className="text-[10px] theme-subtitle flex items-center gap-1 group-hover:text-emerald-400">
                      <span>View Analytics</span>
                      <ArrowRight className="w-3 h-3" />
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 2. Security Decision Queries */}
          <div className="space-y-2 pt-2 first:pt-0">
            <h4 className="text-[11px] font-bold theme-subtitle uppercase tracking-wider flex items-center justify-between">
              <span>Telemetry Events</span>
              {activeSearch && <span className="text-[10px] text-emerald-400 font-normal">Click to Inspect Evidence</span>}
            </h4>

            {matchedQueries.length === 0 ? (
              <div className="py-8 text-center text-xs theme-subtitle italic">
                No telemetry queries or domains matched "{query}".
              </div>
            ) : (
              <div className="space-y-1.5">
                {matchedQueries.map((item, idx) => {
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
                    <div
                      key={item.decision_id || idx}
                      onClick={() => {
                        onSelectDecision(item);
                        onClose();
                      }}
                      className="p-3 rounded-xl border border-emerald-900/20 bg-[var(--input-bg)] hover:border-emerald-500 hover:bg-[var(--table-row-hover)] cursor-pointer transition-all flex items-center justify-between gap-3 group"
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold shrink-0 flex items-center gap-1 ${badgeStyle}`}>
                          {actionIcon}
                          <span>{item.action}</span>
                        </span>
                        <div className="min-w-0">
                          <p className="text-xs font-bold theme-title truncate group-hover:text-emerald-400">
                            {item.query.domain}
                          </p>
                          <p className="text-[10px] theme-subtitle truncate">
                            IP: <span className="theme-title font-semibold">{item.query.client_ip}</span> • Score: <span className="font-bold theme-title">{item.composite_risk_score}</span> • ID: {item.decision_id}
                          </p>
                        </div>
                      </div>

                      <button className="btn-secondary px-2.5 py-1 rounded-lg text-[11px] font-semibold hover:border-emerald-500 shrink-0 inline-flex items-center gap-1">
                        <Eye className="w-3 h-3" />
                        <span>Inspect</span>
                      </button>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* 3. System Navigation Shortcuts */}
          {systemShortcuts.length > 0 && (
            <div className="space-y-2 pt-3">
              <h4 className="text-[11px] font-bold theme-subtitle uppercase tracking-wider">
                System Navigation
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {systemShortcuts.map((sc) => {
                  const IconComp = sc.icon;
                  return (
                    <div
                      key={sc.tab}
                      onClick={() => {
                        setActiveTab(sc.tab);
                        onClose();
                      }}
                      className="p-2.5 rounded-xl border border-emerald-900/20 bg-[var(--input-bg)] hover:border-emerald-500/60 cursor-pointer transition-all flex items-center justify-between group"
                    >
                      <div className="flex items-center gap-2.5">
                        <div className="p-1.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          <IconComp className="w-4 h-4" />
                        </div>
                        <span className="text-xs font-bold theme-title group-hover:text-emerald-400">{sc.label}</span>
                      </div>
                      <span className="text-[10px] theme-subtitle uppercase">{sc.category}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

        </div>
      </div>
    </div>
  );
};

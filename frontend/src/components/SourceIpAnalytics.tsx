import React, { useState, useMemo } from 'react';
import { Network, Search, AlertTriangle, ShieldX, CheckCircle2, ArrowUpDown, Filter, ShieldAlert, Cpu } from 'lucide-react';
import { SecurityDecisionItem } from './QueryStreamTable';

interface SourceIpProps {
  queries: SecurityDecisionItem[];
  onSelectDecision?: (decision: SecurityDecisionItem) => void;
  theme?: 'dark' | 'light';
}

interface IpSummary {
  ip: string;
  totalQueries: number;
  threatsCount: number;
  suspiciousCount: number;
  allowedCount: number;
  maxRiskScore: number;
  avgRiskScore: number;
  status: 'HIGH RISK' | 'SUSPICIOUS' | 'NORMAL';
  lastSeen: string;
  decisions: SecurityDecisionItem[];
}

export const SourceIpAnalytics: React.FC<SourceIpProps> = ({ queries, onSelectDecision, theme = 'light' }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedIpFilter, setSelectedIpFilter] = useState<string | null>(null);

  // Group queries by Client IP
  const ipAnalyticsList: IpSummary[] = useMemo(() => {
    const map = new Map<string, IpSummary>();

    // Initial base seed IPs if active stream has few items
    const defaultIps = [
      { ip: "192.168.1.45", totalQueries: 2842, threatsCount: 37, suspiciousCount: 82, allowedCount: 2723, maxRiskScore: 91, status: 'HIGH RISK' as const },
      { ip: "192.168.1.105", totalQueries: 1420, threatsCount: 12, suspiciousCount: 28, allowedCount: 1380, maxRiskScore: 78, status: 'HIGH RISK' as const },
      { ip: "192.168.1.110", totalQueries: 890, threatsCount: 3, suspiciousCount: 15, allowedCount: 872, maxRiskScore: 45, status: 'SUSPICIOUS' as const },
      { ip: "192.168.1.22", totalQueries: 1104, threatsCount: 0, suspiciousCount: 4, allowedCount: 1100, maxRiskScore: 12, status: 'NORMAL' as const },
      { ip: "192.168.1.102", totalQueries: 620, threatsCount: 0, suspiciousCount: 1, allowedCount: 619, maxRiskScore: 8, status: 'NORMAL' as const },
    ];

    defaultIps.forEach(d => {
      map.set(d.ip, {
        ...d,
        avgRiskScore: Math.round(d.maxRiskScore * 0.7),
        lastSeen: new Date().toLocaleTimeString(),
        decisions: []
      });
    });

    // Aggregate real-time stream queries
    queries.forEach(item => {
      const ip = item.query.client_ip || '192.168.1.100';
      const existing = map.get(ip) || {
        ip,
        totalQueries: 0,
        threatsCount: 0,
        suspiciousCount: 0,
        allowedCount: 0,
        maxRiskScore: 0,
        avgRiskScore: 0,
        status: 'NORMAL',
        lastSeen: item.query.timestamp || item.created_at || 'Just now',
        decisions: []
      };

      existing.totalQueries += 1;
      if (item.action === 'BLOCK') existing.threatsCount += 1;
      else if (item.action === 'SUSPICIOUS') existing.suspiciousCount += 1;
      else existing.allowedCount += 1;

      existing.maxRiskScore = Math.max(existing.maxRiskScore, item.composite_risk_score);
      existing.decisions.push(item);

      if (existing.threatsCount > 0 || existing.maxRiskScore >= 70) {
        existing.status = 'HIGH RISK';
      } else if (existing.suspiciousCount > 0 || existing.maxRiskScore >= 35) {
        existing.status = 'SUSPICIOUS';
      } else {
        existing.status = 'NORMAL';
      }

      map.set(ip, existing);
    });

    return Array.from(map.values()).sort((a, b) => b.maxRiskScore - a.maxRiskScore);
  }, [queries]);

  // Filter list by search term
  const filteredIps = useMemo(() => {
    return ipAnalyticsList.filter(item => item.ip.includes(searchTerm.trim()));
  }, [ipAnalyticsList, searchTerm]);

  // Active IP inspect detail selection
  const activeIpData = useMemo(() => {
    if (!selectedIpFilter) return filteredIps[0] || null;
    return filteredIps.find(i => i.ip === selectedIpFilter) || filteredIps[0] || null;
  }, [filteredIps, selectedIpFilter]);

  const isLight = theme === 'light';

  return (
    <div className="space-y-6 font-mono animate-section-fade">
      
      {/* Header Bar with Title & Search Input */}
      <div className="soc-card p-6 rounded-2xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-2xl bg-emerald-500/15 text-emerald-500 border border-emerald-500/30">
            <Network className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <h2 className="text-lg font-black theme-title tracking-wider uppercase font-mono">
              SOURCE IP ANALYTICS
            </h2>
            <p className="text-xs theme-subtitle mt-0.5">
              Identify high-risk internal endpoints & telemetry traffic volume by Client IP
            </p>
          </div>
        </div>

        {/* Search IP Input */}
        <div className="relative w-full md:w-72">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
          <input
            type="text"
            placeholder="Search Client IP (e.g. 192.168.1.45)..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={
              isLight 
                ? { backgroundColor: '#FFFFFF', color: '#0F172A', borderColor: '#CBD5E1' } 
                : { backgroundColor: '#05120C', color: '#F8FAFC', borderColor: 'rgba(16, 185, 129, 0.8)' }
            }
            className="w-full pl-9 pr-3 py-2 rounded-xl text-xs font-mono placeholder-slate-400 outline-none focus:outline-none focus:ring-2 focus:ring-emerald-500/40 focus:border-emerald-500 transition-all shadow-sm"
          />
        </div>
      </div>

      {/* Grid of Source IP Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
        {filteredIps.map((ipData) => {
          let statusBadge = "bg-emerald-500/15 text-emerald-500 border-emerald-500/30";
          let statusDot = "🔴 HIGH RISK";

          if (ipData.status === 'HIGH RISK') {
            statusBadge = "bg-rose-500/15 text-rose-500 border-rose-500/30";
            statusDot = "🔴 HIGH RISK";
          } else if (ipData.status === 'SUSPICIOUS') {
            statusBadge = "bg-amber-500/15 text-amber-500 border-amber-500/30";
            statusDot = "🟡 SUSPICIOUS";
          } else {
            statusBadge = "bg-emerald-500/15 text-emerald-500 border-emerald-500/30";
            statusDot = "🟢 NORMAL";
          }

          const isSelected = activeIpData?.ip === ipData.ip;

          return (
            <div
              key={ipData.ip}
              onClick={() => setSelectedIpFilter(ipData.ip)}
              className={`soc-card p-5 rounded-2xl cursor-pointer transition-all space-y-4 border ${
                isSelected 
                  ? 'border-emerald-500 ring-2 ring-emerald-500/30 scale-[1.02]' 
                  : 'hover:border-emerald-500/50'
              }`}
            >
              {/* Top IP Title & Status Badge */}
              <div className="flex items-center justify-between pb-3 border-b border-emerald-900/20">
                <span className="text-sm font-black theme-title tracking-wider">{ipData.ip}</span>
                <span className={`px-2.5 py-1 rounded-lg text-[10px] font-bold border ${statusBadge}`}>
                  {statusDot}
                </span>
              </div>

              {/* 4 Core IP Key-Value Metrics */}
              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between items-center">
                  <span className="theme-subtitle">Queries:</span>
                  <strong className="theme-title font-bold">{ipData.totalQueries.toLocaleString()}</strong>
                </div>

                <div className="flex justify-between items-center">
                  <span className="theme-subtitle">Threats:</span>
                  <strong className={ipData.threatsCount > 0 ? "text-rose-500 font-bold" : "theme-title"}>
                    {ipData.threatsCount}
                  </strong>
                </div>

                <div className="flex justify-between items-center">
                  <span className="theme-subtitle">Suspicious:</span>
                  <strong className={ipData.suspiciousCount > 0 ? "text-amber-500 font-bold" : "theme-title"}>
                    {ipData.suspiciousCount}
                  </strong>
                </div>

                <div className="flex justify-between items-center">
                  <span className="theme-subtitle">Risk Score:</span>
                  <strong className={
                    ipData.maxRiskScore >= 70 ? "text-rose-500 font-extrabold" :
                    ipData.maxRiskScore >= 35 ? "text-amber-500 font-extrabold" : "text-emerald-500 font-extrabold"
                  }>
                    {ipData.maxRiskScore} / 100
                  </strong>
                </div>
              </div>

              {/* Progress Risk Bar */}
              <div className="w-full bg-[var(--input-bg)] h-2 rounded-full overflow-hidden border border-emerald-900/20">
                <div
                  className={`h-full rounded-full ${
                    ipData.maxRiskScore >= 70 ? 'bg-rose-500' :
                    ipData.maxRiskScore >= 35 ? 'bg-amber-500' : 'bg-emerald-500'
                  }`}
                  style={{ width: `${Math.min(100, ipData.maxRiskScore)}%` }}
                ></div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Selected IP Telemetry Stream Breakdown Table */}
      {activeIpData && (
        <div className="soc-card p-6 rounded-2xl space-y-4 animate-section-fade">
          <div className="flex items-center justify-between pb-3 border-b border-emerald-900/20">
            <div>
              <span className="text-[10px] font-bold theme-subtitle uppercase block">Selected Endpoint Audit:</span>
              <h3 className="text-base font-black theme-title tracking-wider flex items-center gap-2">
                <Cpu className="w-5 h-5 text-emerald-500" />
                <span>Telemetry History for Client IP <code className="text-emerald-500">{activeIpData.ip}</code></span>
              </h3>
            </div>

            <span className="px-3 py-1 rounded-xl bg-[var(--input-bg)] border border-emerald-900/20 text-xs theme-title font-bold">
              {activeIpData.decisions.length} Active Stream Events Logged
            </span>
          </div>

          {activeIpData.decisions.length === 0 ? (
            <p className="text-xs theme-subtitle italic py-4">No recent live stream queries captured for this IP yet.</p>
          ) : (
            <div className="rounded-xl border border-emerald-900/20 overflow-hidden">
              <table className="w-full text-left border-collapse font-mono text-xs">
                <thead>
                  <tr className="bg-[var(--table-head-bg)] border-b border-emerald-900/20 text-emerald-500 font-bold uppercase tracking-wider">
                    <th className="py-2.5 px-4">Action</th>
                    <th className="py-2.5 px-4">Target Domain</th>
                    <th className="py-2.5 px-4">Protocol</th>
                    <th className="py-2.5 px-4">Risk Score</th>
                    <th className="py-2.5 px-4 text-right">Inspect</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-emerald-900/20">
                  {activeIpData.decisions.map((item, idx) => (
                    <tr key={idx} className="hover:bg-[var(--table-row-hover)] cursor-pointer" onClick={() => onSelectDecision && onSelectDecision(item)}>
                      <td className="py-2.5 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          item.action === 'BLOCK' ? 'badge-block' : item.action === 'SUSPICIOUS' ? 'badge-suspicious' : 'badge-allow'
                        }`}>
                          {item.action}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 font-bold theme-title max-w-[240px] truncate">{item.query.domain}</td>
                      <td className="py-2.5 px-4 theme-subtitle">{item.query.protocol || 'UDP'} ({item.query.qtype || 'A'})</td>
                      <td className="py-2.5 px-4 font-bold text-amber-500">{item.composite_risk_score}</td>
                      <td className="py-2.5 px-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectDecision && onSelectDecision(item);
                          }}
                          className="btn-secondary px-2 py-1 rounded text-[11px] font-bold"
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

    </div>
  );
};

import React from 'react';
import { 
  LayoutDashboard, 
  Search, 
  Activity, 
  BarChart3, 
  Network, 
  FileCode, 
  UploadCloud, 
  RefreshCw, 
  ShieldCheck,
  ChevronLeft,
  ChevronRight,
  Sun,
  Moon
} from 'lucide-react';

interface SidebarProps {
  wsConnected: boolean;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onOpenUpload: () => void;
  onRunTestQuery: (domain: string) => void;
  onRefresh: () => void;
  isCollapsed: boolean;
  setIsCollapsed: (collapsed: boolean) => void;
  theme: 'dark' | 'light';
  setTheme: (theme: 'dark' | 'light') => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  wsConnected,
  activeTab,
  setActiveTab,
  onOpenUpload,
  onRunTestQuery,
  onRefresh,
  isCollapsed,
  setIsCollapsed,
  theme,
  setTheme
}) => {
  // Navigation Menu Order: Dashboard -> Domain Inspector (2nd) -> Live DNS -> Threat Analytics -> Source IPs -> PCAP / Zeek
  const navItems = [
    { id: 'DASHBOARD', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'DOMAIN_INSPECTOR', label: 'Domain Inspector', icon: Search },
    { id: 'LIVE_DNS', label: 'Live DNS', icon: Activity },
    { id: 'ANALYTICS', label: 'Threat Analytics', icon: BarChart3 },
    { id: 'SOURCE_IPS', label: 'Source IPs', icon: Network },
    { id: 'PCAP_ZEEK', label: 'PCAP / Zeek', icon: FileCode },
  ];

  const quickTestDomains = [
    { name: 'google.com', type: 'Clean Domain', action: 'ALLOW' },
    { name: 'bad-c2.com', type: 'C2 Threat Intel', action: 'BLOCK' },
    { name: 'cxz98qwe12a.info', type: 'DGA Flagged', action: 'SUSPICIOUS' },
  ];

  return (
    <aside 
      className={`sidebar-container flex flex-col justify-between transition-all duration-300 z-40 select-none border-r border-emerald-900/30 ${
        isCollapsed ? 'w-20' : 'w-64'
      }`}
      style={{ backgroundColor: 'var(--bg-sidebar)' }}
    >
      {/* Top Brand Header */}
      <div>
        <div className="p-4 flex items-center justify-between border-b border-emerald-900/30">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="p-2.5 rounded-xl bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 shrink-0">
              <ShieldCheck className="w-6 h-6 animate-pulse" />
            </div>
            {!isCollapsed && (
              <div className="flex flex-col">
                <h1 className="text-base font-black tracking-wider text-white font-mono flex items-center gap-1.5">
                  DNSentinel
                </h1>
                <span className="text-[10px] text-emerald-400 font-mono tracking-widest uppercase font-semibold">
                  Threat Engine 2.0
                </span>
              </div>
            )}
          </div>

          <button
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="p-1.5 rounded-lg text-slate-400 hover:text-emerald-400 hover:bg-emerald-900/30 transition-colors"
            title={isCollapsed ? "Expand Sidebar" : "Collapse Sidebar"}
          >
            {isCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Primary Navigation Menu */}
        <nav className="p-3 space-y-1.5 font-mono text-xs">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;

            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center gap-3 px-3.5 py-3 rounded-xl transition-all duration-200 font-semibold ${
                  isActive
                    ? 'bg-emerald-600 text-white shadow-lg shadow-emerald-900/50 font-bold'
                    : 'text-slate-300 hover:text-white hover:bg-emerald-950/60'
                }`}
                title={isCollapsed ? item.label : undefined}
              >
                <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-white' : 'text-emerald-400/80'}`} />
                {!isCollapsed && <span>{item.label}</span>}
              </button>
            );
          })}
        </nav>

        {/* Quick Threat Evaluation Drawer (Expanded Only) */}
        {!isCollapsed && (
          <div className="px-3 py-4 mx-3 my-2 rounded-xl bg-emerald-950/40 border border-emerald-900/40 space-y-2.5 font-mono">
            <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider block">
              Simulate Live Evaluation
            </span>
            <div className="space-y-1.5">
              {quickTestDomains.map((item) => (
                <button
                  key={item.name}
                  onClick={() => onRunTestQuery(item.name)}
                  className="w-full text-left p-2 rounded-lg bg-emerald-900/20 hover:bg-emerald-900/50 border border-emerald-900/30 transition-all flex items-center justify-between group"
                >
                  <div className="truncate pr-2">
                    <span className="text-[11px] font-bold text-white block group-hover:text-emerald-300 transition-colors truncate">
                      {item.name}
                    </span>
                    <span className="text-[9px] text-slate-400 block">{item.type}</span>
                  </div>
                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold shrink-0 ${
                    item.action === 'BLOCK' ? 'bg-rose-500/20 text-rose-300' :
                    item.action === 'SUSPICIOUS' ? 'bg-amber-500/20 text-amber-300' : 'bg-emerald-500/20 text-emerald-300'
                  }`}>
                    {item.action}
                  </span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Sidebar Footer Actions */}
      <div className="p-3 border-t border-emerald-900/30 space-y-2 font-mono text-xs">
        
        {/* Upload Passive Telemetry Batch CTA */}
        <button
          onClick={onOpenUpload}
          className={`w-full flex items-center justify-center gap-2 py-2.5 px-3 rounded-xl btn-emerald-primary text-xs font-bold transition-all shadow-md ${
            isCollapsed ? 'p-2.5' : ''
          }`}
          title="Upload PCAP or Zeek Log Batch"
        >
          <UploadCloud className="w-4 h-4 shrink-0" />
          {!isCollapsed && <span>Upload Batch</span>}
        </button>

        {/* Theme Toggle & Live WebSocket Status */}
        {!isCollapsed ? (
          <div className="pt-2 flex items-center justify-between text-[11px]">
            <button
              onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-emerald-950/60 border border-emerald-900/40 text-slate-300 hover:text-white transition-colors"
            >
              {theme === 'light' ? <Moon className="w-3.5 h-3.5 text-amber-400" /> : <Sun className="w-3.5 h-3.5 text-amber-400" />}
              <span>{theme === 'light' ? 'Dark Mode' : 'Light Mode'}</span>
            </button>

            <div className="flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`}></span>
              <span className="text-[10px] text-slate-400 font-bold">{wsConnected ? 'LIVE' : 'OFFLINE'}</span>
            </div>
          </div>
        ) : (
          <div className="flex justify-center pt-1">
            <span className={`w-2.5 h-2.5 rounded-full ${wsConnected ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} title={wsConnected ? 'WebSocket Telemetry Live' : 'Offline'}></span>
          </div>
        )}

      </div>

    </aside>
  );
};

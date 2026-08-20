import React from 'react';
import { ShieldCheck, LayoutDashboard, Activity, BarChart3, UploadCloud, Terminal, Zap, Radio, RefreshCw } from 'lucide-react';

interface SidebarProps {
  wsConnected: boolean;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onOpenUpload: () => void;
  onRunTestQuery: (domain: string, qtype?: string) => void;
  onRefresh: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  wsConnected,
  activeTab,
  setActiveTab,
  onOpenUpload,
  onRunTestQuery,
  onRefresh
}) => {
  return (
    <aside className="w-full lg:w-72 soc-card rounded-2xl p-5 flex flex-col justify-between shrink-0 h-fit lg:h-[calc(100vh-3rem)] lg:sticky lg:top-6">
      
      {/* Top Section: Brand & Navigation */}
      <div className="space-y-6">
        
        {/* Brand Header */}
        <div className="flex items-center gap-3.5 pb-5 border-b border-slate-800">
          <div className="p-2.5 rounded-xl bg-indigo-500/10 border border-indigo-500/30 text-indigo-400">
            <ShieldCheck className="w-7 h-7 text-indigo-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-black tracking-wider text-slate-100 font-mono">DNSENTINEL</h1>
              <span className="text-[10px] px-2 py-0.5 rounded-md bg-indigo-500/15 text-indigo-300 font-mono font-bold border border-indigo-500/30">
                SOC
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-medium mt-0.5">DNS Security Platform</p>
          </div>
        </div>

        {/* Main Navigation Links */}
        <nav className="space-y-1.5 font-mono text-xs">
          <button
            onClick={() => setActiveTab('DASHBOARD')}
            className={`w-full px-4 py-3 rounded-xl flex items-center gap-3 transition-all font-semibold ${
              activeTab === 'DASHBOARD'
                ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            <LayoutDashboard className="w-4 h-4 text-indigo-400" />
            <span>Dashboard Overview</span>
          </button>

          <button
            onClick={() => setActiveTab('STREAM')}
            className={`w-full px-4 py-3 rounded-xl flex items-center gap-3 transition-all font-semibold ${
              activeTab === 'STREAM'
                ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            <Activity className="w-4 h-4 text-emerald-400" />
            <span>Telemetry Stream</span>
          </button>

          <button
            onClick={() => setActiveTab('ANALYTICS')}
            className={`w-full px-4 py-3 rounded-xl flex items-center gap-3 transition-all font-semibold ${
              activeTab === 'ANALYTICS'
                ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            <BarChart3 className="w-4 h-4 text-violet-400" />
            <span>Threat Analytics</span>
          </button>
        </nav>

        {/* Quick Test Queries Section */}
        <div className="pt-4 border-t border-slate-800 space-y-2">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 font-mono block px-2">
            Threat Test Suite
          </span>

          <div className="space-y-1.5 font-mono text-xs">
            <button
              onClick={() => onRunTestQuery("bad-c2.com")}
              className="w-full px-3 py-2.5 rounded-xl btn-secondary text-left flex items-center gap-2.5 hover:border-rose-500/40"
            >
              <Terminal className="w-3.5 h-3.5 text-rose-400 shrink-0" />
              <span className="truncate">Test C2 Threat IOC</span>
            </button>

            <button
              onClick={() => onRunTestQuery("cxz98qwe12a98f.info")}
              className="w-full px-3 py-2.5 rounded-xl btn-secondary text-left flex items-center gap-2.5 hover:border-amber-500/40"
            >
              <Zap className="w-3.5 h-3.5 text-amber-400 shrink-0" />
              <span className="truncate">Test AI/ML DGA Model</span>
            </button>

            <button
              onClick={() => onRunTestQuery("4f8a91b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8.attacker-tunnel.net", "TXT")}
              className="w-full px-3 py-2.5 rounded-xl btn-secondary text-left flex items-center gap-2.5 hover:border-indigo-500/40"
            >
              <Radio className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
              <span className="truncate">Test DNS Tunneling</span>
            </button>
          </div>
        </div>

        {/* Upload PCAP / Zeek Action Button */}
        <div className="pt-2">
          <button
            onClick={onOpenUpload}
            className="w-full btn-indigo-primary py-3 px-4 rounded-xl text-xs font-bold flex items-center justify-center gap-2"
          >
            <UploadCloud className="w-4 h-4" />
            <span>Upload PCAP / Zeek</span>
          </button>
        </div>

      </div>

      {/* Bottom Section: WebSocket Status & Refresh (Steady Solid Dot, No Blinking) */}
      <div className="pt-5 mt-6 border-t border-slate-800 space-y-3 font-mono">
        <div className="flex items-center justify-between px-3 py-2.5 rounded-xl bg-slate-900/80 border border-slate-800 text-xs">
          <div className="flex items-center gap-2.5">
            <span className={`w-2.5 h-2.5 rounded-full ${wsConnected ? 'bg-emerald-500' : 'bg-rose-500'}`}></span>
            <span className="text-slate-300 font-bold">{wsConnected ? 'WEBSOCKET LIVE' : 'REST POLLING'}</span>
          </div>
          <button
            onClick={onRefresh}
            className="p-1 rounded text-slate-400 hover:text-indigo-400 transition-colors"
            title="Refresh Database Stats"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

    </aside>
  );
};

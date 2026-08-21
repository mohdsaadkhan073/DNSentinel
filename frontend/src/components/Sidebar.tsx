import React, { useState } from 'react';
import {
  ShieldCheck, LayoutDashboard, Activity, BarChart3, UploadCloud,
  RefreshCw, PanelLeftClose, PanelLeftOpen, Search, Network
} from 'lucide-react';

interface SidebarProps {
  wsConnected: boolean;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onOpenUpload: () => void;
  onRunTestQuery: (domain: string, qtype?: string) => void;
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
  onRefresh,
  isCollapsed,
  setIsCollapsed,
  theme,
  setTheme
}) => {
  const [isLogoHovered, setIsLogoHovered] = useState(false);

  // Active tab styling based on theme
  const getActiveTabStyle = (tabName: string) => {
    const isActive = activeTab === tabName;
    if (!isActive) {
      return 'text-emerald-100/70 hover:text-white hover:bg-emerald-950/40';
    }
    // Light Mode gets rich filled active tab, Dark Mode gets outlined minimal filling
    return theme === 'light'
      ? 'bg-emerald-500/25 text-white border border-emerald-400/40 shadow-sm font-bold'
      : 'bg-emerald-500/10 text-white border border-emerald-400/80 font-bold';
  };

  return (
    <aside
      className={`border-r flex flex-col justify-between shrink-0 transition-all duration-300 ${isCollapsed ? 'w-20 p-3' : 'w-72 p-5'
        } h-screen sticky top-0 z-40 ${theme === 'light'
          ? 'bg-[#011711] text-white border-emerald-950'
          : 'bg-[#04160E] text-slate-100 border-emerald-900/40'
        }`}
    >

      {/* Top Section: Brand Header & Navigation Links */}
      <div className="space-y-6">

        {/* Brand Header: Logo box transforms to collapse/expand toggle on hover */}
        <div
          onClick={() => setIsCollapsed(!isCollapsed)}
          onMouseEnter={() => setIsLogoHovered(true)}
          onMouseLeave={() => setIsLogoHovered(false)}
          className={`flex items-center ${isCollapsed ? 'justify-center' : 'justify-between'} pb-4 border-b ${theme === 'light' ? 'border-emerald-900/60' : 'border-emerald-900/40'
            } cursor-pointer group`}
          title={isCollapsed ? "Click to Expand Sidebar" : "Click to Collapse Sidebar"}
        >
          <div className="flex items-center gap-3">
            {/* Logo Icon that seamlessly switches to Toggle Icon on hover */}
            <div className="p-2.5 rounded-xl bg-emerald-950/80 border border-emerald-800/60 text-emerald-400 shrink-0">
              {isLogoHovered ? (
                isCollapsed ? <PanelLeftOpen className="w-5 h-5 text-white" /> : <PanelLeftClose className="w-5 h-5 text-white" />
              ) : (
                <ShieldCheck className="w-5 h-5 text-white" />
              )}
            </div>

            {!isCollapsed && (
              <div className="animate-fade-in-up">
                <h1 className="text-lg font-extrabold tracking-wide text-white font-mono">DNSentinel</h1>
                <p className="text-[10px] text-emerald-200/70 font-medium">Threat Detection Engine</p>
              </div>
            )}
          </div>
        </div>

        {/* Exact 6 Navigation Tabs */}
        <nav className="space-y-1 font-mono text-xs">
          {/* 1. Dashboard */}
          <button
            onClick={() => setActiveTab('DASHBOARD')}
            className={`w-full px-3 py-2.5 rounded-xl flex items-center ${isCollapsed ? 'justify-center' : 'gap-3'} transition-all ${getActiveTabStyle('DASHBOARD')}`}
            title="Dashboard"
          >
            <LayoutDashboard className="w-4 h-4 text-emerald-300 shrink-0" />
            {!isCollapsed && <span>Dashboard</span>}
          </button>

          {/* 2. Domain Inspector */}
          <button
            onClick={() => setActiveTab('DOMAIN_INSPECTOR')}
            className={`w-full px-3 py-2.5 rounded-xl flex items-center ${isCollapsed ? 'justify-center' : 'gap-3'} transition-all ${getActiveTabStyle('DOMAIN_INSPECTOR')}`}
            title="Domain Inspector"
          >
            <Search className="w-4 h-4 text-cyan-300 shrink-0" />
            {!isCollapsed && <span>Domain Inspector</span>}
          </button>

          {/* 3. Live DNS */}
          <button
            onClick={() => setActiveTab('LIVE_DNS')}
            className={`w-full px-3 py-2.5 rounded-xl flex items-center ${isCollapsed ? 'justify-center' : 'gap-3'} transition-all ${getActiveTabStyle('LIVE_DNS')}`}
            title="Live DNS"
          >
            <Activity className="w-4 h-4 text-emerald-300 shrink-0" />
            {!isCollapsed && <span>Live DNS</span>}
          </button>

          {/* 4. Threat Analytics */}
          <button
            onClick={() => setActiveTab('ANALYTICS')}
            className={`w-full px-3 py-2.5 rounded-xl flex items-center ${isCollapsed ? 'justify-center' : 'gap-3'} transition-all ${getActiveTabStyle('ANALYTICS')}`}
            title="Threat Analytics"
          >
            <BarChart3 className="w-4 h-4 text-amber-300 shrink-0" />
            {!isCollapsed && <span>Threat Analytics</span>}
          </button>

          {/* 5. Source IPs */}
          <button
            onClick={() => setActiveTab('SOURCE_IPS')}
            className={`w-full px-3 py-2.5 rounded-xl flex items-center ${isCollapsed ? 'justify-center' : 'gap-3'} transition-all ${getActiveTabStyle('SOURCE_IPS')}`}
            title="Source IPs"
          >
            <Network className="w-4 h-4 text-violet-300 shrink-0" />
            {!isCollapsed && <span>Source IPs</span>}
          </button>

          {/* 6. PCAP / Zeek */}
          <button
            onClick={() => {
              setActiveTab('PCAP_ZEEK');
              onOpenUpload();
            }}
            className={`w-full px-3 py-2.5 rounded-xl flex items-center ${isCollapsed ? 'justify-center' : 'gap-3'} transition-all ${getActiveTabStyle('PCAP_ZEEK')}`}
            title="PCAP / Zeek"
          >
            <UploadCloud className="w-4 h-4 text-emerald-300 shrink-0" />
            {!isCollapsed && <span>PCAP / Zeek</span>}
          </button>
        </nav>

      </div>

      {/* Bottom Section: WebSocket Status Pill */}
      <div className={`pt-4 border-t ${theme === 'light' ? 'border-emerald-900/60' : 'border-emerald-900/40'} space-y-2 font-mono`}>

        {/* WebSocket Status Pill */}
        <div className={`flex items-center ${isCollapsed ? 'justify-center' : 'justify-between px-3'} py-2 rounded-xl bg-emerald-950 border border-emerald-800/80 text-xs text-white`}>
          <div className="flex items-center gap-2">
            <span className={`w-2.5 h-2.5 rounded-full ${wsConnected ? 'bg-emerald-400' : 'bg-rose-500'}`}></span>
            {!isCollapsed && <span className="font-bold">{wsConnected ? 'WEBSOCKET LIVE' : 'REST POLLING'}</span>}
          </div>
          {!isCollapsed && (
            <button
              onClick={onRefresh}
              className="p-1 rounded text-emerald-300 hover:text-white transition-colors"
              title="Refresh Database Stats"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

    </aside>
  );
};

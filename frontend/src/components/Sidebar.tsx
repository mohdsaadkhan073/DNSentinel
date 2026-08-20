import React, { useState } from 'react';
import { 
  ShieldCheck, LayoutDashboard, Activity, BarChart3, UploadCloud, 
  Terminal, Zap, Radio, RefreshCw, PanelLeftClose, PanelLeftOpen,
  Sun, Moon
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
  onRunTestQuery,
  onRefresh,
  isCollapsed,
  setIsCollapsed,
  theme,
  setTheme
}) => {
  const [isLogoHovered, setIsLogoHovered] = useState(false);

  return (
    <aside 
      className={`border-r border-emerald-900/50 flex flex-col justify-between shrink-0 transition-all duration-300 ${
        isCollapsed ? 'w-20 p-3' : 'w-72 p-5'
      } h-screen sticky top-0 z-40 ${
        theme === 'light' ? 'bg-[#011711] text-white' : 'bg-[#04160E] text-slate-100'
      } backdrop-blur-none shadow-2xl`}
    >
      
      {/* Top Section: Brand Header & Navigation Links */}
      <div className="space-y-6">
        
        {/* Brand Header: Logo box transforms to collapse/expand toggle on hover */}
        <div 
          onClick={() => setIsCollapsed(!isCollapsed)}
          onMouseEnter={() => setIsLogoHovered(true)}
          onMouseLeave={() => setIsLogoHovered(false)}
          className={`flex items-center ${isCollapsed ? 'justify-center' : 'justify-between'} pb-5 border-b border-emerald-800/50 cursor-pointer group`}
          title={isCollapsed ? "Click to Expand Sidebar" : "Click to Collapse Sidebar"}
        >
          <div className="flex items-center gap-3">
            {/* Logo Icon that seamlessly switches to Toggle Icon on hover */}
            <div className="p-2.5 rounded-xl bg-emerald-500/20 border border-emerald-400/30 text-emerald-300 group-hover:border-emerald-300 group-hover:bg-emerald-500/30 transition-all shrink-0">
              {isLogoHovered ? (
                isCollapsed ? <PanelLeftOpen className="w-6 h-6 text-white" /> : <PanelLeftClose className="w-6 h-6 text-white" />
              ) : (
                <ShieldCheck className="w-6 h-6 text-white" />
              )}
            </div>

            {!isCollapsed && (
              <div className="animate-fade-in-up">
                <h1 className="text-xl font-extrabold tracking-wide text-white font-mono">DNSentinel</h1>
                <p className="text-[11px] text-emerald-200/80 font-medium mt-0.5">Threat Detection Engine</p>
              </div>
            )}
          </div>
        </div>

        {/* Navigation Section */}
        <nav className="space-y-1.5 font-mono text-xs">
          <button
            onClick={() => setActiveTab('DASHBOARD')}
            className={`w-full px-3.5 py-3 rounded-xl flex items-center ${isCollapsed ? 'justify-center' : 'gap-3'} transition-all font-semibold ${
              activeTab === 'DASHBOARD'
                ? 'bg-emerald-500/25 text-white border border-emerald-400/40 shadow-sm'
                : 'text-emerald-100/80 hover:text-white hover:bg-emerald-800/40'
            }`}
            title="Dashboard Overview"
          >
            <LayoutDashboard className="w-4 h-4 text-emerald-300 shrink-0" />
            {!isCollapsed && <span>Dashboard Overview</span>}
          </button>

          <button
            onClick={() => setActiveTab('STREAM')}
            className={`w-full px-3.5 py-3 rounded-xl flex items-center ${isCollapsed ? 'justify-center' : 'gap-3'} transition-all font-semibold ${
              activeTab === 'STREAM'
                ? 'bg-emerald-500/25 text-white border border-emerald-400/40 shadow-sm'
                : 'text-emerald-100/80 hover:text-white hover:bg-emerald-800/40'
            }`}
            title="Telemetry Stream"
          >
            <Activity className="w-4 h-4 text-emerald-300 shrink-0" />
            {!isCollapsed && <span>Telemetry Stream</span>}
          </button>

          <button
            onClick={() => setActiveTab('ANALYTICS')}
            className={`w-full px-3.5 py-3 rounded-xl flex items-center ${isCollapsed ? 'justify-center' : 'gap-3'} transition-all font-semibold ${
              activeTab === 'ANALYTICS'
                ? 'bg-emerald-500/25 text-white border border-emerald-400/40 shadow-sm'
                : 'text-emerald-100/80 hover:text-white hover:bg-emerald-800/40'
            }`}
            title="Threat Analytics"
          >
            <BarChart3 className="w-4 h-4 text-amber-300 shrink-0" />
            {!isCollapsed && <span>Threat Analytics</span>}
          </button>
        </nav>

        {/* Quick Threat Test Suite */}
        {!isCollapsed ? (
          <div className="pt-4 border-t border-emerald-800/50 space-y-2 animate-fade-in-up">
            <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-200/70 font-mono block px-2">
              Threat Test Suite
            </span>

            <div className="space-y-1.5 font-mono text-xs">
              <button
                onClick={() => onRunTestQuery("bad-c2.com")}
                className="w-full px-3 py-2 rounded-xl bg-emerald-950/60 hover:bg-emerald-900/80 border border-emerald-700/40 text-left flex items-center gap-2.5 text-emerald-100"
              >
                <Terminal className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                <span className="truncate">Test C2 Threat IOC</span>
              </button>

              <button
                onClick={() => onRunTestQuery("cxz98qwe12a98f.info")}
                className="w-full px-3 py-2 rounded-xl bg-emerald-950/60 hover:bg-emerald-900/80 border border-emerald-700/40 text-left flex items-center gap-2.5 text-emerald-100"
              >
                <Zap className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                <span className="truncate">Test AI/ML DGA Model</span>
              </button>

              <button
                onClick={() => onRunTestQuery("4f8a91b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8.attacker-tunnel.net", "TXT")}
                className="w-full px-3 py-2 rounded-xl bg-emerald-950/60 hover:bg-emerald-900/80 border border-emerald-700/40 text-left flex items-center gap-2.5 text-emerald-100"
              >
                <Radio className="w-3.5 h-3.5 text-emerald-300 shrink-0" />
                <span className="truncate">Test DNS Tunneling</span>
              </button>
            </div>
          </div>
        ) : (
          <div className="pt-4 border-t border-emerald-800/50 space-y-2 flex flex-col items-center">
            <button
              onClick={() => onRunTestQuery("bad-c2.com")}
              className="p-2.5 rounded-xl bg-emerald-950/60 hover:bg-emerald-900/80 border border-emerald-700/40 text-rose-400"
              title="Test C2 Threat IOC"
            >
              <Terminal className="w-4 h-4" />
            </button>
            <button
              onClick={() => onRunTestQuery("cxz98qwe12a98f.info")}
              className="p-2.5 rounded-xl bg-emerald-950/60 hover:bg-emerald-900/80 border border-emerald-700/40 text-amber-400"
              title="Test AI/ML DGA Model"
            >
              <Zap className="w-4 h-4" />
            </button>
            <button
              onClick={() => onRunTestQuery("4f8a91b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8.attacker-tunnel.net", "TXT")}
              className="p-2.5 rounded-xl bg-emerald-950/60 hover:bg-emerald-900/80 border border-emerald-700/40 text-emerald-300"
              title="Test DNS Tunneling"
            >
              <Radio className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Upload PCAP / Zeek Action Button */}
        <div className="pt-2">
          <button
            onClick={onOpenUpload}
            className={`w-full btn-emerald-primary py-2.5 ${isCollapsed ? 'px-2' : 'px-4'} rounded-xl text-xs font-bold flex items-center justify-center gap-2`}
            title="Upload PCAP / Zeek File"
          >
            <UploadCloud className="w-4 h-4 shrink-0 text-white" />
            {!isCollapsed && <span>Upload PCAP / Zeek</span>}
          </button>
        </div>

      </div>

      {/* Bottom Section: Theme Switcher & WebSocket Status Pill */}
      <div className="pt-4 border-t border-emerald-800/50 space-y-2 font-mono">
        
        {/* Theme Toggle Button */}
        <button
          onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
          className={`w-full py-2 ${isCollapsed ? 'px-2 justify-center' : 'px-3 justify-between'} rounded-xl bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-700/50 flex items-center text-xs text-white transition-all`}
          title={theme === 'dark' ? "Switch to Light Emerald Theme" : "Switch to Dark Emerald Command Theme"}
        >
          <div className="flex items-center gap-2">
            {theme === 'dark' ? <Moon className="w-4 h-4 text-amber-300" /> : <Sun className="w-4 h-4 text-amber-400" />}
            {!isCollapsed && <span>{theme === 'dark' ? 'Dark Command' : 'Light Enterprise'}</span>}
          </div>
          {!isCollapsed && <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-emerald-800 text-emerald-200">TOGGLE</span>}
        </button>

        {/* WebSocket Status Pill */}
        <div className={`flex items-center ${isCollapsed ? 'justify-center' : 'justify-between px-3'} py-2 rounded-xl bg-emerald-950 border border-emerald-800 text-xs text-white`}>
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

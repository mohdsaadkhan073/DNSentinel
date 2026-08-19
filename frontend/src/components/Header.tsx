import React from 'react';
import { ShieldCheck, Activity, Terminal, Lock, RefreshCw } from 'lucide-react';

interface HeaderProps {
  wsConnected: boolean;
  onOpenUpload: () => void;
  onRunTestQuery: (domain: string) => void;
  onRefresh: () => void;
}

export const Header: React.FC<HeaderProps> = ({ wsConnected, onOpenUpload, onRunTestQuery, onRefresh }) => {
  return (
    <header className="cyber-card rounded-2xl p-4 mb-6 sticky top-4 z-40 flex flex-col lg:flex-row items-center justify-between gap-4 border-[#1F2933]">
      {/* Brand & Logo */}
      <div className="flex items-center gap-3.5 w-full lg:w-auto">
        <div className="relative flex items-center justify-center p-3 rounded-xl bg-[#00D4FF]/10 border border-[#00D4FF]/30 text-[#00D4FF] shadow-[0_0_20px_rgba(0,212,255,0.2)]">
          <ShieldCheck className="w-7 h-7 text-[#00D4FF]" />
          <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-[#22C55E] animate-ping"></span>
        </div>
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-[#E6EDF3] font-mono">DNSENTINEL</h1>
            <span className="text-[11px] px-2 py-0.5 rounded-md bg-[#22C55E]/15 text-[#22C55E] font-mono font-semibold border border-[#22C55E]/30">
              SIH1524
            </span>
          </div>
          <p className="text-xs text-[#8B98A5] mt-0.5">Next-Gen Cyber Security & Explainable Threat Telemetry Platform</p>
        </div>
      </div>

      {/* Action Controls & Indicators */}
      <div className="flex items-center gap-3 w-full lg:w-auto overflow-x-auto pb-1 lg:pb-0">
        
        {/* Connection Status Badge */}
        <div className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-[#0B0F14] border border-[#1F2933] text-xs font-mono">
          <span className={`w-2.5 h-2.5 rounded-full ${wsConnected ? 'bg-[#22C55E] shadow-[0_0_10px_#22C55E]' : 'bg-[#EF4444]'}`}></span>
          <span className="text-[#E6EDF3] font-semibold">{wsConnected ? 'WEBSOCKET ACTIVE' : 'REST POLLING'}</span>
        </div>

        {/* Quick Test Queries */}
        <button 
          onClick={() => onRunTestQuery("bad-c2.com")}
          className="btn-cyber-ghost px-3.5 py-2 text-xs font-medium flex items-center gap-1.5 whitespace-nowrap"
        >
          <Terminal className="w-3.5 h-3.5 text-[#F59E0B]" />
          <span>Test C2 Match</span>
        </button>

        <button 
          onClick={() => onRunTestQuery("cxz98qwe12a.info")}
          className="btn-cyber-ghost px-3.5 py-2 text-xs font-medium flex items-center gap-1.5 whitespace-nowrap"
        >
          <Terminal className="w-3.5 h-3.5 text-[#00D4FF]" />
          <span>Test ML DGA</span>
        </button>

        <button 
          onClick={onRefresh}
          className="p-2 rounded-xl bg-[#111820] hover:bg-[#1F2933] border border-[#1F2933] text-[#8B98A5] hover:text-[#00D4FF] transition-all"
          title="Refresh Data"
        >
          <RefreshCw className="w-4 h-4" />
        </button>

        {/* Upload PCAP Button */}
        <button 
          onClick={onOpenUpload}
          className="btn-cyber-primary px-4 py-2 text-xs font-semibold flex items-center gap-2 whitespace-nowrap"
        >
          <Activity className="w-4 h-4" />
          <span>Upload PCAP / Zeek</span>
        </button>

      </div>
    </header>
  );
};

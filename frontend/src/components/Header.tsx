import React from 'react';
import { ShieldCheck, Activity, Terminal, RefreshCw, Zap } from 'lucide-react';

interface HeaderProps {
  wsConnected: boolean;
  onOpenUpload: () => void;
  onRunTestQuery: (domain: string) => void;
  onRefresh: () => void;
}

export const Header: React.FC<HeaderProps> = ({ wsConnected, onOpenUpload, onRunTestQuery, onRefresh }) => {
  return (
    <header className="cyber-card rounded-2xl p-5 mb-6 sticky top-4 z-40 border-[#1F2933]">
      <div className="flex flex-col lg:flex-row items-center justify-between gap-4">
        
        {/* Brand Logo & Name */}
        <div className="flex items-center gap-4 w-full lg:w-auto">
          <div className="relative flex items-center justify-center p-3 rounded-2xl bg-[#00D4FF]/10 border border-[#00D4FF]/30 text-[#00D4FF] shadow-[0_0_25px_rgba(0,212,255,0.25)]">
            <ShieldCheck className="w-8 h-8 text-[#00D4FF]" />
            <span className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-[#22C55E] animate-ping"></span>
          </div>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-black tracking-wider text-[#E6EDF3] font-mono">DNSENTINEL</h1>
              <span className="text-[11px] px-2.5 py-0.5 rounded-full bg-[#22C55E]/15 text-[#4ADE80] font-mono font-extrabold border border-[#22C55E]/40 shadow-[0_0_10px_rgba(34,197,94,0.2)]">
                SIH1524
              </span>
            </div>
            <p className="text-xs text-[#8B98A5] mt-0.5 font-medium">Production-Oriented DNS Threat Detection & Telemetry Platform</p>
          </div>
        </div>

        {/* Status Indicators & Action Buttons */}
        <div className="flex items-center gap-3 w-full lg:w-auto overflow-x-auto pb-1 lg:pb-0">
          
          {/* WebSocket Status Indicator */}
          <div className="flex items-center gap-2.5 px-4 py-2 rounded-xl bg-[#0B0F14] border border-[#1F2933] text-xs font-mono">
            <div className="relative flex items-center justify-center">
              <span className={`w-2.5 h-2.5 rounded-full ${wsConnected ? 'bg-[#22C55E]' : 'bg-[#EF4444]'}`}></span>
              {wsConnected && <span className="absolute w-4 h-4 rounded-full bg-[#22C55E]/40 animate-ping"></span>}
            </div>
            <span className="text-[#E6EDF3] font-bold tracking-wide">{wsConnected ? 'WEBSOCKET ACTIVE' : 'REST POLLING'}</span>
          </div>

          {/* Quick Test Queries */}
          <button 
            onClick={() => onRunTestQuery("bad-c2.com")}
            className="px-3.5 py-2 rounded-xl bg-[#111820] hover:bg-[#1F2933] border border-[#1F2933] hover:border-[#F59E0B]/50 text-xs font-semibold text-[#E6EDF3] hover:text-[#F59E0B] flex items-center gap-1.5 transition-all shadow-sm"
          >
            <Terminal className="w-3.5 h-3.5 text-[#F59E0B]" />
            <span>Test C2 Match</span>
          </button>

          <button 
            onClick={() => onRunTestQuery("cxz98qwe12a.info")}
            className="px-3.5 py-2 rounded-xl bg-[#111820] hover:bg-[#1F2933] border border-[#1F2933] hover:border-[#00D4FF]/50 text-xs font-semibold text-[#E6EDF3] hover:text-[#00D4FF] flex items-center gap-1.5 transition-all shadow-sm"
          >
            <Zap className="w-3.5 h-3.5 text-[#00D4FF]" />
            <span>Test DGA</span>
          </button>

          <button 
            onClick={onRefresh}
            className="p-2.5 rounded-xl bg-[#111820] hover:bg-[#1F2933] border border-[#1F2933] text-[#8B98A5] hover:text-[#00D4FF] transition-all"
            title="Refresh Data"
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          {/* Upload PCAP / Zeek Button */}
          <button 
            onClick={onOpenUpload}
            className="btn-cyan-glow px-4 py-2 text-xs font-bold flex items-center gap-2 rounded-xl"
          >
            <Activity className="w-4 h-4" />
            <span>Upload PCAP / Zeek</span>
          </button>

        </div>
      </div>
    </header>
  );
};

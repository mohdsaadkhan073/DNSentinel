import React from 'react';
import { ShieldCheck, Terminal, RefreshCw, UploadCloud, Zap, Radio } from 'lucide-react';

interface HeaderProps {
  wsConnected: boolean;
  onOpenUpload: () => void;
  onRunTestQuery: (domain: string, qtype?: string) => void;
  onRefresh: () => void;
}

export const Header: React.FC<HeaderProps> = ({ wsConnected, onOpenUpload, onRunTestQuery, onRefresh }) => {
  return (
    <header className="soc-card rounded-2xl p-5 mb-6 sticky top-4 z-40">
      <div className="flex flex-col lg:flex-row items-center justify-between gap-4">
        
        {/* Brand & Platform Identifier */}
        <div className="flex items-center gap-4 w-full lg:w-auto">
          <div className="relative flex items-center justify-center p-3 rounded-2xl bg-indigo-500/10 border border-indigo-500/30 text-indigo-400 shadow-[0_0_20px_rgba(99,102,241,0.2)]">
            <ShieldCheck className="w-8 h-8 text-indigo-400" />
            <span className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-emerald-500 animate-ping"></span>
          </div>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-black tracking-wider text-slate-100 font-mono">DNSENTINEL</h1>
              <span className="text-[11px] px-2.5 py-0.5 rounded-full bg-indigo-500/15 text-indigo-300 font-mono font-bold border border-indigo-500/30">
                SOC v2.0
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5 font-medium">Enterprise DNS Threat Detection & Passive Network Telemetry Platform</p>
          </div>
        </div>

        {/* Action Toolbar & Connectivity */}
        <div className="flex items-center gap-3 w-full lg:w-auto overflow-x-auto pb-1 lg:pb-0">
          
          {/* WebSocket Status Indicator */}
          <div className="flex items-center gap-2.5 px-3.5 py-2 rounded-xl bg-slate-900/80 border border-slate-800 text-xs font-mono">
            <div className="relative flex items-center justify-center">
              <span className={`w-2.5 h-2.5 rounded-full ${wsConnected ? 'bg-emerald-500' : 'bg-rose-500'}`}></span>
              {wsConnected && <span className="absolute w-4 h-4 rounded-full bg-emerald-500/40 animate-ping"></span>}
            </div>
            <span className="text-slate-200 font-bold tracking-wide">{wsConnected ? 'WEBSOCKET LIVE' : 'POLLING'}</span>
          </div>

          {/* Quick Test Queries */}
          <button 
            onClick={() => onRunTestQuery("bad-c2.com")}
            className="btn-secondary px-3 py-2 rounded-xl text-xs font-semibold flex items-center gap-1.5"
            title="Test Threat Intel IOC Match"
          >
            <Terminal className="w-3.5 h-3.5 text-rose-400" />
            <span>Test C2 Match</span>
          </button>

          <button 
            onClick={() => onRunTestQuery("cxz98qwe12a98f.info")}
            className="btn-secondary px-3 py-2 rounded-xl text-xs font-semibold flex items-center gap-1.5"
            title="Test AI/ML DGA Model"
          >
            <Zap className="w-3.5 h-3.5 text-amber-400" />
            <span>Test DGA</span>
          </button>

          <button 
            onClick={() => onRunTestQuery("4f8a91b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8.attacker-tunnel.net", "TXT")}
            className="btn-secondary px-3 py-2 rounded-xl text-xs font-semibold flex items-center gap-1.5"
            title="Test Active DNS Tunnel Exfiltration"
          >
            <Radio className="w-3.5 h-3.5 text-indigo-400" />
            <span>Test Tunnel</span>
          </button>

          <button 
            onClick={onRefresh}
            className="p-2.5 rounded-xl btn-secondary text-slate-400 hover:text-indigo-400"
            title="Refresh Database Stats"
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          {/* Upload PCAP / Zeek Button */}
          <button 
            onClick={onOpenUpload}
            className="btn-indigo-primary px-4 py-2 text-xs font-bold flex items-center gap-2 rounded-xl"
          >
            <UploadCloud className="w-4 h-4" />
            <span>Upload PCAP / Zeek</span>
          </button>

        </div>
      </div>
    </header>
  );
};

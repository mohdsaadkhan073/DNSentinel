import React from 'react';
import { ShieldAlert, Activity, Wifi, Terminal } from 'lucide-react';

interface HeaderProps {
  wsConnected: boolean;
  onOpenUpload: () => void;
  onRunTestQuery: (domain: string) => void;
}

export const Header: React.FC<HeaderProps> = ({ wsConnected, onOpenUpload, onRunTestQuery }) => {
  return (
    <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur-md sticky top-0 z-40 px-6 py-4 flex flex-col md:flex-row items-center justify-between gap-4">
      <div className="flex items-center space-x-3">
        <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-xl text-cyan-400">
          <ShieldAlert className="w-7 h-7" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-white tracking-tight">DNSENTINEL</h1>
            <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-mono border border-cyan-500/30">SIH1524</span>
          </div>
          <p className="text-xs text-slate-400">DNS Threat Detection & Telemetry Platform Prototype</p>
        </div>
      </div>

      <div className="flex items-center gap-3 w-full md:w-auto overflow-x-auto">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700/60 text-xs text-slate-300 font-mono">
          <Wifi className={`w-3.5 h-3.5 ${wsConnected ? 'text-emerald-400 animate-pulse' : 'text-rose-400'}`} />
          <span>{wsConnected ? 'LIVE STREAM' : 'REST POLLING'}</span>
        </div>

        <button 
          onClick={() => onRunTestQuery("bad-c2.com")}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-medium text-slate-200 transition-all"
        >
          <Terminal className="w-3.5 h-3.5 text-amber-400" />
          Test Malicious Query
        </button>

        <button 
          onClick={() => onRunTestQuery("cxz98qwe12a.info")}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-medium text-slate-200 transition-all"
        >
          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
          Test DGA Query
        </button>

        <button 
          onClick={onOpenUpload}
          className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white shadow-lg shadow-cyan-600/20 transition-all"
        >
          <Activity className="w-3.5 h-3.5" />
          Upload PCAP / Zeek
        </button>
      </div>
    </header>
  );
};

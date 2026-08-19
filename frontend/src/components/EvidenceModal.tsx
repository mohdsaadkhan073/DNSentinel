import React from 'react';
import { X, ShieldAlert, Cpu, Network, Database, CheckCircle, AlertTriangle } from 'lucide-react';
import { SecurityDecisionItem } from './QueryStreamTable';

interface ModalProps {
  decision: SecurityDecisionItem | null;
  onClose: () => void;
}

export const EvidenceModal: React.FC<ModalProps> = ({ decision, onClose }) => {
  if (!decision) return null;

  const isBlock = decision.action === 'BLOCK';
  const isSuspicious = decision.action === 'SUSPICIOUS';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md">
      <div className="glass-panel w-full max-w-2xl overflow-hidden shadow-2xl border border-slate-700 animate-in fade-in zoom-in duration-200">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/90">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-xl border ${isBlock ? 'bg-rose-500/10 border-rose-500/30 text-rose-400' : isSuspicious ? 'bg-amber-500/10 border-amber-500/30 text-amber-400' : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'}`}>
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white font-mono">Domain Evidence Inspector</h3>
              <p className="text-xs text-slate-400">Explainable AI Telemetry & Security Attribution</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          
          {/* Domain & Decision Banner */}
          <div className="flex flex-col sm:flex-row items-center justify-between p-4 rounded-xl bg-slate-900/60 border border-slate-800 gap-4">
            <div>
              <div className="text-xs text-slate-400">TARGET DOMAIN EVALUATED</div>
              <div className="text-lg font-bold font-mono text-cyan-400">{decision.query.domain}</div>
              <div className="text-xs text-slate-500 mt-0.5">Client: {decision.query.client_ip} | Proto: {decision.query.protocol}</div>
            </div>
            
            <div className="text-right">
              <div className="text-xs text-slate-400 mb-1">COMPOSITE RISK SCORE</div>
              <div className={`text-3xl font-extrabold font-mono ${isBlock ? 'text-rose-400' : isSuspicious ? 'text-amber-400' : 'text-emerald-400'}`}>
                {decision.composite_risk_score.toFixed(1)} <span className="text-sm font-normal text-slate-500">/ 100</span>
              </div>
            </div>
          </div>

          {/* Rationale String */}
          <div className="p-3.5 rounded-lg bg-slate-800/60 border border-slate-700/80 text-xs text-slate-300">
            <span className="font-semibold text-cyan-300">Decision Rationale: </span>
            {decision.rationale}
          </div>

          {/* Granular Sub-Score Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            
            {/* Threat Intel Sub-Score */}
            <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800">
              <div className="flex items-center gap-2 mb-2">
                <Database className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-semibold text-slate-300">Threat Intel</span>
              </div>
              <div className="text-sm font-bold font-mono text-white mb-1">
                {decision.intel_result?.matched ? 'IOC MATCH' : 'CLEAN'}
              </div>
              <p className="text-[11px] text-slate-400">
                {decision.intel_result?.threat_category || 'No threat feed indicators match this domain.'}
              </p>
            </div>

            {/* AI/ML DGA Sub-Score */}
            <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800">
              <div className="flex items-center gap-2 mb-2">
                <Cpu className="w-4 h-4 text-purple-400" />
                <span className="text-xs font-semibold text-slate-300">ML DGA Model</span>
              </div>
              <div className="text-sm font-bold font-mono text-white mb-1">
                {((decision.ml_result?.dga_probability || 0) * 100).toFixed(1)}% <span className="text-xs font-normal text-slate-400">Prob</span>
              </div>
              <p className="text-[11px] text-slate-400">
                12-metric lexical feature analysis (entropy & n-grams).
              </p>
            </div>

            {/* DNS Tunneling Sub-Score */}
            <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800">
              <div className="flex items-center gap-2 mb-2">
                <Network className="w-4 h-4 text-amber-400" />
                <span className="text-xs font-semibold text-slate-300">DNS Tunneling</span>
              </div>
              <div className="text-sm font-bold font-mono text-white mb-1">
                {(decision.tunnel_result?.tunnel_score || 0).toFixed(1)} / 100
              </div>
              <p className="text-[11px] text-slate-400">
                60s sliding window tracker (entropy: {decision.tunnel_result?.entropy || 0}).
              </p>
            </div>
          </div>

        </div>

        {/* Footer */}
        <div className="px-6 py-3 bg-slate-900/80 border-t border-slate-800 flex justify-end">
          <button onClick={onClose} className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-300 transition-colors">
            Close Inspector
          </button>
        </div>

      </div>
    </div>
  );
};

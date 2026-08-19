import React from 'react';
import { X, ShieldAlert, Cpu, Network, Database } from 'lucide-react';
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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-lg">
      <div className="cyber-card w-full max-w-2xl overflow-hidden rounded-3xl border border-[#1F2933] shadow-2xl animate-in fade-in zoom-in duration-200">
        
        {/* Modal Header */}
        <div className="px-6 py-5 border-b border-[#1F2933] flex items-center justify-between bg-[#0B0F14]/90">
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-2xl border ${isBlock ? 'bg-[#EF4444]/10 border-[#EF4444]/30 text-[#EF4444]' : isSuspicious ? 'bg-[#F59E0B]/10 border-[#F59E0B]/30 text-[#F59E0B]' : 'bg-[#22C55E]/10 border-[#22C55E]/30 text-[#22C55E]'}`}>
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-base font-bold text-[#E6EDF3] font-mono tracking-tight">Domain Evidence Inspector</h3>
              <p className="text-xs text-[#8B98A5]">Explainable AI Telemetry & Security Rationale</p>
            </div>
          </div>
          <button 
            onClick={onClose} 
            className="p-2 rounded-xl text-[#8B98A5] hover:text-[#E6EDF3] hover:bg-[#1F2933] transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Content */}
        <div className="p-6 space-y-6">
          
          {/* Target Domain & Risk Gauge */}
          <div className="flex flex-col sm:flex-row items-center justify-between p-5 rounded-2xl bg-[#0B0F14] border border-[#1F2933] gap-4">
            <div>
              <div className="text-xs font-semibold text-[#8B98A5] font-mono uppercase tracking-wider">Target Domain Evaluated</div>
              <div className="text-xl font-extrabold font-mono text-[#00D4FF] mt-1">{decision.query.domain}</div>
              <div className="text-xs text-[#8B98A5] mt-1 font-mono">
                Client: {decision.query.client_ip} | Protocol: {decision.query.protocol}
              </div>
            </div>
            
            <div className="text-center sm:text-right">
              <div className="text-xs font-semibold text-[#8B98A5] font-mono uppercase tracking-wider mb-1">Composite Risk Score</div>
              <div className={`text-4xl font-black font-mono ${isBlock ? 'text-[#EF4444]' : isSuspicious ? 'text-[#F59E0B]' : 'text-[#22C55E]'}`}>
                {decision.composite_risk_score.toFixed(1)} <span className="text-sm font-normal text-[#8B98A5]">/ 100</span>
              </div>
            </div>
          </div>

          {/* Rationale Callout */}
          <div className="p-4 rounded-2xl bg-[#111820] border border-[#1F2933] text-xs text-[#E6EDF3]">
            <span className="font-bold text-[#00D4FF] font-mono">Security Decision Rationale: </span>
            <span className="text-[#E6EDF3] font-medium">{decision.rationale}</span>
          </div>

          {/* Sub-Score Breakdown Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            
            {/* Threat Intel Sub-Score */}
            <div className="p-4 rounded-2xl bg-[#0B0F14] border border-[#1F2933]">
              <div className="flex items-center gap-2 mb-2">
                <Database className="w-4 h-4 text-[#00D4FF]" />
                <span className="text-xs font-bold text-[#E6EDF3]">Threat Intel Feed</span>
              </div>
              <div className="text-sm font-extrabold font-mono text-white mb-1">
                {decision.intel_result?.matched ? 'IOC MATCH' : 'CLEAN'}
              </div>
              <p className="text-[11px] text-[#8B98A5]">
                {decision.intel_result?.threat_category || 'No malicious indicators match STIX/TAXII feeds.'}
              </p>
            </div>

            {/* AI/ML DGA Sub-Score */}
            <div className="p-4 rounded-2xl bg-[#0B0F14] border border-[#1F2933]">
              <div className="flex items-center gap-2 mb-2">
                <Cpu className="w-4 h-4 text-[#A855F7]" />
                <span className="text-xs font-bold text-[#E6EDF3]">AI/ML DGA Model</span>
              </div>
              <div className="text-sm font-extrabold font-mono text-white mb-1">
                {((decision.ml_result?.dga_probability || 0) * 100).toFixed(1)}% <span className="text-xs font-normal text-[#8B98A5]">Probability</span>
              </div>
              <p className="text-[11px] text-[#8B98A5]">
                Random Forest 12-metric lexical feature analysis (entropy & n-grams).
              </p>
            </div>

            {/* DNS Tunneling Sub-Score */}
            <div className="p-4 rounded-2xl bg-[#0B0F14] border border-[#1F2933]">
              <div className="flex items-center gap-2 mb-2">
                <Network className="w-4 h-4 text-[#F59E0B]" />
                <span className="text-xs font-bold text-[#E6EDF3]">DNS Tunneling</span>
              </div>
              <div className="text-sm font-extrabold font-mono text-white mb-1">
                {(decision.tunnel_result?.tunnel_score || 0).toFixed(1)} / 100
              </div>
              <p className="text-[11px] text-[#8B98A5]">
                60s sliding window tracker (entropy: {decision.tunnel_result?.entropy || 0}).
              </p>
            </div>
          </div>

        </div>

        {/* Modal Footer */}
        <div className="px-6 py-4 bg-[#0B0F14] border-t border-[#1F2933] flex justify-end">
          <button 
            onClick={onClose} 
            className="px-5 py-2 rounded-xl bg-[#1F2933] hover:bg-[#111820] text-xs font-semibold text-[#E6EDF3] transition-colors border border-[#1F2933]"
          >
            Close Inspector
          </button>
        </div>

      </div>
    </div>
  );
};

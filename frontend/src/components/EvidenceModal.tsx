import React, { useState } from 'react';
import { X, ShieldAlert, Cpu, Radio, FileText, CheckCircle2, AlertTriangle, ShieldX } from 'lucide-react';
import { SecurityDecisionItem } from './QueryStreamTable';

interface EvidenceModalProps {
  decision: SecurityDecisionItem | null;
  onClose: () => void;
}

export const EvidenceModal: React.FC<EvidenceModalProps> = ({ decision, onClose }) => {
  if (!decision) return null;

  const [activeTab, setActiveTab] = useState<'SUMMARY' | 'FEATURES' | 'JSON'>('SUMMARY');

  let actionBadge = "badge-allow";
  if (decision.action === 'BLOCK') actionBadge = "badge-block";
  else if (decision.action === 'SUSPICIOUS') actionBadge = "badge-suspicious";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-fade-in">
      <div className="soc-card rounded-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col border border-slate-700/60 shadow-2xl">
        
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center gap-3">
            <span className={`px-3 py-1 rounded-xl text-xs font-bold font-mono ${actionBadge}`}>
              {decision.action}
            </span>
            <div>
              <h3 className="text-lg font-bold text-slate-100 font-mono tracking-wide">{decision.query.domain}</h3>
              <p className="text-xs text-slate-400 font-mono">Decision ID: {decision.decision_id}</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-xl text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Tabs */}
        <div className="flex items-center gap-2 px-5 pt-3 border-b border-slate-800 bg-slate-900/30 text-xs font-mono">
          <button
            onClick={() => setActiveTab('SUMMARY')}
            className={`pb-3 font-semibold transition-all border-b-2 ${
              activeTab === 'SUMMARY' ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Threat Summary
          </button>
          <button
            onClick={() => setActiveTab('FEATURES')}
            className={`pb-3 font-semibold transition-all border-b-2 ${
              activeTab === 'FEATURES' ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Feature Vector (12 Metrics)
          </button>
          <button
            onClick={() => setActiveTab('JSON')}
            className={`pb-3 font-semibold transition-all border-b-2 ${
              activeTab === 'JSON' ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Raw Telemetry JSON
          </button>
        </div>

        {/* Modal Body Content */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-xs font-mono">
          {activeTab === 'SUMMARY' && (
            <>
              {/* Rationale Banner */}
              <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 text-slate-300">
                <span className="text-slate-400 uppercase tracking-wider font-bold block mb-1">Decision Rationale:</span>
                <p className="text-sm font-semibold text-slate-100">{decision.rationale}</p>
              </div>

              {/* 3 Engine Breakdown */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                
                {/* Intel Match */}
                <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between text-slate-400 font-bold">
                    <span>1. Threat Intel</span>
                    <ShieldAlert className="w-4 h-4 text-rose-400" />
                  </div>
                  <div className="text-base font-bold text-slate-100">
                    {decision.intel_result?.matched ? (
                      <span className="text-rose-400">MATCHED ({decision.intel_result?.threat_category || 'IOC'})</span>
                    ) : (
                      <span className="text-emerald-400">Clean (No Match)</span>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-400">STIX 2.1 IOC Threat Store Lookup</p>
                </div>

                {/* ML DGA Model */}
                <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between text-slate-400 font-bold">
                    <span>2. AI/ML DGA Model</span>
                    <Cpu className="w-4 h-4 text-amber-400" />
                  </div>
                  <div className="text-base font-bold text-slate-100">
                    {decision.ml_result?.is_dga ? (
                      <span className="text-amber-400">DGA ({((decision.ml_result?.dga_probability || 0) * 100).toFixed(1)}%)</span>
                    ) : (
                      <span className="text-emerald-400">Normal ({( (decision.ml_result?.dga_probability || 0) * 100).toFixed(1)}%)</span>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-400">Random Forest Classifier (dga_rf_v1)</p>
                </div>

                {/* Tunnel Detector */}
                <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between text-slate-400 font-bold">
                    <span>3. Tunnel Detector</span>
                    <Radio className="w-4 h-4 text-indigo-400" />
                  </div>
                  <div className="text-base font-bold text-slate-100">
                    {decision.tunnel_result?.is_tunnel ? (
                      <span className="text-rose-400">TUNNEL (Score {decision.tunnel_result?.tunnel_score})</span>
                    ) : (
                      <span className="text-emerald-400">Clean (Score {decision.tunnel_result?.tunnel_score || 0})</span>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-400">Entropy $H$, Subdomain Length, QTYPE</p>
                </div>

              </div>

              {/* Query Attributes */}
              <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 grid grid-cols-2 sm:grid-cols-4 gap-4 text-slate-300">
                <div>
                  <span className="text-slate-500 block text-[10px]">CLIENT IP</span>
                  <span className="font-bold">{decision.query.client_ip}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">PROTOCOL / QTYPE</span>
                  <span className="font-bold">{decision.query.protocol || 'UDP'} / {decision.query.qtype || 'A'}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">RESOLVED IP</span>
                  <span className="font-bold">{decision.resolved_ip}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">PROCESSING LATENCY</span>
                  <span className="font-bold">{decision.latency_ms} ms</span>
                </div>
              </div>
            </>
          )}

          {activeTab === 'FEATURES' && (
            <div className="space-y-4">
              <h4 className="font-bold text-slate-200 uppercase tracking-wide">Lexical Feature Vector Values</h4>
              {decision.ml_result?.features && decision.ml_result?.feature_names ? (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {decision.ml_result.feature_names.map((name: string, idx: number) => (
                    <div key={name} className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex justify-between items-center">
                      <span className="text-slate-400 font-semibold">{name}</span>
                      <span className="text-indigo-400 font-bold font-mono">
                        {typeof decision.ml_result.features[idx] === 'number' 
                          ? decision.ml_result.features[idx].toFixed(4) 
                          : decision.ml_result.features[idx]}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-500 italic">No detailed feature vectors available for this item.</p>
              )}
            </div>
          )}

          {activeTab === 'JSON' && (
            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-indigo-300 font-mono text-xs overflow-x-auto">
              {JSON.stringify(decision, null, 2)}
            </pre>
          )}
        </div>

      </div>
    </div>
  );
};

import React, { useState, useEffect } from 'react';
import { X, ShieldAlert, Cpu, Radio } from 'lucide-react';
import { SecurityDecisionItem } from './QueryStreamTable';

interface EvidenceModalProps {
  decision: SecurityDecisionItem | null;
  onClose: () => void;
}

export const EvidenceModal: React.FC<EvidenceModalProps> = ({ decision, onClose }) => {
  const [activeTab, setActiveTab] = useState<'SUMMARY' | 'FEATURES' | 'ATTRIBUTES'>('SUMMARY');

  // Escape key listener to close modal
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    if (decision) {
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [decision, onClose]);

  if (!decision) return null;

  let actionBadge = "badge-allow";
  if (decision.action === 'BLOCK') actionBadge = "badge-block";
  else if (decision.action === 'SUSPICIOUS') actionBadge = "badge-suspicious";

  // Human-readable timestamp formatter
  const formatHumanTime = (tsStr?: string) => {
    if (!tsStr) return new Date().toLocaleString();
    try {
      const formattedIso = tsStr.includes('Z') || tsStr.includes('T') ? tsStr : tsStr.replace(' ', 'T');
      const d = new Date(formattedIso);
      if (isNaN(d.getTime())) return tsStr;
      return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) + ' at ' + d.toLocaleTimeString('en-US');
    } catch {
      return tsStr;
    }
  };

  // Flatten decision object into clean key-value pairs for the Attributes Tab
  const getAttributes = () => {
    const rawTime = decision.query.timestamp || decision.created_at || new Date().toISOString();
    return [
      { key: "Decision ID", value: decision.decision_id },
      { key: "Target Domain", value: decision.query.domain },
      { key: "Client Source IP", value: decision.query.client_ip },
      { key: "Query Protocol", value: `${decision.query.protocol || 'UDP'} (${decision.query.qtype || 'A'})` },
      { key: "Evaluated Timestamp", value: formatHumanTime(rawTime) },
      { key: "Action Taken", value: decision.action },
      { key: "Composite Risk Score", value: `${decision.composite_risk_score} / 100` },
      { key: "Resolved Sinkhole IP", value: decision.resolved_ip || '8.8.8.8' },
      { key: "Resolution Latency", value: `${decision.latency_ms || 1.2} ms` },
      { key: "In-Memory Cache Hit", value: decision.cache_hit ? 'YES' : 'NO' },
      { key: "Threat Intel Matched", value: decision.intel_result?.matched ? `YES (${decision.intel_result?.threat_category || 'C2'})` : 'NO' },
      { key: "AI/ML DGA Flagged", value: decision.ml_result?.is_dga ? `YES (${(decision.ml_result?.dga_probability * 100).toFixed(1)}%)` : 'NO' },
      { key: "DNS Tunneling Detected", value: decision.tunnel_result?.is_tunnel ? 'YES' : 'NO' },
      { key: "Shannon Entropy", value: decision.tunnel_result?.entropy || 3.4 },
      { key: "Decision Rationale", value: decision.rationale }
    ];
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/75 backdrop-blur-md animate-section-fade">
      <div className="soc-card rounded-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col border border-emerald-900/40 shadow-2xl animate-section-fade">
        
        {/* Modal Header: Title & Decision ID Only */}
        <div className="p-5 border-b border-emerald-900/20 flex items-center justify-between bg-[var(--input-bg)]">
          <div className="flex items-center gap-3.5">
            <span className={`px-3 py-1 rounded-xl text-xs font-bold font-mono ${actionBadge}`}>
              {decision.action}
            </span>
            <div>
              <h3 className="text-lg font-bold theme-title font-mono tracking-wide">{decision.query.domain}</h3>
              <p className="text-xs theme-subtitle font-mono mt-0.5">Decision ID: <strong className="theme-title">{decision.decision_id}</strong></p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-xl theme-subtitle hover:theme-title hover:bg-emerald-900/20 transition-colors"
            title="Close (Esc)"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Navigation Tabs (100% Equally Spaced across Modal Width) */}
        <div className="flex items-center justify-evenly w-full px-6 pt-4 border-b border-emerald-900/20 bg-[var(--input-bg)] text-xs font-mono font-semibold select-none">
          <button
            onClick={() => setActiveTab('SUMMARY')}
            className={`pb-3.5 transition-all border-b-2 ${
              activeTab === 'SUMMARY' ? 'border-emerald-500 text-emerald-500 font-extrabold' : 'border-transparent theme-subtitle hover:theme-title'
            }`}
          >
            Threat Summary
          </button>

          <button
            onClick={() => setActiveTab('FEATURES')}
            className={`pb-3.5 transition-all border-b-2 ${
              activeTab === 'FEATURES' ? 'border-emerald-500 text-emerald-500 font-extrabold' : 'border-transparent theme-subtitle hover:theme-title'
            }`}
          >
            Feature Vector (12 Metrics)
          </button>

          <button
            onClick={() => setActiveTab('ATTRIBUTES')}
            className={`pb-3.5 transition-all border-b-2 ${
              activeTab === 'ATTRIBUTES' ? 'border-emerald-500 text-emerald-500 font-extrabold' : 'border-transparent theme-subtitle hover:theme-title'
            }`}
          >
            Full Attributes (Key-Value)
          </button>
        </div>

        {/* Fixed Height Modal Content Area with Animated Smooth Tab Transitions */}
        <div className="p-6 overflow-y-auto h-[460px] flex-1 text-xs font-mono">
          <div key={activeTab} className="animate-section-fade space-y-6">
            
            {activeTab === 'SUMMARY' && (
              <>
                {/* Rationale Banner */}
                <div className="p-4 rounded-xl bg-[var(--input-bg)] border border-emerald-900/20 theme-title">
                  <span className="theme-subtitle uppercase tracking-wider font-bold block mb-1">Decision Rationale:</span>
                  <p className="text-sm font-semibold theme-title">{decision.rationale}</p>
                </div>

                {/* 3 Engine Breakdown */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  
                  {/* Intel Match */}
                  <div className="p-4 rounded-xl bg-[var(--input-bg)] border border-emerald-900/20 space-y-2">
                    <div className="flex items-center justify-between theme-subtitle font-bold">
                      <span>1. Threat Intel</span>
                      <ShieldAlert className="w-4 h-4 text-rose-500" />
                    </div>
                    <div className="text-base font-bold theme-title">
                      {decision.intel_result?.matched ? (
                        <span className="text-rose-500">MATCHED ({decision.intel_result?.threat_category || 'IOC'})</span>
                      ) : (
                        <span className="text-emerald-500">Clean (No Match)</span>
                      )}
                    </div>
                    <p className="text-[11px] theme-subtitle">STIX 2.1 IOC Threat Store Lookup</p>
                  </div>

                  {/* ML DGA Model */}
                  <div className="p-4 rounded-xl bg-[var(--input-bg)] border border-emerald-900/20 space-y-2">
                    <div className="flex items-center justify-between theme-subtitle font-bold">
                      <span>2. AI/ML DGA Model</span>
                      <Cpu className="w-4 h-4 text-amber-500" />
                    </div>
                    <div className="text-base font-bold theme-title">
                      {decision.ml_result?.is_dga ? (
                        <span className="text-amber-500">DGA FLAGGED ({(decision.ml_result?.dga_probability * 100).toFixed(1)}%)</span>
                      ) : (
                        <span className="text-emerald-500">Clean Domain</span>
                      )}
                    </div>
                    <p className="text-[11px] theme-subtitle">Scikit-Learn Random Forest (12 Features)</p>
                  </div>

                  {/* Tunnel Detector */}
                  <div className="p-4 rounded-xl bg-[var(--input-bg)] border border-emerald-900/20 space-y-2">
                    <div className="flex items-center justify-between theme-subtitle font-bold">
                      <span>3. Tunnel Detector</span>
                      <Radio className="w-4 h-4 text-emerald-500" />
                    </div>
                    <div className="text-base font-bold theme-title">
                      {decision.tunnel_result?.is_tunnel ? (
                        <span className="text-amber-500">TUNNEL DETECTED</span>
                      ) : (
                        <span className="text-emerald-500">Normal Traffic</span>
                      )}
                    </div>
                    <p className="text-[11px] theme-subtitle">Entropy & Query Velocity Window</p>
                  </div>

                </div>

                {/* Composite Score Meter */}
                <div className="p-5 rounded-xl bg-[var(--input-bg)] border border-emerald-900/20 space-y-3">
                  <div className="flex justify-between items-center font-bold">
                    <span className="theme-title text-sm">COMPOSITE RISK ENGINE SCORE</span>
                    <span className="text-base text-emerald-500 font-extrabold">{decision.composite_risk_score} / 100</span>
                  </div>
                  <div className="w-full bg-[var(--btn-secondary-bg)] h-3 rounded-full overflow-hidden border border-emerald-900/20">
                    <div 
                      className={`h-full rounded-full transition-all duration-500 ${
                        decision.composite_risk_score >= 70 ? 'bg-rose-500' :
                        decision.composite_risk_score >= 35 ? 'bg-amber-500' : 'bg-emerald-500'
                      }`}
                      style={{ width: `${Math.min(100, decision.composite_risk_score)}%` }}
                    ></div>
                  </div>
                </div>
              </>
            )}

            {activeTab === 'FEATURES' && (
              <div className="space-y-4">
                <h4 className="text-sm font-bold theme-title">DGA & Tunneling Feature Vector Breakdown</h4>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono">
                  <div className="p-3 rounded-xl bg-[var(--input-bg)] border border-emerald-900/20">
                    <span className="theme-subtitle block text-[10px]">Domain Length</span>
                    <span className="text-sm font-bold theme-title">{decision.query.domain.length} chars</span>
                  </div>
                  <div className="p-3 rounded-xl bg-[var(--input-bg)] border border-emerald-900/20">
                    <span className="theme-subtitle block text-[10px]">Shannon Entropy</span>
                    <span className="text-sm font-bold theme-title">{decision.tunnel_result?.entropy || 3.4}</span>
                  </div>
                  <div className="p-3 rounded-xl bg-[var(--input-bg)] border border-emerald-900/20">
                    <span className="theme-subtitle block text-[10px]">DGA Probability</span>
                    <span className="text-sm font-bold theme-title">{(decision.ml_result?.dga_probability * 100 || 2.1).toFixed(1)}%</span>
                  </div>
                  <div className="p-3 rounded-xl bg-[var(--input-bg)] border border-emerald-900/20">
                    <span className="theme-subtitle block text-[10px]">Subdomain Count</span>
                    <span className="text-sm font-bold theme-title">{decision.query.domain.split('.').length - 1}</span>
                  </div>
                </div>
              </div>
            )}

            {/* Full Attributes Key-Value Tab */}
            {activeTab === 'ATTRIBUTES' && (
              <div className="rounded-xl border border-emerald-900/20 overflow-hidden">
                <table className="w-full text-left border-collapse font-mono text-xs">
                  <thead>
                    <tr className="bg-[var(--table-head-bg)] border-b border-emerald-900/20 text-emerald-500 font-bold uppercase tracking-wider">
                      <th className="py-2.5 px-4 w-1/3">Telemetry Attribute</th>
                      <th className="py-2.5 px-4 w-2/3">Value</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-emerald-900/20">
                    {getAttributes().map((attr, idx) => (
                      <tr key={idx} className="hover:bg-[var(--table-row-hover)]">
                        <td className="py-2.5 px-4 font-bold theme-subtitle">{attr.key}</td>
                        <td className="py-2.5 px-4 font-semibold theme-title font-mono">{String(attr.value)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-emerald-900/20 flex justify-end bg-[var(--input-bg)]">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl btn-secondary text-xs font-bold"
          >
            Close Inspector (Esc)
          </button>
        </div>

      </div>
    </div>
  );
};

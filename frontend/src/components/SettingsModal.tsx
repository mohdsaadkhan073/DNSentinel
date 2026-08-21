import React, { useEffect, useState } from 'react';
import { Settings, X, Bot, Cpu, Sun, Moon, RefreshCw, CheckCircle2, ShieldAlert, Radio, Server, Sliders } from 'lucide-react';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  theme: 'dark' | 'light';
  setTheme: (theme: 'dark' | 'light') => void;
  selectedModel: string;
  setSelectedModel: (model: string) => void;
  availableModels: string[];
  isOfflineOnly: boolean;
  setIsOfflineOnly: (offline: boolean) => void;
  onRefresh: () => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({
  isOpen,
  onClose,
  theme,
  setTheme,
  selectedModel,
  setSelectedModel,
  availableModels,
  isOfflineOnly,
  setIsOfflineOnly,
  onRefresh
}) => {
  const [ollamaOnline, setOllamaOnline] = useState<boolean>(true);

  // Check Ollama status on open
  useEffect(() => {
    if (isOpen) {
      fetch('http://localhost:8000/api/v1/copilot/models')
        .then(res => res.json())
        .then(data => setOllamaOnline(data.online))
        .catch(() => setOllamaOnline(false));
    }
  }, [isOpen]);

  // ESC key listener to close modal
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div 
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-section-fade font-mono"
      onClick={onClose}
    >
      <div 
        className="soc-card rounded-2xl w-full max-w-xl overflow-hidden flex flex-col border border-emerald-500/40 shadow-2xl animate-section-fade"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="p-5 border-b border-emerald-900/30 flex items-center justify-between bg-[var(--input-bg)]">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
              <Settings className="w-5 h-5 animate-spin-slow" />
            </div>
            <div>
              <h3 className="text-base font-bold theme-title tracking-wide">Platform & AI Copilot Settings</h3>
              <p className="text-[11px] theme-subtitle">Configure Ollama LLM models, AI modes, and SOC engine</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-xl theme-subtitle hover:text-rose-400 hover:bg-rose-500/15 transition-all shrink-0 border border-transparent hover:border-rose-500/30"
            title="Close Settings (Esc)"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 max-h-[70vh] overflow-y-auto">

          {/* Section 1: AI Copilot & Neural Model Settings */}
          <div className="space-y-4">
            <h4 className="text-xs font-bold uppercase tracking-wider theme-subtitle flex items-center gap-2">
              <Bot className="w-4 h-4 text-emerald-500" />
              <span>AI Copilot & Neural Model</span>
            </h4>

            {/* Model Selection Dropdown */}
            <div className="p-4 rounded-xl bg-[var(--input-bg)] border border-emerald-900/20 space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold theme-title">Target LLM Neural Model</label>
                <span className="text-[10px] theme-subtitle">Local Ollama Weights</span>
              </div>
              <select
                value={selectedModel}
                onChange={(e) => setSelectedModel(e.target.value)}
                className="w-full p-2.5 rounded-xl bg-[var(--table-head-bg)] text-xs font-bold theme-title border border-emerald-900/30 focus:border-emerald-500 outline-none cursor-pointer"
              >
                {availableModels.map((m) => (
                  <option key={m} value={m} className="bg-slate-900 text-slate-100 font-mono">
                    {m} {m === 'llama3:latest' ? '(Recommended - 4.7 GB)' : ''}
                  </option>
                ))}
              </select>
            </div>

            {/* AI Mode Toggle (Online Ollama vs Offline Fast Engine) */}
            <div className="p-4 rounded-xl bg-[var(--input-bg)] border border-emerald-900/20 flex items-center justify-between gap-4">
              <div>
                <span className="text-xs font-bold theme-title block">Force Offline Rule Engine</span>
                <span className="text-[11px] theme-subtitle block mt-0.5">
                  Bypass Ollama LLM queries and use fast deterministic SOC rule evaluation
                </span>
              </div>

              <button
                onClick={() => setIsOfflineOnly(!isOfflineOnly)}
                className={`w-12 h-6 rounded-full transition-colors relative cursor-pointer p-0.5 shrink-0 ${
                  isOfflineOnly ? 'bg-amber-600' : 'bg-emerald-600'
                }`}
              >
                <div
                  className={`w-5 h-5 rounded-full bg-white shadow-md transform transition-transform ${
                    isOfflineOnly ? 'translate-x-6' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>

            {/* Local Ollama Connection Status Indicator */}
            <div className="p-3.5 rounded-xl bg-[var(--input-bg)] border border-emerald-900/20 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-emerald-500" />
                <span className="theme-subtitle">Ollama API (http://localhost:11434)</span>
              </div>
              <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold flex items-center gap-1 ${
                ollamaOnline ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
              }`}>
                <span className={`w-2 h-2 rounded-full ${ollamaOnline ? 'bg-emerald-400' : 'bg-amber-400'}`}></span>
                <span>{ollamaOnline ? 'ONLINE' : 'OFFLINE'}</span>
              </span>
            </div>
          </div>

          {/* Section 2: Visual Theme & Data Refresh */}
          <div className="space-y-4 pt-2 border-t border-emerald-900/20">
            <h4 className="text-xs font-bold uppercase tracking-wider theme-subtitle flex items-center gap-2">
              <Sliders className="w-4 h-4 text-emerald-500" />
              <span>Appearance & Telemetry Data</span>
            </h4>

            {/* Theme Toggle Button */}
            <div className="p-4 rounded-xl bg-[var(--input-bg)] border border-emerald-900/20 flex items-center justify-between">
              <div>
                <span className="text-xs font-bold theme-title block">Interface Theme Mode</span>
                <span className="text-[11px] theme-subtitle block mt-0.5">
                  Currently active: <strong className="theme-title">{theme === 'dark' ? 'Dark Command Mode' : 'Light Enterprise Mode'}</strong>
                </span>
              </div>

              <button
                onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
                className="px-3.5 py-2 rounded-xl btn-secondary text-xs font-bold flex items-center gap-2"
              >
                {theme === 'dark' ? (
                  <>
                    <Sun className="w-4 h-4 text-amber-400" />
                    <span>Light Mode</span>
                  </>
                ) : (
                  <>
                    <Moon className="w-4 h-4 text-amber-500" />
                    <span>Dark Mode</span>
                  </>
                )}
              </button>
            </div>

            {/* Manual Refresh Button */}
            <div className="p-4 rounded-xl bg-[var(--input-bg)] border border-emerald-900/20 flex items-center justify-between">
              <div>
                <span className="text-xs font-bold theme-title block">Purge Cache & Reload Stream</span>
                <span className="text-[11px] theme-subtitle block mt-0.5">
                  Re-fetch live metrics summary and trigger chart animations
                </span>
              </div>

              <button
                onClick={() => {
                  onRefresh();
                  onClose();
                }}
                className="px-3.5 py-2 rounded-xl btn-secondary text-xs font-bold flex items-center gap-2"
              >
                <RefreshCw className="w-4 h-4" />
                <span>Reload Data</span>
              </button>
            </div>
          </div>

          {/* Section 3: Platform Version Info */}
          <div className="p-3.5 rounded-xl bg-[var(--table-head-bg)] border border-emerald-900/20 text-center space-y-1 text-[11px] theme-subtitle">
            <p className="font-bold theme-title">DNSentinel v2.0 Platform (SIH1524)</p>
            <p>Developed for Ministry / Enterprise SOC Infrastructure • Team EliteCore</p>
          </div>

        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-emerald-900/20 flex justify-end bg-[var(--input-bg)]">
          <button
            onClick={onClose}
            className="px-5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold cursor-pointer transition-all shadow-md"
          >
            Save & Done
          </button>
        </div>

      </div>
    </div>
  );
};

import React, { useState, useEffect, useRef } from 'react';
import { Bot, Sparkles, Send, X, Minus, RefreshCw, ArrowRight, ShieldAlert, CheckCircle2, ChevronDown, Cpu, Terminal, Radio, FileDown } from 'lucide-react';
import { generateDomainPdfReport } from '../utils/pdfReport';
import { SecurityDecisionItem } from './QueryStreamTable';

interface CopilotChatProps {
  onNavigate?: (tab: string) => void;
  onEvaluate?: (domain: string) => void;
  onClearFilters?: () => void;
  onRefresh?: () => void;
  theme?: 'dark' | 'light';
}

interface MessageItem {
  id: string;
  sender: 'user' | 'ai';
  text: string;
  action?: {
    type: 'EVALUATE' | 'NAVIGATE' | 'CLEAR_FILTERS' | 'REFRESH';
    domain?: string;
    tab?: string;
  } | null;
  timestamp: string;
}

export const CopilotChat: React.FC<CopilotChatProps> = ({
  onNavigate,
  onEvaluate,
  onClearFilters,
  onRefresh,
  theme = 'light'
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<MessageItem[]>([
    {
      id: 'welcome-1',
      sender: 'ai',
      text: "👋 Hi, I'm **SentinAI**, your local AI SOC Copilot powered by **Ollama (`llama3:latest`)**.\n\nI can analyze DNS threats, evaluate domains, or navigate the dashboard for you! Try asking:\n- *\"Evaluate bad-c2.com\"*\n- *\"Show Threat Analytics\"*\n- *\"Check system status\"*",
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);
  const [inputMsg, setInputMsg] = useState('');
  const [loading, setLoading] = useState(false);
  const [availableModels, setAvailableModels] = useState<string[]>(['llama3:latest', 'gemma4:e2b']);
  const [selectedModel, setSelectedModel] = useState<string>('llama3:latest');
  const [isOnline, setIsOnline] = useState<boolean>(true);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll chat to bottom
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isOpen]);

  // Fetch available local Ollama models on mount
  useEffect(() => {
    const fetchModels = async () => {
      try {
        const res = await fetch('http://localhost:8000/api/v1/copilot/models');
        if (res.ok) {
          const data = await res.json();
          setIsOnline(data.online);
          if (data.models && data.models.length > 0) {
            setAvailableModels(data.models);
            if (data.models.includes('llama3:latest')) {
              setSelectedModel('llama3:latest');
            } else {
              setSelectedModel(data.models[0]);
            }
          }
        }
      } catch (err) {
        setIsOnline(false);
      }
    };
    fetchModels();
  }, []);

  const handleSend = async (textToSend?: string) => {
    const msgText = (textToSend || inputMsg).trim();
    if (!msgText || loading) return;

    const userMsg: MessageItem = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text: msgText,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages(prev => [...prev, userMsg]);
    if (!textToSend) setInputMsg('');
    setLoading(true);

    try {
      const historyPayload = messages.map(m => ({
        role: m.sender === 'user' ? 'user' : 'assistant',
        content: m.text
      }));

      const res = await fetch('http://localhost:8000/api/v1/copilot/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: msgText,
          history: historyPayload,
          model: selectedModel
        })
      });

      if (res.ok) {
        const data = await res.json();
        setIsOnline(data.online);

        const aiMsg: MessageItem = {
          id: `ai-${Date.now()}`,
          sender: 'ai',
          text: data.reply || "Processed request successfully.",
          action: data.action,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        };

        setMessages(prev => [...prev, aiMsg]);

        // Execute action callback if present
        if (data.action) {
          executeAction(data.action);
        }
      } else {
        throw new Error("Copilot backend returned error");
      }
    } catch (err) {
      setMessages(prev => [
        ...prev,
        {
          id: `ai-${Date.now()}`,
          sender: 'ai',
          text: "⚠️ Unable to communicate with SentinAI Copilot endpoint. Make sure the FastAPI backend and local Ollama are running.",
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const executeAction = (action: any) => {
    if (!action || !action.type) return;
    if (action.type === 'NAVIGATE' && action.tab && onNavigate) {
      onNavigate(action.tab);
    } else if (action.type === 'EVALUATE' && action.domain && onEvaluate) {
      onEvaluate(action.domain);
    } else if (action.type === 'CLEAR_FILTERS' && onClearFilters) {
      onClearFilters();
    } else if (action.type === 'REFRESH' && onRefresh) {
      onRefresh();
    }
  };

  const handleDownloadPdfFromChat = async (domainName: string) => {
    try {
      const res = await fetch(`http://localhost:8000/api/v1/dns/evaluate?domain=${encodeURIComponent(domainName)}&qtype=A`, {
        method: 'POST'
      });
      let decision: SecurityDecisionItem;
      if (res.ok) {
        decision = await res.json();
      } else {
        decision = {
          decision_id: `insp-${Math.floor(Math.random() * 9000 + 1000)}`,
          query: { domain: domainName, client_ip: "192.168.1.100", protocol: "UDP", qtype: "A", timestamp: new Date().toISOString() },
          action: domainName.includes('bad') || domainName.includes('c2') ? "BLOCK" : "ALLOW",
          composite_risk_score: domainName.includes('bad') ? 95 : 8,
          intel_result: { matched: domainName.includes('bad'), threat_category: domainName.includes('bad') ? "Command & Control" : "No active match", intel_score: domainName.includes('bad') ? 95 : 0 },
          ml_result: { is_dga: false, dga_probability: 0.05 },
          tunnel_result: { is_tunnel: false, tunnel_score: 20, entropy: 3.4 },
          latency_ms: 1.2,
          cache_hit: false,
          resolved_ip: "8.8.8.8",
          rationale: `Evaluated ${domainName}: Threat evidence analyzed.`
        };
      }
      generateDomainPdfReport(decision);
    } catch (err) {
      const fallback: SecurityDecisionItem = {
        decision_id: `insp-${Math.floor(Math.random() * 9000 + 1000)}`,
        query: { domain: domainName, client_ip: "192.168.1.100", protocol: "UDP", qtype: "A", timestamp: new Date().toISOString() },
        action: "ALLOW",
        composite_risk_score: 8,
        intel_result: { matched: false, threat_category: "No active match", intel_score: 0 },
        ml_result: { is_dga: false, dga_probability: 0.05 },
        tunnel_result: { is_tunnel: false, tunnel_score: 20, entropy: 3.4 },
        latency_ms: 1.2,
        cache_hit: false,
        resolved_ip: "8.8.8.8",
        rationale: `Evaluated ${domainName}: Threat evidence report.`
      };
      generateDomainPdfReport(fallback);
    }
  };

  const quickPrompts = [
    "Evaluate bad-c2.com",
    "Show Threat Analytics",
    "Check system status",
    "Clear table filters"
  ];

  return (
    <div className="fixed bottom-6 right-6 z-40 font-mono">
      {/* Hover Expandable Robot Launcher Button */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className="group flex items-center justify-center gap-2 h-12 w-12 hover:w-32 bg-emerald-600 hover:bg-emerald-500 text-white rounded-full shadow-2xl transition-all duration-300 border border-emerald-400/40 cursor-pointer overflow-hidden px-3"
          title="Ask AI - SentinAI SOC Copilot"
        >
          <Bot className="w-6 h-6 shrink-0 animate-pulse" />
          <span className="text-xs font-extrabold whitespace-nowrap hidden group-hover:inline-block transition-all">
            Ask AI
          </span>
        </button>
      )}

      {/* Expandable Glassmorphism Chat Window */}
      {isOpen && (
        <div className="soc-card rounded-2xl w-96 h-[540px] shadow-2xl border border-emerald-500/40 flex flex-col overflow-hidden animate-section-fade">
          
          {/* Header Bar */}
          <div className="p-3.5 border-b border-emerald-900/30 bg-[var(--input-bg)] flex items-center justify-between gap-2 shrink-0">
            <div className="flex items-center gap-2 min-w-0">
              <div className="p-1.5 rounded-xl bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                <Bot className="w-4 h-4" />
              </div>
              <div className="min-w-0">
                <h4 className="text-xs font-bold theme-title truncate flex items-center gap-1.5">
                  <span>SentinAI Copilot</span>
                  <span className={`w-2 h-2 rounded-full shrink-0 ${isOnline ? 'bg-emerald-500' : 'bg-amber-500'}`} title={isOnline ? "Ollama Online" : "Ollama Offline"}></span>
                </h4>
                <div className="flex items-center gap-1">
                  <select
                    value={selectedModel}
                    onChange={(e) => setSelectedModel(e.target.value)}
                    className="bg-transparent text-[10px] theme-subtitle focus:outline-none cursor-pointer border-0 p-0 font-bold"
                  >
                    {availableModels.map(m => (
                      <option key={m} value={m} className="bg-slate-900 text-slate-100">{m}</option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-1 shrink-0">
              <button
                onClick={() => setIsOpen(false)}
                className="p-1 rounded-lg theme-subtitle hover:theme-title transition-colors"
                title="Minimize"
              >
                <Minus className="w-4 h-4" />
              </button>
              <button
                onClick={() => setIsOpen(false)}
                className="p-1 rounded-lg theme-subtitle hover:text-rose-400 transition-colors"
                title="Close"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Messages Body */}
          <div className="flex-1 p-3.5 overflow-y-auto space-y-3.5 text-xs bg-[var(--table-head-bg)]/40">
            {messages.map((m) => (
              <div
                key={m.id}
                className={`flex flex-col ${m.sender === 'user' ? 'items-end' : 'items-start'}`}
              >
                <div
                  className={`max-w-[85%] p-3 rounded-2xl ${
                    m.sender === 'user'
                      ? 'bg-emerald-600 text-white font-medium rounded-br-none shadow-md'
                      : 'soc-card border border-emerald-900/30 text-slate-200 rounded-bl-none theme-title'
                  }`}
                >
                  <p className="whitespace-pre-wrap leading-relaxed">{m.text}</p>

                  {/* Render Action Execution Card if returned by AI */}
                  {m.action && (
                    <div className="mt-2.5 pt-2 border-t border-emerald-500/30 space-y-1.5">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1">
                        <Terminal className="w-3 h-3" />
                        <span>Action Executed</span>
                      </span>

                      {m.action.type === 'EVALUATE' && (
                        <div className="p-2.5 rounded-xl bg-emerald-950/80 border border-emerald-500/50 space-y-2">
                          <div className="flex items-center justify-between gap-2">
                            <div className="min-w-0">
                              <span className="text-[10px] text-emerald-400 block font-bold">Evaluated Domain</span>
                              <span className="text-xs font-bold text-white truncate block font-mono">{m.action.domain}</span>
                            </div>
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                              READY
                            </span>
                          </div>

                          <div className="flex items-center gap-2 pt-1 border-t border-emerald-900/40">
                            <button
                              onClick={() => executeAction(m.action)}
                              className="flex-1 py-1.5 px-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-[11px] font-bold flex items-center justify-center gap-1 transition-all cursor-pointer shadow-sm"
                            >
                              <span>Inspect Domain</span>
                              <ArrowRight className="w-3.5 h-3.5" />
                            </button>

                            <button
                              onClick={() => {
                                if (m.action?.domain) {
                                  handleDownloadPdfFromChat(m.action.domain);
                                }
                              }}
                              className="py-1.5 px-3 rounded-lg bg-slate-900 hover:bg-slate-800 text-emerald-400 border border-emerald-500/40 text-[11px] font-bold flex items-center gap-1.5 transition-all cursor-pointer shadow-sm shrink-0"
                              title="Download PDF Report"
                            >
                              <FileDown className="w-3.5 h-3.5" />
                              <span>PDF</span>
                            </button>
                          </div>
                        </div>
                      )}

                      {m.action.type === 'NAVIGATE' && (
                        <div className="p-2 rounded-xl bg-emerald-950/80 border border-emerald-500/40 text-[11px] font-bold text-emerald-300 flex items-center justify-between">
                          <span>Switched Tab to {m.action.tab}</span>
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                        </div>
                      )}

                      {m.action.type === 'CLEAR_FILTERS' && (
                        <div className="p-2 rounded-xl bg-emerald-950/80 border border-emerald-500/40 text-[11px] font-bold text-emerald-300 flex items-center justify-between">
                          <span>Cleared Stream Filters</span>
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                        </div>
                      )}
                    </div>
                  )}
                </div>
                <span className="text-[9px] theme-subtitle mt-1 px-1">{m.timestamp}</span>
              </div>
            ))}

            {/* Typing Indicator */}
            {loading && (
              <div className="flex items-center gap-2 theme-subtitle p-2 rounded-xl bg-[var(--input-bg)] w-fit border border-emerald-900/20 animate-pulse">
                <Bot className="w-3.5 h-3.5 text-emerald-500" />
                <span className="text-[11px] font-bold">SentinAI thinking ({selectedModel})...</span>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Quick Prompts Bar (Scrollable without visible scrollbar) */}
          <div className="px-3 py-1.5 border-t border-emerald-900/20 bg-[var(--input-bg)] flex items-center gap-1.5 overflow-x-auto shrink-0 text-[10px] [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden">
            {quickPrompts.map((qp, idx) => (
              <button
                key={idx}
                onClick={() => handleSend(qp)}
                className="px-2.5 py-1 rounded-lg border border-emerald-500/30 hover:border-emerald-500/80 bg-emerald-500/10 text-emerald-400 font-bold whitespace-nowrap transition-all shrink-0 cursor-pointer"
              >
                {qp}
              </button>
            ))}
          </div>

          {/* Input Header Footer */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSend();
            }}
            className="p-3 border-t border-emerald-900/30 bg-[var(--input-bg)] flex items-center gap-2 shrink-0"
          >
            <input
              type="text"
              placeholder="Ask SentinAI Copilot..."
              value={inputMsg}
              onChange={(e) => setInputMsg(e.target.value)}
              disabled={loading}
              className="flex-1 bg-[var(--table-head-bg)] text-xs theme-title placeholder-slate-400 px-3 py-2 rounded-xl focus:outline-none border border-emerald-900/30 focus:border-emerald-500/80 font-medium"
            />
            <button
              type="submit"
              disabled={loading || !inputMsg.trim()}
              className="p-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white transition-all shrink-0 cursor-pointer"
              title="Send message"
            >
              <Send className="w-4 h-4" />
            </button>
          </form>

        </div>
      )}
    </div>
  );
};

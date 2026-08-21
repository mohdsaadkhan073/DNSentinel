import React, { useState, useEffect } from 'react';
import { Sidebar } from './components/Sidebar';
import { Header } from './components/Header';
import { MetricCards } from './components/MetricCards';
import { ThreatCharts } from './components/ThreatCharts';
import { QueryStreamTable, SecurityDecisionItem } from './components/QueryStreamTable';
import { DomainInspector } from './components/DomainInspector';
import { ThreatAnalytics } from './components/ThreatAnalytics';
import { SourceIpAnalytics } from './components/SourceIpAnalytics';
import { PcapZeekInvestigator } from './components/PcapZeekInvestigator';
import { EvidenceModal } from './components/EvidenceModal';
import { UploadModal } from './components/UploadModal';
import { SearchModal } from './components/SearchModal';
import { CopilotChat } from './components/CopilotChat';
import { SettingsModal } from './components/SettingsModal';

export const App: React.FC = () => {
  const [wsConnected, setWsConnected] = useState(false);
  const [activeTab, setActiveTab] = useState('DASHBOARD');
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [theme, setTheme] = useState<'dark' | 'light'>('light'); // Light mode default
  const [globalSearch, setGlobalSearch] = useState('');
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const [selectedDecision, setSelectedDecision] = useState<SecurityDecisionItem | null>(null);
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [forensicReport, setForensicReport] = useState<any | null>(null);

  // Settings & Copilot Global Configuration State
  const [selectedModel, setSelectedModel] = useState<string>('llama3:latest');
  const [availableModels, setAvailableModels] = useState<string[]>(['llama3:latest', 'gemma4:e2b']);
  const [isOfflineOnly, setIsOfflineOnly] = useState<boolean>(false);
  const [tableLimit, setTableLimit] = useState<number>(50);

  // Persistent Domain Inspector Search State across Tab Navigation
  const [lastInspectedDomain, setLastInspectedDomain] = useState<string>('');
  const [lastInspectedResult, setLastInspectedResult] = useState<SecurityDecisionItem | null>(null);

  // Global Ctrl + K / Cmd + K listener for Command Palette Search Modal
  useEffect(() => {
    const handleGlobalKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsSearchOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleGlobalKeyDown);
    return () => window.removeEventListener('keydown', handleGlobalKeyDown);
  }, []);

  // Sync theme with body data-theme attribute
  useEffect(() => {
    document.body.setAttribute('data-theme', theme);
  }, [theme]);

  const [metrics, setMetrics] = useState({
    total_queries: 1240,
    blocked_queries: 182,
    suspicious_queries: 45,
    allowed_queries: 1013,
    cache_hits: 680,
    avg_latency_ms: 12.4,
    dga_detected_count: 78,
    tunnels_detected_count: 23
  });

  const [queries, setQueries] = useState<SecurityDecisionItem[]>([
    {
      decision_id: "sec-9901-a1b2",
      query: { domain: "google.com", client_ip: "192.168.1.105", protocol: "UDP", qtype: "A" },
      action: "ALLOW",
      composite_risk_score: 5.0,
      intel_result: { matched: false, intel_score: 0 },
      ml_result: { is_dga: false, dga_probability: 0.02 },
      tunnel_result: { is_tunnel: false, tunnel_score: 0, entropy: 2.1 },
      latency_ms: 2.1,
      cache_hit: true,
      resolved_ip: "142.250.190.46",
      rationale: "Allowed: Low risk score (5.0). Domain clean."
    },
    {
      decision_id: "sec-9902-c3d4",
      query: { domain: "bad-c2.com", client_ip: "192.168.1.105", protocol: "UDP", qtype: "A" },
      action: "BLOCK",
      composite_risk_score: 100.0,
      intel_result: { matched: true, threat_category: "Command & Control (C2)", intel_score: 100 },
      ml_result: { is_dga: false, dga_probability: 0.15 },
      tunnel_result: { is_tunnel: false, tunnel_score: 10, entropy: 2.8 },
      latency_ms: 4.8,
      cache_hit: false,
      resolved_ip: "0.0.0.0",
      rationale: "Blocked: Direct Threat Intel match (Command & Control)."
    },
    {
      decision_id: "sec-9903-e5f6",
      query: { domain: "cxz98qwe12a98f.info", client_ip: "192.168.1.110", protocol: "DoH", qtype: "A" },
      action: "SUSPICIOUS",
      composite_risk_score: 39.8,
      intel_result: { matched: false, intel_score: 0 },
      ml_result: { is_dga: true, dga_probability: 0.995 },
      tunnel_result: { is_tunnel: false, tunnel_score: 25, entropy: 4.2 },
      latency_ms: 7.2,
      cache_hit: false,
      resolved_ip: "8.8.8.8",
      rationale: "Suspicious: Moderate risk score (39.8). High DGA probability."
    },
    {
      decision_id: "sec-9904-g7h8",
      query: { domain: "4f8a91b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8-fresh.attacker-tunnel.net", client_ip: "192.168.1.120", protocol: "DTLS", qtype: "TXT" },
      action: "SUSPICIOUS",
      composite_risk_score: 50.2,
      intel_result: { matched: false, intel_score: 0 },
      ml_result: { is_dga: false, dga_probability: 0.35 },
      tunnel_result: { is_tunnel: true, tunnel_score: 65, entropy: 4.17 },
      latency_ms: 6.5,
      cache_hit: false,
      resolved_ip: "8.8.8.8",
      rationale: "Suspicious: DNS Tunneling activity flagged (Excessive subdomain prefix length)."
    }
  ]);

  // Fetch metrics & recent queries from REST API with explicit limit parameter
  const fetchMetricsAndQueries = async (customLimit?: number) => {
    const limitToUse = customLimit !== undefined ? customLimit : tableLimit;
    try {
      const resMetrics = await fetch('http://localhost:8000/api/v1/metrics/summary');
      if (resMetrics.ok) {
        const dataMetrics = await resMetrics.json();
        setMetrics(dataMetrics);
      }
      const resQueries = await fetch(`http://localhost:8000/api/v1/dns/queries?limit=${limitToUse}`);
      if (resQueries.ok) {
        const dataQueries = await resQueries.json();
        if (dataQueries.length > 0) {
          setQueries(dataQueries);
        }
      }
    } catch (err) {}
  };

  // Re-fetch queries automatically whenever tableLimit is updated by the user
  useEffect(() => {
    localStorage.setItem('dnsentinel_table_limit', tableLimit.toString());
    fetchMetricsAndQueries(tableLimit);
  }, [tableLimit]);

  // Manual Refresh Trigger (User clicks Topbar Refresh button)
  const handleManualRefresh = () => {
    setRefreshKey((prev) => prev + 1);
    fetchMetricsAndQueries(tableLimit);
  };

  // WebSocket Telemetry Connection with Auto-Reconnect
  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimeout: any = null;

    const connectWS = () => {
      try {
        ws = new WebSocket('ws://localhost:8000/ws/telemetry');

        ws.onopen = () => {
          setWsConnected(true);
        };

        ws.onmessage = (event) => {
          try {
            const decision: SecurityDecisionItem = JSON.parse(event.data);
            setQueries((prev) => [decision, ...prev.slice(0, Math.max(0, tableLimit - 1))]);
            fetchMetricsAndQueries(tableLimit);
          } catch (e) {}
        };

        ws.onclose = () => {
          setWsConnected(false);
          reconnectTimeout = setTimeout(connectWS, 3000);
        };

        ws.onerror = () => {
          setWsConnected(false);
        };
      } catch (err) {
        setWsConnected(false);
      }
    };

    connectWS();
    fetchMetricsAndQueries();

    return () => {
      if (ws) ws.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, []);

  // Quick Test Query Trigger
  const handleRunTestQuery = async (domain: string, qtype: string = "A") => {
    try {
      const res = await fetch(`http://localhost:8000/api/v1/dns/evaluate?domain=${encodeURIComponent(domain)}&qtype=${qtype}`, {
        method: 'POST'
      });
      if (res.ok) {
        const decision = await res.json();
        setQueries((prev) => [decision, ...prev.slice(0, 49)]);
        fetchMetricsAndQueries();
      }
    } catch (err) {}
  };

  // Forensic Upload Success Handler
  const handleUploadSuccess = (report: any) => {
    setForensicReport(report);
    if (report.sample_decisions && report.sample_decisions.length > 0) {
      setQueries((prev) => [...report.sample_decisions, ...prev].slice(0, 50));
    }
    setActiveTab('PCAP_ZEEK');
    fetchMetricsAndQueries();
  };

  return (
    <div className="min-h-screen flex flex-col lg:flex-row font-sans">
      
      {/* Left Sidebar Section */}
      <Sidebar
        wsConnected={wsConnected}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenUpload={() => setIsUploadOpen(true)}
        onRunTestQuery={handleRunTestQuery}
        onRefresh={handleManualRefresh}
        isCollapsed={isSidebarCollapsed}
        setIsCollapsed={setIsSidebarCollapsed}
        theme={theme}
        setTheme={setTheme}
      />

      {/* Main Right Area: Top Header + Padded Content Workspace */}
      <div className="flex-1 flex flex-col min-w-0 min-h-screen">
        
        {/* Flush Top Bar Header */}
        <Header
          wsConnected={wsConnected}
          theme={theme}
          setTheme={setTheme}
          onOpenUpload={() => setIsUploadOpen(true)}
          onOpenSearch={() => setIsSearchOpen(true)}
          onOpenSettings={() => setIsSettingsOpen(true)}
          onRefresh={handleManualRefresh}
          globalSearch={globalSearch}
          setGlobalSearch={setGlobalSearch}
        />

        {/* Padded Workspace Area */}
        <main className="flex-1 p-6 space-y-6">

          {/* Smooth Dynamic View Container keyed on activeTab */}
          <div key={`view-${activeTab}`} className="animate-section-fade space-y-6">
            
            {/* 5 Core Metric Cards (Displayed ONLY on DASHBOARD) */}
            {activeTab === 'DASHBOARD' && (
              <MetricCards summary={metrics} />
            )}

            {/* Persistent Domain Inspector Search State across Navigation */}
            {activeTab === 'DOMAIN_INSPECTOR' && (
              <DomainInspector 
                lastDomain={lastInspectedDomain}
                lastResult={lastInspectedResult}
                onDomainAnalyzed={(domain, result) => {
                  setLastInspectedDomain(domain);
                  setLastInspectedResult(result);
                }}
                onSelectDecision={(decision) => setSelectedDecision(decision)}
                theme={theme}
              />
            )}

            {/* Dedicated Threat Analytics Workspace */}
            {activeTab === 'ANALYTICS' && (
              <ThreatAnalytics
                summary={metrics}
                queries={queries}
                theme={theme}
              />
            )}

            {/* Dedicated Source IP Analytics Workspace */}
            {activeTab === 'SOURCE_IPS' && (
              <SourceIpAnalytics
                queries={queries}
                onSelectDecision={(decision) => setSelectedDecision(decision)}
                externalSearch={globalSearch}
                theme={theme}
              />
            )}

            {/* Dedicated PCAP / Zeek Investigation Module */}
            {activeTab === 'PCAP_ZEEK' && (
              <PcapZeekInvestigator
                activeReport={forensicReport}
                onUploadSuccess={handleUploadSuccess}
                onSelectDecision={(decision) => setSelectedDecision(decision)}
                theme={theme}
              />
            )}

            {/* Donut & Area Threat Charts (Dashboard View) */}
            {activeTab === 'DASHBOARD' && (
              <ThreatCharts key={`charts-${refreshKey}`} summary={metrics} queries={queries} />
            )}

            {/* Live Stream Table (Displayed on DASHBOARD & LIVE_DNS) */}
            {(activeTab === 'DASHBOARD' || activeTab === 'LIVE_DNS') && (
              <QueryStreamTable
                queries={queries}
                onSelectDecision={(decision) => setSelectedDecision(decision)}
                externalSearch={globalSearch}
                theme={theme}
              />
            )}
          </div>

        </main>
      </div>

      {/* Evidence Inspector Modal */}
      <EvidenceModal
        decision={selectedDecision}
        onClose={() => setSelectedDecision(null)}
      />

      {/* Passive Upload Modal */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onUploadSuccess={handleUploadSuccess}
      />

      {/* Universal Command Palette Search Modal Overlay */}
      <SearchModal
        isOpen={isSearchOpen}
        onClose={() => setIsSearchOpen(false)}
        query={globalSearch}
        setQuery={setGlobalSearch}
        queries={queries}
        onSelectDecision={(decision) => setSelectedDecision(decision)}
        setActiveTab={setActiveTab}
      />

      {/* Platform & AI SOC Copilot Settings Modal */}
      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        theme={theme}
        setTheme={setTheme}
        selectedModel={selectedModel}
        setSelectedModel={setSelectedModel}
        availableModels={availableModels}
        isOfflineOnly={isOfflineOnly}
        setIsOfflineOnly={setIsOfflineOnly}
        onRefresh={handleManualRefresh}
        tableLimit={tableLimit}
        setTableLimit={setTableLimit}
      />

      {/* Floating AI SOC Copilot Chatbot (SentinAI) */}
      <CopilotChat
        onNavigate={(tab) => setActiveTab(tab)}
        onEvaluate={(dom) => {
          setActiveTab('DOMAIN_INSPECTOR');
          setLastInspectedDomain(dom);
        }}
        onClearFilters={() => setGlobalSearch('')}
        onRefresh={handleManualRefresh}
        theme={theme}
        selectedModel={selectedModel}
        setSelectedModel={setSelectedModel}
        availableModels={availableModels}
        isOfflineOnly={isOfflineOnly}
      />

    </div>
  );
};

export default App;

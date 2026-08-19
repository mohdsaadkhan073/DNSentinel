import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { MetricCards } from './components/MetricCards';
import { QueryStreamTable, SecurityDecisionItem } from './components/QueryStreamTable';
import { EvidenceModal } from './components/EvidenceModal';
import { UploadModal } from './components/UploadModal';

export const App: React.FC = () => {
  const [wsConnected, setWsConnected] = useState(false);
  const [selectedDecision, setSelectedDecision] = useState<SecurityDecisionItem | null>(null);
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [forensicReport, setForensicReport] = useState<any | null>(null);

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
      query: { domain: "cxz98qwe12a.info", client_ip: "192.168.1.110", protocol: "DoH", qtype: "A" },
      action: "BLOCK",
      composite_risk_score: 84.0,
      intel_result: { matched: false, intel_score: 0 },
      ml_result: { is_dga: true, dga_probability: 0.92 },
      tunnel_result: { is_tunnel: false, tunnel_score: 25, entropy: 4.2 },
      latency_ms: 7.2,
      cache_hit: false,
      resolved_ip: "0.0.0.0",
      rationale: "Blocked: High composite risk score (84.0 >= 70.0). High DGA probability."
    },
    {
      decision_id: "sec-9904-g7h8",
      query: { domain: "a1b2c3d4e5f6g7h8i9j0.tunnel-server.net", client_ip: "192.168.1.120", protocol: "DTLS", qtype: "TXT" },
      action: "SUSPICIOUS",
      composite_risk_score: 62.5,
      intel_result: { matched: false, intel_score: 0 },
      ml_result: { is_dga: false, dga_probability: 0.35 },
      tunnel_result: { is_tunnel: true, tunnel_score: 75, entropy: 4.8 },
      latency_ms: 6.5,
      cache_hit: false,
      resolved_ip: "192.168.1.120",
      rationale: "Suspicious: High DNS Tunneling score (75.0). Flagged for monitoring."
    }
  ]);

  // Fetch metrics & queries from REST API
  const refreshData = async () => {
    try {
      const resMetrics = await fetch('http://localhost:8000/api/v1/metrics/summary');
      if (resMetrics.ok) {
        const dataMetrics = await resMetrics.json();
        setMetrics(dataMetrics);
      }
      const resQueries = await fetch('http://localhost:8000/api/v1/dns/queries');
      if (resQueries.ok) {
        const dataQueries = await resQueries.json();
        if (dataQueries.length > 0) {
          setQueries(dataQueries);
        }
      }
    } catch (err) {}
  };

  // WebSocket Telemetry Connection with Auto-Reconnect
  useEffect(() => {
    let ws: WebSocket | null = null;
    let timer: any = null;

    const connectWS = () => {
      try {
        ws = new WebSocket('ws://localhost:8000/ws/telemetry');
        ws.onopen = () => {
          setWsConnected(true);
        };
        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.decision_id) {
              setQueries((prev) => [data, ...prev.slice(0, 49)]);
              setMetrics((prev) => ({
                ...prev,
                total_queries: prev.total_queries + 1,
                blocked_queries: data.action === 'BLOCK' ? prev.blocked_queries + 1 : prev.blocked_queries,
                suspicious_queries: data.action === 'SUSPICIOUS' ? prev.suspicious_queries + 1 : prev.suspicious_queries,
                allowed_queries: data.action === 'ALLOW' ? prev.allowed_queries + 1 : prev.allowed_queries
              }));
            }
          } catch (err) {}
        };
        ws.onclose = () => {
          setWsConnected(false);
          timer = setTimeout(connectWS, 3000);
        };
        ws.onerror = () => {
          setWsConnected(false);
          ws?.close();
        };
      } catch (err) {
        setWsConnected(false);
        timer = setTimeout(connectWS, 3000);
      }
    };

    connectWS();
    refreshData();

    return () => {
      if (timer) clearTimeout(timer);
      if (ws) ws.close();
    };
  }, []);

  const runTestQuery = async (domain: string) => {
    try {
      const res = await fetch(`http://localhost:8000/api/v1/dns/evaluate?domain=${encodeURIComponent(domain)}`, {
        method: 'POST'
      });
      if (res.ok) {
        const decision = await res.json();
        setQueries((prev) => [decision, ...prev.slice(0, 49)]);
        setSelectedDecision(decision);
      }
    } catch (err) {
      alert(`Backend API offline. Make sure 'python -m backend.main' is running.`);
    }
  };

  return (
    <div className="min-h-screen bg-[#0B0F14] text-[#E6EDF3] flex flex-col p-4 md:p-6">
      <div className="max-w-7xl mx-auto w-full space-y-6">
        
        {/* Modern Cyber Header */}
        <Header 
          wsConnected={wsConnected}
          onOpenUpload={() => setIsUploadOpen(true)}
          onRunTestQuery={runTestQuery}
          onRefresh={refreshData}
        />

        {/* Metric Stat Cards */}
        <MetricCards summary={metrics} />

        {/* Forensic Report Alert (If PCAP / Zeek uploaded) */}
        {forensicReport && (
          <div className="cyber-card p-4 rounded-2xl border-l-4 border-l-[#00D4FF] flex items-center justify-between text-xs font-mono">
            <div>
              <span className="font-bold text-[#00D4FF]">Forensic Packet Analysis Complete: </span>
              Analyzed {forensicReport.total_queries_analyzed} queries from <span className="text-white font-bold">{forensicReport.filename}</span> ({forensicReport.blocked} Blocked, {forensicReport.suspicious} Suspicious, {forensicReport.allowed} Allowed).
            </div>
            <button onClick={() => setForensicReport(null)} className="text-[#8B98A5] hover:text-[#E6EDF3]">Dismiss</button>
          </div>
        )}

        {/* Real-time Query Stream Table */}
        <QueryStreamTable 
          queries={queries}
          onSelectDecision={(item) => setSelectedDecision(item)}
        />

      </div>

      {/* Domain Evidence Inspector Modal */}
      <EvidenceModal 
        decision={selectedDecision}
        onClose={() => setSelectedDecision(null)}
      />

      {/* PCAP / Zeek Upload Modal */}
      <UploadModal 
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onUploadSuccess={(report) => setForensicReport(report)}
      />
    </div>
  );
};

export default App;

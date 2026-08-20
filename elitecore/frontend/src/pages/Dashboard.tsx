import { useEffect, useMemo, useRef, useState } from "react";
import { getSummary, getDnsQueries, getIntelStats, getQueryDetail } from "../services/api";
import { useTelemetry } from "../hooks/useTelemetry";
import { useTheme } from "../hooks/useTheme";
import type { MetricsSummary, DNSQuerySummary, IntelStats, SecurityDecision } from "../types/security";

import SystemStatus from "../components/SystemStatus";
import MetricCard from "../components/MetricCard";
import QueryTable from "../components/QueryTable";
import EvidenceModal from "../components/EvidenceModal";
import UploadModal from "../components/UploadModal";
import DecisionDistributionChart from "../components/DecisionDistributionChart";
import RiskTrendChart from "../components/RiskTrendChart";
import ThreatCategoriesChart from "../components/ThreatCategoriesChart";
import IncidentsPanel from "../components/IncidentsPanel";
import TopBlockedWidget from "../components/TopBlockedWidget";
import ToastStack, { type ToastItem } from "../components/ToastStack";
import {
  ShieldIcon,
  ListIcon,
  CheckShieldIcon,
  AlertTriangleIcon,
  BanIcon,
  BugIcon,
  UploadCloudIcon,
  SunIcon,
  MoonIcon,
} from "../components/icons";

const TOAST_LIFETIME_MS = 6000;

export default function Dashboard() {
  const { events, status } = useTelemetry();
  const { theme, toggle: toggleTheme } = useTheme();
  const [summary, setSummary] = useState<MetricsSummary | null>(null);
  const [initialRows, setInitialRows] = useState<DNSQuerySummary[]>([]);
  const [intel, setIntel] = useState<IntelStats | null>(null);

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedDecision, setSelectedDecision] = useState<SecurityDecision | null>(null);
  const [loadingEvidence, setLoadingEvidence] = useState(false);
  const [uploadOpen, setUploadOpen] = useState(false);

  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const toastedIds = useRef<Set<string>>(new Set());

  const refresh = async () => {
    const [s, q, i] = await Promise.all([getSummary(), getDnsQueries({ limit: 50 }), getIntelStats()]);
    setSummary(s);
    setInitialRows(q.items);
    setIntel(i);
  };

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (status === "RECONNECTING") {
      const t = setTimeout(refresh, 500);
      return () => clearTimeout(t);
    }
  }, [status]);

  useEffect(() => {
    const latest = events[0];
    if (!latest || latest.decision !== "BLOCK" || toastedIds.current.has(latest.id)) return;
    toastedIds.current.add(latest.id);
    setToasts((prev) => [...prev, { id: latest.id, domain: latest.domain, risk_score: latest.risk_score }]);
    const timer = setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== latest.id));
    }, TOAST_LIFETIME_MS);
    return () => clearTimeout(timer);
  }, [events]);

  const rows: DNSQuerySummary[] = useMemo(() => {
    const live = events.map((e) => ({
      id: e.id,
      timestamp: e.timestamp,
      domain: e.domain,
      client_ip: e.client_ip,
      risk_score: e.risk_score,
      decision: e.decision,
    }));
    const liveIds = new Set(live.map((r) => r.id));
    const merged = [...live, ...initialRows.filter((r) => !liveIds.has(r.id))];
    return merged.slice(0, 100);
  }, [events, initialRows]);

  const openEvidence = async (id: string) => {
    setSelectedId(id);
    const liveMatch = events.find((e) => e.id === id);
    if (liveMatch) {
      setSelectedDecision(liveMatch);
      return;
    }
    setLoadingEvidence(true);
    try {
      const detail = await getQueryDetail(id);
      setSelectedDecision(detail);
    } finally {
      setLoadingEvidence(false);
    }
  };

  const dismissToast = (id: string) => setToasts((prev) => prev.filter((t) => t.id !== id));
  const openFromToast = (id: string) => {
    dismissToast(id);
    openEvidence(id);
  };

  const closeEvidence = () => {
    setSelectedId(null);
    setSelectedDecision(null);
  };

  return (
    <div className="dashboard">
      <header className="dashboard__header">
        <div className="dashboard__brand">
          <ShieldIcon className="dashboard__brand-icon" />
          <div>
            <div className="dashboard__title">DNSentinel</div>
            <div className="dashboard__subtitle">DNS SECURITY OPERATIONS CENTER</div>
          </div>
        </div>
        <div className="dashboard__header-right">
          <SystemStatus status={status} />
          <button className="btn btn--icon" onClick={toggleTheme} aria-label="Toggle theme">
            {theme === "dark" ? <SunIcon /> : <MoonIcon />}
          </button>
          <button className="btn" onClick={() => setUploadOpen(true)}>
            <UploadCloudIcon />
            Upload PCAP
          </button>
        </div>
      </header>

      <section className="metric-grid">
        <MetricCard
          label="Total Queries"
          value={summary?.total_queries ?? "—"}
          sub={`avg risk ${summary?.average_risk_score ?? "—"}`}
          icon={<ListIcon />}
        />
        <MetricCard
          label="Allowed"
          value={summary?.allowed ?? "—"}
          sub={summary ? `${((summary.allowed / Math.max(summary.total_queries, 1)) * 100).toFixed(1)}%` : undefined}
          tone="positive"
          icon={<CheckShieldIcon />}
        />
        <MetricCard
          label="Suspicious"
          value={summary?.suspicious ?? "—"}
          sub={summary ? `${((summary.suspicious / Math.max(summary.total_queries, 1)) * 100).toFixed(1)}%` : undefined}
          tone="warning"
          icon={<AlertTriangleIcon />}
        />
        <MetricCard
          label="Blocked"
          value={summary?.blocked ?? "—"}
          sub={summary ? `${((summary.blocked / Math.max(summary.total_queries, 1)) * 100).toFixed(1)}%` : undefined}
          tone="danger"
          icon={<BanIcon />}
        />
        <MetricCard label="Threats" value={summary?.threats ?? "—"} sub="Detected Today" tone="danger" icon={<BugIcon />} />
      </section>

      <section className="dashboard__main">
        <div className="dashboard__col">
          <QueryTable onSelect={openEvidence} />
          <IncidentsPanel rows={rows} onSelect={openEvidence} />
        </div>

        <div className="dashboard__col">
          <DecisionDistributionChart summary={summary} />
          <RiskTrendChart events={events.length > 0 ? events : (initialRows as unknown as SecurityDecision[])} />
          <ThreatCategoriesChart intel={intel} />
          <TopBlockedWidget />
        </div>
      </section>

      {(selectedId || loadingEvidence) && (
        <EvidenceModal decision={selectedDecision} loading={loadingEvidence} onClose={closeEvidence} />
      )}
      {uploadOpen && <UploadModal onClose={() => setUploadOpen(false)} />}
      <ToastStack toasts={toasts} onDismiss={dismissToast} onOpen={openFromToast} />
    </div>
  );
}

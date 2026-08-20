import type {
  MetricsSummary,
  PaginatedDNSQueries,
  SecurityDecision,
  IntelStats,
  MLStats,
  PassiveUploadResult,
  Decision,
  TopBlockedResponse,
  TrendResponse,
} from "../types/security";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, init);
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API ${path} failed: ${res.status} ${body}`);
  }
  return res.json() as Promise<T>;
}

export function getSummary(): Promise<MetricsSummary> {
  return request<MetricsSummary>("/api/v1/metrics/summary");
}

export function getDnsQueries(params: {
  page?: number;
  limit?: number;
  decision?: Decision;
  search?: string;
} = {}): Promise<PaginatedDNSQueries> {
  const qs = new URLSearchParams();
  if (params.page) qs.set("page", String(params.page));
  if (params.limit) qs.set("limit", String(params.limit));
  if (params.decision) qs.set("decision", params.decision);
  if (params.search) qs.set("search", params.search);
  return request<PaginatedDNSQueries>(`/api/v1/dns/queries?${qs.toString()}`);
}

export function getQueryDetail(id: string): Promise<SecurityDecision> {
  return request<SecurityDecision>(`/api/v1/dns/queries/${id}`);
}

export function getIntelStats(): Promise<IntelStats> {
  return request<IntelStats>("/api/v1/intel/stats");
}

export function getMlStats(): Promise<MLStats> {
  return request<MLStats>("/api/v1/ml/stats");
}

export function getTopBlocked(limit = 5): Promise<TopBlockedResponse> {
  return request<TopBlockedResponse>(`/api/v1/dns/top-blocked?limit=${limit}`);
}

export function getTrend(granularity: "hour" | "day" = "hour"): Promise<TrendResponse> {
  return request<TrendResponse>(`/api/v1/metrics/trend?granularity=${granularity}`);
}

export async function uploadPcap(file: File): Promise<PassiveUploadResult> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${API_BASE}/api/v1/passive/upload-pcap`, {
    method: "POST",
    body: form,
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`Upload failed: ${res.status} ${body}`);
  }
  return res.json();
}

export const WS_URL = API_BASE.replace(/^http/, "ws") + "/ws/telemetry";

// Mirrors backend/schemas.py exactly. This is THE contract -- when Members 1-5
// ship real data, only the provider (services/api.ts, useTelemetry.ts) changes.

export type Decision = "ALLOW" | "SUSPICIOUS" | "BLOCK";

export interface ThreatIntelEvidence {
  matched: boolean;
  confidence: number;
  category: string;
}

export interface DGAEvidence {
  probability: number;
  classification: string;
}

export interface TunnelingEvidence {
  rate: number;
  detected: boolean;
}

export interface Evidence {
  threat_intel: ThreatIntelEvidence;
  dga: DGAEvidence;
  tunneling: TunnelingEvidence;
}

export interface SecurityDecision {
  id: string;
  timestamp: string;
  domain: string;
  client_ip: string;
  query_type: string;
  risk_score: number;
  decision: Decision;
  evidence: Evidence;
  rationale: string;
}

export interface DNSQuerySummary {
  id: string;
  timestamp: string;
  domain: string;
  client_ip: string;
  risk_score: number;
  decision: Decision;
}

export interface PaginatedDNSQueries {
  items: DNSQuerySummary[];
  page: number;
  limit: number;
  total: number;
}

export interface TopBlockedDomain {
  domain: string;
  count: number;
  avg_risk: number;
}

export interface TopBlockedResponse {
  items: TopBlockedDomain[];
}

export interface TrendPoint {
  bucket: string;
  avg_risk: number;
  allowed: number;
  suspicious: number;
  blocked: number;
}

export interface TrendResponse {
  granularity: "hour" | "day";
  points: TrendPoint[];
}

export interface MetricsSummary {
  total_queries: number;
  allowed: number;
  suspicious: number;
  blocked: number;
  threats: number;
  average_risk_score: number;
  cache_hit_rate: number;
  system_status: string;
}

export interface IntelStats {
  total_iocs: number;
  active_iocs: number;
  matches_today: number;
  categories: Record<string, number>;
}

export interface MLStats {
  model: string;
  accuracy: number;
  total_predictions: number;
  dga_detected: number;
  normal_domains: number;
}

export interface PassiveUploadResult {
  filename: string;
  status: string;
  total_packets: number;
  dns_queries: number;
  malicious_domains: number;
  suspicious_domains: number;
  dga_detected: number;
  tunneling_detected: number;
  blocked: number;
}

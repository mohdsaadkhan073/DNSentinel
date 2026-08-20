import { useEffect, useState } from "react";
import type { Decision, DNSQuerySummary } from "../types/security";
import { getDnsQueries } from "../services/api";
import StatusBadge from "./StatusBadge";
import { SearchIcon, DownloadIcon, ChevronLeftIcon, ChevronRightIcon, CloseIcon } from "./icons";

const PAGE_SIZE = 15;
const REFRESH_MS = 5000;
const DECISIONS: Decision[] = ["ALLOW", "SUSPICIOUS", "BLOCK"];

function formatTime(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour12: false });
}

function riskColor(score: number): string {
  if (score <= 29) return "var(--green)";
  if (score <= 59) return "var(--amber)";
  if (score <= 79) return "var(--orange)";
  return "var(--red)";
}

function toCsv(rows: DNSQuerySummary[]): string {
  const header = "id,timestamp,domain,client_ip,risk_score,decision";
  const lines = rows.map((r) =>
    [r.id, r.timestamp, r.domain, r.client_ip, r.risk_score, r.decision]
      .map((v) => `"${String(v).replace(/"/g, '""')}"`)
      .join(",")
  );
  return [header, ...lines].join("\n");
}

function downloadCsv(rows: DNSQuerySummary[]) {
  const csv = toCsv(rows);
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `dns-queries-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Windowed page list: 1 ... p-2 p-1 p p+1 p+2 ... last
function getPageList(current: number, total: number): (number | "...")[] {
  const delta = 2;
  const left = Math.max(2, current - delta);
  const right = Math.min(total - 1, current + delta);
  const pages: (number | "...")[] = [1];

  if (left > 2) pages.push("...");
  for (let i = left; i <= right; i++) pages.push(i);
  if (right < total - 1) pages.push("...");
  if (total > 1) pages.push(total);

  return pages;
}

interface QueryTableProps {
  onSelect: (id: string) => void;
}

export default function QueryTable({ onSelect }: QueryTableProps) {
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [decisionFilter, setDecisionFilter] = useState<Decision | null>(null);
  const [page, setPage] = useState(1);
  const [items, setItems] = useState<DNSQuerySummary[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setSearch(searchInput), 350);
    return () => clearTimeout(t);
  }, [searchInput]);

  useEffect(() => {
    setPage(1);
  }, [search, decisionFilter]);

  useEffect(() => {
    let cancelled = false;
    const load = (showSpinner: boolean) => {
      if (showSpinner) setLoading(true);
      getDnsQueries({ page, limit: PAGE_SIZE, decision: decisionFilter ?? undefined, search: search || undefined })
        .then((res) => {
          if (cancelled) return;
          setItems(res.items);
          setTotal(res.total);
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    };
    load(true);
    const interval = setInterval(() => load(false), REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [page, decisionFilter, search]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const pageList = getPageList(page, totalPages);

  const clearFilters = () => {
    setSearchInput("");
    setSearch("");
    setDecisionFilter(null);
    setPage(1);
  };

  return (
    <div className="panel query-table">
      <div className="query-table__header">
        <div className="panel__title">DNS Query Log</div>
        <div className="query-table__controls">
          <div className="query-table__search">
            <SearchIcon className="query-table__search-icon" />
            <input
              type="text"
              placeholder="Search domain..."
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
            />
            {searchInput && (
              <button className="query-table__search-clear" onClick={() => setSearchInput("")} aria-label="Clear search">
                <CloseIcon />
              </button>
            )}
          </div>
          <select
            className="query-table__select"
            value={decisionFilter ?? ""}
            onChange={(e) => setDecisionFilter((e.target.value || null) as Decision | null)}
          >
            <option value="">All decisions</option>
            {DECISIONS.map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </select>
          {(search || decisionFilter) && (
            <button className="btn btn--ghost" onClick={clearFilters}>
              Clear
            </button>
          )}
          <button className="btn btn--ghost" onClick={() => downloadCsv(items)} disabled={items.length === 0}>
            <DownloadIcon />
            Export CSV
          </button>
        </div>
      </div>

      <div className="query-table__scroll">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Domain</th>
              <th>Risk</th>
              <th>Decision</th>
            </tr>
          </thead>
          <tbody>
            {items.map((row) => (
              <tr key={row.id} onClick={() => onSelect(row.id)} className="query-table__row">
                <td className="query-table__time">{formatTime(row.timestamp)}</td>
                <td className="query-table__domain" title={row.domain}>
                  {row.domain}
                </td>
                <td>
                  <div className="query-table__risk">
                    <span className="query-table__risk-number">{row.risk_score}</span>
                    <span className="query-table__risk-bar">
                      <span
                        className="query-table__risk-fill"
                        style={{ width: `${row.risk_score}%`, background: riskColor(row.risk_score) }}
                      />
                    </span>
                  </div>
                </td>
                <td>
                  <StatusBadge decision={row.decision} />
                </td>
              </tr>
            ))}
            {items.length === 0 && !loading && (
              <tr>
                <td colSpan={4} className="query-table__empty">
                  No matching queries
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="query-table__pagination">
        <span className="query-table__pagination-info">
          {total.toLocaleString()} results &middot; page {page} of {totalPages}
        </span>
        <div className="query-table__pagination-buttons">
          <button
            className="btn btn--icon"
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1}
            aria-label="Previous page"
          >
            <ChevronLeftIcon />
          </button>
          {pageList.map((p, i) =>
            p === "..." ? (
              <span key={`ellipsis-${i}`} className="query-table__page-ellipsis">
                &hellip;
              </span>
            ) : (
              <button
                key={p}
                className={`query-table__page-btn ${p === page ? "is-active" : ""}`}
                onClick={() => setPage(p)}
              >
                {p}
              </button>
            )
          )}
          <button
            className="btn btn--icon"
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages}
            aria-label="Next page"
          >
            <ChevronRightIcon />
          </button>
        </div>
      </div>
    </div>
  );
}

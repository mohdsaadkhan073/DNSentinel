import { SecurityDecisionItem } from '../components/QueryStreamTable';

export const generateDomainPdfReport = (decision: SecurityDecisionItem) => {
  const domain = decision.query.domain;
  const decisionId = decision.decision_id || `sec-${Math.floor(Math.random() * 9000 + 1000)}`;
  
  let formattedTime = new Date().toLocaleString();
  try {
    const rawTime = decision.query.timestamp || decision.created_at;
    if (rawTime) {
      let isoStr = rawTime.includes('T') ? rawTime : rawTime.replace(' ', 'T');
      if (isoStr.includes('T') && !isoStr.endsWith('Z') && !isoStr.includes('+') && !isoStr.includes('-', 10)) {
        isoStr += 'Z';
      }
      const d = new Date(isoStr);
      if (!isNaN(d.getTime())) {
        formattedTime = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) + ' at ' + d.toLocaleTimeString('en-US');
      }
    }
  } catch {}

  const printWindow = window.open('', '_blank');
  if (!printWindow) return;

  const actionColor = decision.action === 'BLOCK' ? '#dc2626' : decision.action === 'SUSPICIOUS' ? '#d97706' : '#059669';
  const actionBg = decision.action === 'BLOCK' ? '#fee2e2' : decision.action === 'SUSPICIOUS' ? '#fef3c7' : '#d1fae5';
  const actionBorder = decision.action === 'BLOCK' ? '#fca5a5' : decision.action === 'SUSPICIOUS' ? '#fcd34d' : '#6ee7b7';

  const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>DNSentinel Executive Security Report - ${domain}</title>
      <meta charset="utf-8" />
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #0f172a; margin: 0; padding: 40px; background: #ffffff; line-height: 1.5; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 3px solid #10b981; padding-bottom: 20px; margin-bottom: 25px; }
        .logo { font-size: 24px; font-weight: 800; color: #047857; font-family: monospace; letter-spacing: 0.5px; }
        .sublogo { font-size: 12px; color: #64748b; margin-top: 4px; font-family: sans-serif; }
        .badge { display: inline-block; padding: 6px 16px; border-radius: 8px; font-weight: 800; font-size: 14px; text-transform: uppercase; background: ${actionBg}; color: ${actionColor}; border: 1px solid ${actionBorder}; }
        .domain-title { font-size: 26px; font-weight: 800; color: #0f172a; margin: 0 0 6px 0; font-family: monospace; word-break: break-all; }
        .meta-line { font-size: 13px; color: #64748b; margin-bottom: 25px; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 25px; }
        .card { border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px 20px; background: #f8fafc; }
        .card h3 { margin: 0; font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 700; }
        .metric { font-size: 28px; font-weight: 800; color: ${actionColor}; margin: 8px 0 4px 0; font-family: monospace; }
        .rationale-box { border: 1px solid #cbd5e1; border-left: 4px solid ${actionColor}; border-radius: 8px; padding: 16px; background: #f1f5f9; margin-bottom: 25px; }
        .rationale-box h3 { margin: 0 0 6px 0; font-size: 12px; color: #475569; text-transform: uppercase; letter-spacing: 0.5px; }
        .rationale-box p { margin: 0; font-size: 14px; font-weight: 600; color: #0f172a; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; font-family: monospace; }
        th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #e2e8f0; }
        th { background: #f1f5f9; color: #475569; font-weight: 700; text-transform: uppercase; font-size: 11px; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; text-align: center; font-family: monospace; }
        .btn-print { background: #10b981; color: white; border: none; padding: 10px 22px; border-radius: 10px; font-weight: bold; cursor: pointer; font-size: 13px; font-family: sans-serif; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .btn-print:hover { background: #059669; }
        @media print {
          body { padding: 0; }
          .no-print { display: none !important; }
        }
      </style>
    </head>
    <body>
      <div class="no-print" style="margin-bottom: 20px; text-align: right;">
        <button onclick="window.print()" class="btn-print">🖨️ Save as PDF / Print</button>
      </div>

      <div class="header">
        <div>
          <div class="logo">🛡️ DNSentinel v2.0</div>
          <div class="sublogo">Executive Threat Intelligence & Domain Investigation Report</div>
        </div>
        <div>
          <span class="badge">${decision.action}</span>
        </div>
      </div>

      <div>
        <div class="domain-title">${domain}</div>
        <div class="meta-line">Decision ID: <strong>${decisionId}</strong> &nbsp;•&nbsp; Timestamp: <strong>${formattedTime}</strong></div>
      </div>

      <div class="grid">
        <div class="card">
          <h3>Composite Threat Risk Score</h3>
          <div class="metric">${decision.composite_risk_score} / 100</div>
          <div style="font-size: 12px; color: #64748b;">Evaluated via Intel + ML + Entropy Engine</div>
        </div>
        <div class="card">
          <h3>Client Source IP & Latency</h3>
          <div class="metric" style="font-size: 22px; color: #0f172a;">${decision.query.client_ip}</div>
          <div style="font-size: 12px; color: #64748b;">Resolution Latency: ${decision.latency_ms || 1.2} ms</div>
        </div>
      </div>

      <div class="rationale-box">
        <h3>Threat Engine Rationale</h3>
        <p>${decision.rationale}</p>
      </div>

      <h3 style="font-size: 14px; text-transform: uppercase; color: #475569; margin-top: 30px;">Detection Engine Evidence Breakdown</h3>
      <table>
        <thead>
          <tr>
            <th>Security Subsystem</th>
            <th>Inspection Attribute</th>
            <th>Evaluated Value & Status</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>STIX 2.1 Threat Intel</strong></td>
            <td>Database IOC Match</td>
            <td>${decision.intel_result?.matched ? `FLAGGED (${decision.intel_result?.threat_category || 'C2'})` : 'CLEAN (No IOC Match)'}</td>
          </tr>
          <tr>
            <td><strong>Bi-LSTM AI/ML Classifier</strong></td>
            <td>Lexical DGA Probability</td>
            <td>${(decision.ml_result?.dga_probability * 100 || 0).toFixed(1)}% ${decision.ml_result?.is_dga ? '(DGA Flagged)' : '(Normal Lexical)'}</td>
          </tr>
          <tr>
            <td><strong>Tunneling Detector</strong></td>
            <td>Shannon Payload Entropy</td>
            <td>${decision.tunnel_result?.entropy || 3.4} H ${decision.tunnel_result?.is_tunnel ? '(High Entropy Subdomain Tunnel)' : '(Normal Payload)'}</td>
          </tr>
          <tr>
            <td><strong>Sinkhole DNS Resolver</strong></td>
            <td>Resolved IP Address</td>
            <td>${decision.resolved_ip || '8.8.8.8'}</td>
          </tr>
          <tr>
            <td><strong>In-Memory Cache</strong></td>
            <td>Cache Hit Status</td>
            <td>${decision.cache_hit ? 'YES (0ms SLA Cache Hit)' : 'NO (Engine Evaluated)'}</td>
          </tr>
        </tbody>
      </table>

      <div class="footer">
        <p>Confidential • SIH1524 DNSentinel Threat Filtering Platform • Team EliteCore</p>
      </div>

      <script>
        window.onload = function() {
          setTimeout(function() {
            window.print();
          }, 350);
        };
      </script>
    </body>
    </html>
  `;

  printWindow.document.write(htmlContent);
  printWindow.document.close();
};

/**
 * report-html.js
 * Generates a self-contained HTML security report from scan findings.
 * Targeted at two audiences: technical leads (full detail) and management (executive summary).
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ── OWASP Top 10 2021 mapping ──────────────────────────────────────────────

const OWASP_CATEGORIES = {
  'Broken Access Control (OWASP A01)':                          { id: 'A01', name: 'Broken Access Control' },
  'Cryptographic Failures (OWASP A02)':                         { id: 'A02', name: 'Cryptographic Failures' },
  'Injection (OWASP A03)':                                      { id: 'A03', name: 'Injection' },
  'Insecure Design (OWASP A04)':                                { id: 'A04', name: 'Insecure Design' },
  'Security Misconfiguration (OWASP A05)':                      { id: 'A05', name: 'Security Misconfiguration' },
  'Vulnerable and Outdated Components (OWASP A06)':             { id: 'A06', name: 'Vulnerable Components' },
  'Identification and Authentication Failures (OWASP A07)':     { id: 'A07', name: 'Auth Failures' },
  'Software and Data Integrity Failures (OWASP A08)':           { id: 'A08', name: 'Integrity Failures' },
  'Security Logging and Monitoring Failures (OWASP A09)':       { id: 'A09', name: 'Logging Failures' },
  'Server-Side Request Forgery (OWASP A10)':                    { id: 'A10', name: 'SSRF' },
};

// ── Risk scoring ───────────────────────────────────────────────────────────

const SEV_WEIGHT = { CRITICAL: 10, HIGH: 5, MEDIUM: 2, EXPOSURE: 1, INFO: 0 };
const SEV_COLOR  = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  EXPOSURE: '#3b82f6',
  INFO:     '#6b7280',
};
const SEV_BG = {
  CRITICAL: 'rgba(239,68,68,0.12)',
  HIGH:     'rgba(249,115,22,0.12)',
  MEDIUM:   'rgba(234,179,8,0.12)',
  EXPOSURE: 'rgba(59,130,246,0.12)',
  INFO:     'rgba(107,114,128,0.12)',
};

function computeRiskScore(findings) {
  if (!findings.length) return 0;
  const raw = findings.reduce((sum, f) => sum + (SEV_WEIGHT[f.severity] || 0), 0);
  // Normalize to 0-100, cap at 100
  return Math.min(100, Math.round(raw / Math.max(findings.length, 1) * 5));
}

function riskLabel(score) {
  if (score >= 80) return { label: 'CRITICAL RISK', color: '#ef4444' };
  if (score >= 55) return { label: 'HIGH RISK',     color: '#f97316' };
  if (score >= 30) return { label: 'MEDIUM RISK',   color: '#eab308' };
  if (score >= 10) return { label: 'LOW RISK',      color: '#22c55e' };
  return             { label: 'MINIMAL RISK',        color: '#6b7280' };
}

// ── Helpers ────────────────────────────────────────────────────────────────

function escHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function groupBy(arr, key) {
  return arr.reduce((acc, item) => {
    const k = item[key] || 'Unknown';
    (acc[k] = acc[k] || []).push(item);
    return acc;
  }, {});
}

function countBySeverity(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, EXPOSURE: 0, INFO: 0 };
  findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });
  return counts;
}

function getOwaspCoverage(findings) {
  const hit = new Set();
  findings.forEach(f => {
    const match = Object.entries(OWASP_CATEGORIES).find(([k]) => f.category && f.category.includes(k.split('(')[1]?.replace(')', '') || ''));
    if (match) hit.add(match[1].id);
    // Also match by category string directly
    Object.entries(OWASP_CATEGORIES).forEach(([cat, info]) => {
      if (f.category === cat) hit.add(info.id);
    });
  });
  return hit;
}

function formatDate(d) {
  return d.toLocaleDateString('en-GB', { year: 'numeric', month: 'long', day: 'numeric' });
}

function formatTime(d) {
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
}

// ── Remediation priority list ──────────────────────────────────────────────

function buildRemediationPlan(findings) {
  const groups = groupBy(findings.filter(f => !f.excepted && !f.resolved), 'ruleId');
  return Object.entries(groups)
    .map(([ruleId, items]) => ({
      ruleId,
      name: items[0].name,
      severity: items[0].severity,
      count: items.length,
      category: items[0].category || '',
      fix: items[0].fix || '',
      files: [...new Set(items.map(f => f.filePath))],
    }))
    .sort((a, b) => {
      const sw = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, EXPOSURE: 3, INFO: 4 };
      return (sw[a.severity] ?? 9) - (sw[b.severity] ?? 9) || b.count - a.count;
    });
}

// ── HTML sections ──────────────────────────────────────────────────────────

function renderGauge(score, risk) {
  const angle = (score / 100) * 180;
  const rad   = (angle - 90) * Math.PI / 180;
  const nx    = 100 + 70 * Math.cos(rad);
  const ny    = 100 + 70 * Math.sin(rad);

  return `
  <div class="gauge-wrap">
    <svg viewBox="0 0 200 110" class="gauge-svg">
      <!-- Track -->
      <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="#1e293b" stroke-width="18" stroke-linecap="round"/>
      <!-- Colored arc segments -->
      <path d="M 20 100 A 80 80 0 0 1 60 31"  fill="none" stroke="#22c55e" stroke-width="18" stroke-linecap="butt" opacity="0.5"/>
      <path d="M 60 31 A 80 80 0 0 1 100 20"  fill="none" stroke="#eab308" stroke-width="18" stroke-linecap="butt" opacity="0.5"/>
      <path d="M 100 20 A 80 80 0 0 1 150 35" fill="none" stroke="#f97316" stroke-width="18" stroke-linecap="butt" opacity="0.5"/>
      <path d="M 150 35 A 80 80 0 0 1 180 100" fill="none" stroke="#ef4444" stroke-width="18" stroke-linecap="round" opacity="0.5"/>
      <!-- Needle -->
      <line x1="100" y1="100" x2="${nx.toFixed(1)}" y2="${ny.toFixed(1)}"
            stroke="${risk.color}" stroke-width="3" stroke-linecap="round"/>
      <circle cx="100" cy="100" r="6" fill="${risk.color}"/>
      <!-- Score -->
      <text x="100" y="88" text-anchor="middle" font-size="22" font-weight="700"
            fill="${risk.color}" font-family="'JetBrains Mono', monospace">${score}</text>
    </svg>
    <div class="gauge-label" style="color:${risk.color}">${risk.label}</div>
  </div>`;
}

function renderSeverityBadge(sev) {
  return `<span class="badge" style="background:${SEV_BG[sev]};color:${SEV_COLOR[sev]};border-color:${SEV_COLOR[sev]}30">${sev}</span>`;
}

function renderOwaspGrid(hitCategories) {
  return Object.entries(OWASP_CATEGORIES).map(([, info]) => {
    const hit = hitCategories.has(info.id);
    return `
    <div class="owasp-cell ${hit ? 'owasp-hit' : 'owasp-miss'}">
      <span class="owasp-id">${info.id}</span>
      <span class="owasp-name">${info.name}</span>
      ${hit ? '<span class="owasp-dot">●</span>' : ''}
    </div>`;
  }).join('');
}

function renderRemediationTable(plan) {
  if (!plan.length) return '<p class="muted">No open findings requiring remediation.</p>';
  return `
  <table class="remed-table">
    <thead>
      <tr>
        <th>#</th>
        <th>Priority</th>
        <th>Rule</th>
        <th>Finding</th>
        <th>Occurrences</th>
        <th>OWASP</th>
        <th>Affected Files</th>
      </tr>
    </thead>
    <tbody>
      ${plan.slice(0, 20).map((item, i) => `
      <tr>
        <td class="mono muted">${i + 1}</td>
        <td>${renderSeverityBadge(item.severity)}</td>
        <td class="mono rule-id">${escHtml(item.ruleId)}</td>
        <td class="finding-name">${escHtml(item.name)}</td>
        <td class="count-cell">${item.count}</td>
        <td class="mono muted">${escHtml(item.category.match(/A\d+/)?.[0] || '—')}</td>
        <td class="file-list">${item.files.slice(0, 3).map(f => `<code>${escHtml(path.basename(f))}</code>`).join(' ') + (item.files.length > 3 ? ` <span class="muted">+${item.files.length - 3} more</span>` : '')}</td>
      </tr>
      `).join('')}
    </tbody>
  </table>`;
}

function renderFindingsDetail(findings, repoRoot = '') {
  const byFile = groupBy(findings, 'filePath');

  return Object.entries(byFile).sort(([a], [b]) => a.localeCompare(b)).map(([filePath, items]) => {
    const bySeverity = groupBy(items, 'severity');
    const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'EXPOSURE', 'INFO'];

    // Absolute path for vscode:// links
    const absPath  = repoRoot ? path.join(repoRoot, filePath) : filePath;
    const vsodeUrl = `vscode://file/${absPath}`;

    const findingRows = severities.flatMap(sev =>
      (bySeverity[sev] || []).map(f => {
        const vscodeLine = `vscode://file/${absPath}:${f.line}`;
        const clipData   = `${absPath}:${f.line}`;
        return `
      <div class="finding-row" data-sev="${f.severity}">
        <div class="finding-header">
          ${renderSeverityBadge(f.severity)}
          <span class="finding-title">${escHtml(f.name)}</span>
          <a class="file-link mono muted finding-meta"
             href="${escHtml(vscodeLine)}"
             data-clip="${escHtml(clipData)}"
             title="Open in VS Code (click) · Copy path (right-click)">Line ${f.line} · ${escHtml(f.ruleId)}</a>
          ${f.excepted ? '<span class="badge badge-excepted">EXCEPTED</span>' : ''}
          ${f.resolved ? '<span class="badge badge-resolved">RESOLVED</span>' : ''}
        </div>
        ${f.snippet ? `<pre class="code-snippet"><code>${escHtml(f.snippet)}</code></pre>` : ''}
        <div class="finding-detail">
          <div class="detail-row"><span class="detail-label">Why</span><span>${escHtml(f.why || '')}</span></div>
          <div class="detail-row"><span class="detail-label">Scenario</span><span>${escHtml(f.scenario || '')}</span></div>
          <div class="detail-row"><span class="detail-label">Fix</span><pre class="inline-fix">${escHtml(f.fix || '')}</pre></div>
        </div>
      </div>`;
      })
    );

    const critCount = (bySeverity['CRITICAL'] || []).length;
    const highCount = (bySeverity['HIGH'] || []).length;

    return `
    <div class="file-block">
      <div class="file-header">
        <span class="file-icon">📄</span>
        <a class="file-path mono file-link"
           href="${escHtml(vsodeUrl)}"
           data-clip="${escHtml(absPath)}"
           title="Open in VS Code · Right-click to copy path">${escHtml(filePath)}</a>
        <div class="file-counts">
          ${critCount ? `<span class="count-chip" style="color:${SEV_COLOR.CRITICAL}">${critCount} CRITICAL</span>` : ''}
          ${highCount ? `<span class="count-chip" style="color:${SEV_COLOR.HIGH}">${highCount} HIGH</span>` : ''}
          <span class="count-chip muted">${items.length} total</span>
        </div>
      </div>
      <div class="findings-list">
        ${findingRows.join('')}
      </div>
    </div>`;
  }).join('');
}

// ── CSS ────────────────────────────────────────────────────────────────────

function buildCSS() {
  return `
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@400;600;700;800&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg:       #0a0f1a;
    --surface:  #0f172a;
    --surface2: #1e293b;
    --border:   #1e293b;
    --text:     #e2e8f0;
    --muted:    #64748b;
    --accent:   #38bdf8;
    --crit:     #ef4444;
    --high:     #f97316;
    --med:      #eab308;
    --exp:      #3b82f6;
  }

  html { font-size: 15px; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Syne', sans-serif;
    line-height: 1.6;
    min-height: 100vh;
  }

  /* ── Layout ── */
  .page { max-width: 1200px; margin: 0 auto; padding: 0 2rem 4rem; }

  /* ── Header ── */
  .report-header {
    border-bottom: 1px solid var(--border);
    padding: 3rem 0 2rem;
    margin-bottom: 3rem;
    display: grid;
    grid-template-columns: 1fr auto;
    align-items: end;
    gap: 2rem;
  }
  .brand { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; }
  .brand-icon {
    width: 42px; height: 42px;
    background: var(--accent);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.4rem;
  }
  .brand-name {
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: var(--accent);
  }
  .report-title { font-size: 2.2rem; font-weight: 800; line-height: 1.2; }
  .report-target { font-family: 'JetBrains Mono', monospace; color: var(--muted); font-size: 0.85rem; margin-top: 0.5rem; }
  .report-meta { text-align: right; }
  .meta-date { font-size: 0.85rem; color: var(--muted); }
  .meta-date strong { color: var(--text); display: block; font-size: 1rem; }

  /* ── Section titles ── */
  .section { margin-bottom: 3rem; }
  .section-title {
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.25em;
    text-transform: uppercase;
    color: var(--accent);
    margin-bottom: 1.25rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }
  .section-title::after {
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border);
  }

  /* ── Executive summary grid ── */
  .exec-grid {
    display: grid;
    grid-template-columns: auto 1fr 1fr;
    gap: 1.5rem;
    align-items: start;
  }
  @media (max-width: 900px) { .exec-grid { grid-template-columns: 1fr; } }

  /* ── Gauge ── */
  .gauge-wrap { text-align: center; }
  .gauge-svg { width: 180px; }
  .gauge-label { font-weight: 700; font-size: 0.8rem; letter-spacing: 0.1em; text-transform: uppercase; margin-top: -0.5rem; }

  /* ── Severity breakdown ── */
  .sev-breakdown { display: flex; flex-direction: column; gap: 0.5rem; }
  .sev-row { display: flex; align-items: center; gap: 0.75rem; }
  .sev-bar-wrap { flex: 1; height: 6px; background: var(--surface2); border-radius: 3px; overflow: hidden; }
  .sev-bar { height: 100%; border-radius: 3px; transition: width 1s ease; }
  .sev-label { font-size: 0.75rem; font-weight: 600; letter-spacing: 0.08em; width: 70px; }
  .sev-count { font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; font-weight: 700; width: 30px; text-align: right; }

  /* ── OWASP grid ── */
  .owasp-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 0.5rem;
  }
  @media (max-width: 700px) { .owasp-grid { grid-template-columns: repeat(2, 1fr); } }
  .owasp-cell {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.6rem 0.75rem;
    position: relative;
    transition: border-color 0.2s;
  }
  .owasp-hit { border-color: var(--crit); background: rgba(239,68,68,0.05); }
  .owasp-id { font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; font-weight: 700; color: var(--muted); display: block; }
  .owasp-hit .owasp-id { color: var(--crit); }
  .owasp-name { font-size: 0.72rem; color: var(--text); display: block; margin-top: 0.15rem; line-height: 1.3; }
  .owasp-dot { position: absolute; top: 0.5rem; right: 0.6rem; color: var(--crit); font-size: 0.6rem; }

  /* ── Stats cards ── */
  .stats-row { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem 1.5rem;
    min-width: 130px;
    flex: 1;
  }
  .stat-value { font-size: 2rem; font-weight: 800; line-height: 1; font-family: 'JetBrains Mono', monospace; }
  .stat-label { font-size: 0.72rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.1em; margin-top: 0.25rem; }

  /* ── Remediation table ── */
  .remed-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  .remed-table th {
    text-align: left;
    padding: 0.6rem 1rem;
    font-size: 0.65rem;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
  }
  .remed-table td { padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); vertical-align: middle; }
  .remed-table tr:hover td { background: var(--surface); }
  .remed-table tr:last-child td { border-bottom: none; }
  .rule-id { color: var(--accent); }
  .finding-name { font-weight: 600; }
  .count-cell { font-family: 'JetBrains Mono', monospace; font-weight: 700; text-align: center; }
  .file-list code { font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: var(--muted); background: var(--surface2); padding: 0.1rem 0.35rem; border-radius: 3px; margin-right: 0.25rem; }

  /* ── Findings detail ── */
  .file-block {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 1rem;
    overflow: hidden;
  }
  .file-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.85rem 1.25rem;
    background: var(--surface2);
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }
  .file-icon { font-size: 0.9rem; }
  .file-path { font-size: 0.8rem; color: var(--text); flex: 1; }
  .file-counts { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
  .count-chip { font-size: 0.72rem; font-weight: 700; }

  .findings-list { padding: 0; }
  .finding-row {
    padding: 1rem 1.25rem;
    border-bottom: 1px solid var(--border);
  }
  .finding-row:last-child { border-bottom: none; }

  .finding-header {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    flex-wrap: wrap;
    margin-bottom: 0.6rem;
  }
  .finding-title { font-weight: 600; font-size: 0.9rem; }
  .finding-meta { font-size: 0.75rem; }

  .code-snippet {
    background: #020817;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.6rem 0.9rem;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    color: #94a3b8;
    overflow-x: auto;
    margin-bottom: 0.75rem;
    white-space: pre-wrap;
    word-break: break-all;
  }

  .finding-detail { display: flex; flex-direction: column; gap: 0.4rem; }
  .detail-row { display: flex; gap: 0.75rem; font-size: 0.82rem; }
  .detail-label {
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--muted);
    min-width: 65px;
    padding-top: 0.15rem;
  }
  .inline-fix {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    color: #86efac;
    white-space: pre-wrap;
    word-break: break-all;
    margin: 0;
  }

  /* ── Badges ── */
  .badge {
    display: inline-block;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    padding: 0.15rem 0.45rem;
    border-radius: 3px;
    border: 1px solid transparent;
    text-transform: uppercase;
  }
  .badge-excepted { background: rgba(100,116,139,0.15); color: #64748b; border-color: #64748b40; }
  .badge-resolved { background: rgba(34,197,94,0.12); color: #22c55e; border-color: #22c55e40; }

  /* ── Misc ── */
  .mono { font-family: 'JetBrains Mono', monospace; }
  .muted { color: var(--muted); }
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.5rem;
  }

  /* ── Navigation tabs ── */
  .tabs { display: flex; gap: 0; border-bottom: 1px solid var(--border); margin-bottom: 2rem; }
  .tab {
    padding: 0.75rem 1.5rem;
    font-size: 0.8rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    color: var(--muted);
    cursor: pointer;
    border-bottom: 2px solid transparent;
    transition: all 0.15s;
    user-select: none;
  }
  .tab:hover { color: var(--text); }
  .tab.active { color: var(--accent); border-bottom-color: var(--accent); }
  .tab-panel { display: none; }
  .tab-panel.active { display: block; }
  .tab-badge { display: inline-block; background: rgba(56,189,248,0.2); color: var(--accent);
               border-radius: 10px; font-size: 0.7rem; font-weight: 700;
               padding: 0.05rem 0.45rem; margin-left: 0.4rem; vertical-align: middle; }
  .tab-deep { color: var(--accent) !important; }
  .deep-file { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
               padding: 1.5rem; margin-bottom: 1.5rem; }
  .deep-file-header { font-family: 'JetBrains Mono', monospace; font-size: 0.82rem;
                      color: var(--accent); margin-bottom: 1rem; display: flex;
                      align-items: center; gap: 0.75rem; }
  .deep-finding { border-left: 3px solid var(--border); padding: 1rem 1.25rem;
                  margin-bottom: 1rem; background: var(--surface2); border-radius: 0 6px 6px 0; }
  .deep-finding.sev-critical { border-left-color: var(--crit); }
  .deep-finding.sev-high     { border-left-color: var(--high); }
  .deep-finding-title { font-weight: 700; font-size: 0.9rem; margin-bottom: 0.5rem; }
  .deep-section { margin-top: 0.75rem; }
  .deep-section-label { font-size: 0.7rem; font-weight: 700; letter-spacing: 0.1em;
                        text-transform: uppercase; color: var(--muted); margin-bottom: 0.3rem; }
  .deep-section-body { font-size: 0.85rem; color: var(--text); line-height: 1.6; }
  .deep-code { background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
               padding: 0.75rem 1rem; font-family: 'JetBrains Mono', monospace;
               font-size: 0.78rem; overflow-x: auto; white-space: pre; margin-top: 0.4rem; }
  .deep-empty { color: var(--muted); padding: 3rem 0; text-align: center; }
  .deep-item { background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
               padding: 0; margin-bottom: 1.5rem; overflow: hidden; }
  .deep-item-header { display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem 1.25rem;
                      background: var(--surface2); border-bottom: 1px solid var(--border); }
  .deep-item-sev { font-size: 0.72rem; font-weight: 800; letter-spacing: 0.08em;
                   text-transform: uppercase; min-width: 70px; }
  .deep-item-file { font-family: 'JetBrains Mono', monospace; font-size: 0.78rem;
                    color: var(--accent); flex: 1; overflow: hidden;
                    text-overflow: ellipsis; white-space: nowrap; }
  .deep-orig-box { padding: 1rem 1.25rem; border-bottom: 1px solid var(--border);
                   background: rgba(30,41,59,0.4); }
  .deep-orig-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }
  .deep-orig-label { font-size: 0.65rem; font-weight: 700; letter-spacing: 0.1em;
                     text-transform: uppercase; color: var(--muted);
                     background: var(--surface2); border: 1px solid var(--border);
                     border-radius: 4px; padding: 0.15rem 0.5rem; }
  .deep-orig-rule { font-family: 'JetBrains Mono', monospace; font-size: 0.78rem;
                    color: var(--muted); }
  .deep-orig-name { font-weight: 700; font-size: 0.9rem; color: var(--text); margin-bottom: 0.25rem; }
  .deep-orig-section { margin-top: 0.75rem; }
  .deep-claude-box { padding: 1rem 1.25rem; }
  .deep-claude-label { font-size: 0.65rem; font-weight: 700; letter-spacing: 0.1em;
                       text-transform: uppercase; color: var(--accent);
                       margin-bottom: 0.75rem; }
  .deep-confidence { font-size: 0.72rem; font-weight: 600; letter-spacing: 0.06em;
                     text-transform: uppercase; color: var(--muted);
                     background: var(--surface2); border: 1px solid var(--border);
                     border-radius: 4px; padding: 0.1rem 0.45rem; margin-left: 0.5rem; }
  .deep-filter-btn.active { opacity: 1 !important; font-weight: 700; }
  .deep-item.hidden { display: none; }

  /* ── Filters ── */
  .filter-bar { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
  .filter-btn {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    font-weight: 700;
    padding: 0.3rem 0.75rem;
    border-radius: 4px;
    border: 1px solid var(--border);
    background: var(--surface2);
    color: var(--muted);
    cursor: pointer;
    transition: all 0.15s;
  }
  .filter-btn:hover, .filter-btn.active { border-color: var(--accent); color: var(--accent); background: rgba(56,189,248,0.08); }

  /* ── File links ── */
  .file-link {
    color: inherit;
    text-decoration: none;
    cursor: pointer;
    position: relative;
    transition: color 0.15s;
  }
  .file-link:hover { color: var(--accent); text-decoration: underline; text-underline-offset: 3px; }
  .file-path.file-link:hover { color: var(--accent); }
  .finding-meta.file-link:hover { color: var(--accent); }

  /* Clipboard toast */
  #clip-toast {
    position: fixed;
    bottom: 1.5rem;
    right: 1.5rem;
    background: var(--surface2);
    border: 1px solid var(--accent);
    color: var(--accent);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    opacity: 0;
    transform: translateY(8px);
    transition: opacity 0.2s, transform 0.2s;
    pointer-events: none;
    z-index: 999;
    max-width: 400px;
    word-break: break-all;
  }
  #clip-toast.show { opacity: 1; transform: translateY(0); }

  /* ── Footer ── */
  .report-footer {
    margin-top: 4rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.75rem;
    color: var(--muted);
  }
  `;
}

// ── JS (interactive) ───────────────────────────────────────────────────────

function buildJS() {
  return `
  // Tab switching
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const panel = tab.dataset.tab;
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(panel).classList.add('active');
    });
  });

  // Severity filter
  document.querySelectorAll('.filter-btn[data-sev]').forEach(btn => {
    btn.addEventListener('click', () => {
      btn.classList.toggle('active');
      const activeSevs = [...document.querySelectorAll('.filter-btn[data-sev].active')].map(b => b.dataset.sev);
      document.querySelectorAll('.finding-row').forEach(row => {
        if (activeSevs.length === 0 || activeSevs.includes(row.dataset.sev)) {
          row.style.display = '';
        } else {
          row.style.display = 'none';
        }
      });
      document.querySelectorAll('.file-block').forEach(block => {
        const visible = [...block.querySelectorAll('.finding-row')].some(r => r.style.display !== 'none');
        block.style.display = visible ? '' : 'none';
      });
    });
  });

  // ── Deep analysis sort & filter ─────────────────────────────────────────
  const SEV_SORT = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, EXPOSURE: 3 };

  function deepSortItems(sortKey) {
    const container = document.getElementById('deep-items-container');
    if (!container) return;
    const items = [...container.querySelectorAll('.deep-item')];
    items.sort((a, b) => {
      const aFP = a.dataset.fp === '1' ? 1 : 0;
      const bFP = b.dataset.fp === '1' ? 1 : 0;
      if (aFP !== bFP) return aFP - bFP;  // confirmed first, FP last always
      if (sortKey === 'file') {
        const fa = a.querySelector('.deep-item-file')?.textContent || '';
        const fb = b.querySelector('.deep-item-file')?.textContent || '';
        return fa.localeCompare(fb);
      }
      // severity sort (default)
      const sa = SEV_SORT[a.dataset.sev] ?? 9;
      const sb = SEV_SORT[b.dataset.sev] ?? 9;
      return sa - sb;
    });
    items.forEach(item => container.appendChild(item));
  }

  document.querySelectorAll('.deep-sort-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.deep-sort-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      deepSortItems(btn.dataset.deepSort);
    });
  });

  // ── Deep analysis filter ─────────────────────────────────────────────────
  document.querySelectorAll('.deep-filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const sev = btn.dataset.deepSev;

      // Toggle active state – but 'ALL' is exclusive
      if (sev === 'ALL') {
        document.querySelectorAll('.deep-filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
      } else {
        document.querySelector('.deep-filter-btn[data-deep-sev="ALL"]').classList.remove('active');
        btn.classList.toggle('active');
        // If nothing active, reset to ALL
        const anyActive = [...document.querySelectorAll('.deep-filter-btn:not([data-deep-sev="ALL"])')].some(b => b.classList.contains('active'));
        if (!anyActive) {
          document.querySelector('.deep-filter-btn[data-deep-sev="ALL"]').classList.add('active');
        }
      }

      // Collect active filters
      const active = [...document.querySelectorAll('.deep-filter-btn.active')].map(b => b.dataset.deepSev);
      const showAll = active.includes('ALL');

      let visible = 0;
      document.querySelectorAll('.deep-item').forEach(item => {
        const itemSev = item.dataset.sev;
        const itemFP  = item.dataset.fp === '1';
        const match   = showAll
          || active.includes(itemSev)
          || (active.includes('FP') && itemFP);
        item.classList.toggle('hidden', !match);
        if (match) visible++;
      });

      const emptyMsg = document.getElementById('deep-empty-msg');
      if (emptyMsg) emptyMsg.style.display = visible === 0 ? '' : 'none';
    });
  });

  // ── Clipboard toast ──────────────────────────────────────────────────────
  const toast = document.createElement('div');
  toast.id = 'clip-toast';
  document.body.appendChild(toast);

  let toastTimer;
  function showToast(msg) {
    toast.textContent = msg;
    toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('show'), 2200);
  }

  function copyToClip(text) {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(() => showToast('📋 Copied: ' + text));
    } else {
      // Fallback for file:// context
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); showToast('📋 Copied: ' + text); } catch(e) {}
      document.body.removeChild(ta);
    }
  }

  // ── File links: vscode:// primary, clipboard on right-click ─────────────
  document.querySelectorAll('.file-link').forEach(link => {
    const clip = link.dataset.clip;
    if (!clip) return;

    // Left click: attempt vscode://, show toast that it was triggered
    link.addEventListener('click', (e) => {
      // vscode:// href handles the navigation; we just show feedback
      setTimeout(() => showToast('↗ Opening in VS Code…'), 80);
      // If vscode:// fails (no VS Code), browser does nothing – clipboard as fallback
    });

    // Right-click: always copy path to clipboard
    link.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      copyToClip(clip);
    });
  });
  `;
}

// ── Main render ────────────────────────────────────────────────────────────

// ── Deep Analysis tab renderer ────────────────────────────────────────────

function renderDeepTab(deepResults, allFindings) {
  if (!deepResults || deepResults.size === 0) return '';

  const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, EXPOSURE: 3 };
  const SEV_COLOR = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', EXPOSURE: '#3b82f6' };

  // Build a flat list of all deep items enriched with original finding data
  const items = [];
  for (const [filePath, analyses] of deepResults.entries()) {
    if (!analyses || analyses.length === 0) continue;
    for (const a of analyses) {
      // Find matching original finding for context
      const orig = allFindings
        ? allFindings.find(f => f.ruleId === a.ruleId && f.line === a.line && f.filePath === filePath)
        : null;
      items.push({ ...a, filePath, orig });
    }
  }

  if (items.length === 0) {
    return '<div id="tab-deep" class="tab-panel"><div class="deep-empty">No deep analysis results available.</div></div>';
  }

  // Collect severities present for filter buttons
  const sevPresent = [...new Set(items.map(i => i.severity).filter(Boolean))];
  sevPresent.sort((a, b) => (SEV_ORDER[a] ?? 9) - (SEV_ORDER[b] ?? 9));
  const confirmedCount = items.filter(i => i.confirmed !== false).length;
  const fpCount        = items.filter(i => i.confirmed === false).length;

  // Render a single deep item
  function renderItem(a) {
    const sev     = a.severity || '';
    const sevCls  = 'sev-' + sev.toLowerCase();
    const sevCol  = SEV_COLOR[sev] || '#64748b';
    const isFP    = a.confirmed === false;

    // ── Original finding box ───────────────────────────────────────────
    let origBox = '';
    if (a.orig) {
      const o = a.orig;
      origBox = [
        '<div class="deep-orig-box">',
        '  <div class="deep-orig-header">',
        '    <span class="deep-orig-label">Original finding</span>',
        '    <span class="deep-orig-rule">' + escHtml(o.ruleId || '') + '</span>',
        '    <span class="muted" style="font-size:0.75rem">' + escHtml(o.category || '') + '</span>',
        '  </div>',
        '  <div class="deep-orig-name">' + escHtml(o.name || '') + '</div>',
        o.snippet ? '  <div class="deep-code" style="margin-top:0.5rem">' + escHtml(o.snippet) + '</div>' : '',
        o.why ? [
          '  <div class="deep-orig-section">',
          '    <span class="deep-section-label">Why this matters</span>',
          '    <div class="deep-section-body">' + escHtml(o.why) + '</div>',
          '  </div>',
        ].join('') : '',
        '</div>',
      ].join('');
    }

    // ── Claude analysis ────────────────────────────────────────────────
    const confirmedHtml = isFP
      ? '<span style="color:#22c55e;font-weight:700">✓ False positive</span>'
      : '<span style="color:#ef4444;font-weight:700">⚠ Confirmed vulnerability</span>';

    const confidenceHtml = a.confidence
      ? ' <span class="deep-confidence">' + escHtml(a.confidence) + '</span>'
      : '';

    const fpReasonHtml = isFP && a.false_positive_reason
      ? '<div class="deep-section"><div class="deep-section-label">Reason</div>' +
        '<div class="deep-section-body">' + escHtml(a.false_positive_reason) + '</div></div>'
      : '';

    const scenarioHtml = !isFP && a.attack_scenario
      ? '<div class="deep-section"><div class="deep-section-label">Attack Scenario</div>' +
        '<div class="deep-section-body">' + escHtml(a.attack_scenario) + '</div></div>'
      : '';

    const fixHtml = !isFP && a.fix_explanation
      ? '<div class="deep-section"><div class="deep-section-label">Recommended Fix</div>' +
        '<div class="deep-section-body">' + escHtml(a.fix_explanation) + '</div></div>'
      : '';

    const codeHtml = !isFP && a.fix_code
      ? '<div class="deep-section"><div class="deep-section-label">Fix Example</div>' +
        '<div class="deep-code">' + escHtml(a.fix_code) + '</div></div>'
      : '';

    return [
      '<div class="deep-item ' + sevCls + '" data-sev="' + sev + '" data-fp="' + (isFP ? '1' : '0') + '">',
      '  <div class="deep-item-header">',
      '    <span class="deep-item-sev" style="color:' + sevCol + '">' + escHtml(sev) + '</span>',
      '    <span class="deep-item-file">' + escHtml(a.filePath) + '</span>',
      (a.line ? '    <span class="muted" style="font-size:0.75rem">line ' + a.line + '</span>' : ''),
      '  </div>',
      origBox,
      '  <div class="deep-claude-box">',
      '    <div class="deep-claude-label">Claude analysis</div>',
      '    <div style="margin-bottom:0.5rem">' + confirmedHtml + confidenceHtml + '</div>',
      fpReasonHtml,
      scenarioHtml,
      fixHtml,
      codeHtml,
      '  </div>',
      '</div>',
    ].join('');
  }

  // Pre-sort by severity
  items.sort((a, b) => {
    const sd = (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
    if (sd !== 0) return sd;
    return (a.filePath || '').localeCompare(b.filePath || '');
  });

  const itemsHtml = items.map(renderItem).join('');

  // Filter buttons
  const filterBtns = sevPresent.map(sev =>
    '<button class="filter-btn deep-filter-btn" data-deep-sev="' + sev + '" style="border-color:' +
    (SEV_COLOR[sev] || '#64748b') + '40;color:' + (SEV_COLOR[sev] || '#64748b') + '">' +
    sev + ' (' + items.filter(i => i.severity === sev).length + ')</button>'
  ).join('');

  const fpBtn = fpCount > 0
    ? '<button class="filter-btn deep-filter-btn" data-deep-sev="FP" style="border-color:#22c55e40;color:#22c55e">False positive (' + fpCount + ')</button>'
    : '';

  return [
    '<div id="tab-deep" class="tab-panel">',
    '  <div class="section">',
    '    <div class="section-title">Claude AI Deep Analysis</div>',
    '    <p class="muted" style="margin-bottom:1.5rem;font-size:0.85rem">',
    '      AI-powered analysis of CRITICAL and HIGH findings — ' + confirmedCount + ' confirmed, ' + fpCount + ' false positive' + (fpCount !== 1 ? 's' : '') + '.',
    '      Each confirmed finding shows the original detection context alongside Claude\'s assessment.',
    '    </p>',
    '    <div class="filter-bar" style="margin-bottom:1.5rem;flex-wrap:wrap">',
    '      <span class="muted" style="font-size:0.75rem;padding:0.3rem 0;align-self:center">Filter:</span>',
    '      <button class="filter-btn deep-filter-btn active" data-deep-sev="ALL" style="border-color:#38bdf840;color:#38bdf8">All (' + items.length + ')</button>',
    filterBtns,
    fpBtn,
    '      <span style="flex:1;min-width:1rem"></span>',
    '      <span class="muted" style="font-size:0.75rem;padding:0.3rem 0;align-self:center">Sort:</span>',
    '      <button class="filter-btn deep-sort-btn active" data-deep-sort="severity">Severity</button>',
    '      <button class="filter-btn deep-sort-btn" data-deep-sort="file">File name</button>',
    '    </div>',
    '    <div id="deep-items-container">',
    itemsHtml,
    '    </div>',
    '    <div id="deep-empty-msg" style="display:none" class="deep-empty">No findings match the current filter.</div>',
    '  </div>',
    '</div>',
  ].join('');
}

function generateReport(findings, opts = {}) {
  const {
    target      = '.',
    repoName    = null,
    scanDate    = new Date(),
    totalFiles  = 0,
    skipped     = [],
    repoRoot    = process.cwd(),
    deepResults = null,
  } = opts;

  const displayName = repoName || path.basename(path.resolve(repoRoot));

  const counts     = countBySeverity(findings);
  const score      = computeRiskScore(findings);
  const risk       = riskLabel(score);
  const owaspHit   = getOwaspCoverage(findings);
  const remedPlan  = buildRemediationPlan(findings);
  const maxCount   = Math.max(...Object.values(counts), 1);

  const sevRows = ['CRITICAL', 'HIGH', 'MEDIUM', 'EXPOSURE'].map(sev => `
    <div class="sev-row">
      <span class="sev-label" style="color:${SEV_COLOR[sev]}">${sev}</span>
      <div class="sev-bar-wrap">
        <div class="sev-bar" style="width:${Math.round((counts[sev] / maxCount) * 100)}%;background:${SEV_COLOR[sev]}"></div>
      </div>
      <span class="sev-count" style="color:${SEV_COLOR[sev]}">${counts[sev]}</span>
    </div>`).join('');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escHtml(displayName)} – Security Report</title>
  <style>${buildCSS()}</style>
</head>
<body>
<div class="page">

  <!-- Header -->
  <header class="report-header">
    <div>
      <div class="brand">
        <div class="brand-icon">🛡️</div>
        <span class="brand-name">Secure Code by Design</span>
      </div>
      <h1 class="report-title">${escHtml(displayName)}</h1>
      <div class="report-target mono">${escHtml(target)}</div>
    </div>
    <div class="report-meta">
      <div class="meta-date">
        <strong>${formatDate(scanDate)}</strong>
        ${formatTime(scanDate)} UTC
      </div>
    </div>
  </header>

  <!-- Stats row -->
  <div class="stats-row">
    <div class="stat-card">
      <div class="stat-value">${findings.length}</div>
      <div class="stat-label">Total Findings</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" style="color:${SEV_COLOR.CRITICAL}">${counts.CRITICAL}</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" style="color:${SEV_COLOR.HIGH}">${counts.HIGH}</div>
      <div class="stat-label">High</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" style="color:${SEV_COLOR.MEDIUM}">${counts.MEDIUM}</div>
      <div class="stat-label">Medium</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">${totalFiles}</div>
      <div class="stat-label">Files Scanned</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">${owaspHit.size}/10</div>
      <div class="stat-label">OWASP Categories</div>
    </div>
  </div>

  <!-- Tabs -->
  <div class="tabs">
    <div class="tab active" data-tab="tab-executive">Executive Summary</div>
    <div class="tab" data-tab="tab-remediation">Remediation Plan</div>
    <div class="tab" data-tab="tab-findings">All Findings</div>
    ${deepResults && deepResults.size > 0 ? '<div class="tab tab-deep" data-tab="tab-deep">🔍 Deep Analysis <span class="tab-badge">' + deepResults.size + '</span></div>' : ''}
  </div>

  <!-- Tab: Executive Summary -->
  <div id="tab-executive" class="tab-panel active">

    <div class="section">
      <div class="section-title">Risk Assessment</div>
      <div class="exec-grid">
        ${renderGauge(score, risk)}
        <div class="card">
          <div class="section-title" style="margin-bottom:1rem">Severity Breakdown</div>
          <div class="sev-breakdown">${sevRows}</div>
        </div>
        <div class="card">
          <div class="section-title" style="margin-bottom:1rem">Key Findings</div>
          ${counts.CRITICAL > 0 ? `<p style="color:${SEV_COLOR.CRITICAL};font-weight:600;margin-bottom:0.5rem">⚠ ${counts.CRITICAL} critical vulnerabilities require immediate attention.</p>` : ''}
          ${counts.HIGH > 0 ? `<p style="color:${SEV_COLOR.HIGH};font-weight:600;margin-bottom:0.5rem">⚠ ${counts.HIGH} high-severity issues should be resolved before next release.</p>` : ''}
          ${counts.CRITICAL === 0 && counts.HIGH === 0 ? `<p style="color:#22c55e;font-weight:600">✓ No critical or high severity findings.</p>` : ''}
          <p class="muted" style="font-size:0.82rem;margin-top:0.75rem">${totalFiles} files scanned · ${skipped.length} skipped · ${findings.filter(f => f.excepted).length} excepted</p>
        </div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">OWASP Top 10 Coverage (2021)</div>
      <div class="owasp-grid">${renderOwaspGrid(owaspHit)}</div>
      <p class="muted" style="font-size:0.78rem;margin-top:0.75rem">
        Highlighted categories have findings in this scan. ${owaspHit.size} of 10 OWASP Top 10 categories detected.
      </p>
    </div>

  </div>

  <!-- Tab: Remediation Plan -->
  <div id="tab-remediation" class="tab-panel">
    <div class="section">
      <div class="section-title">Recommended Action Order</div>
      <p class="muted" style="margin-bottom:1.5rem;font-size:0.85rem">
        Findings are ordered by severity and occurrence count. Address critical issues first to reduce overall risk exposure.
      </p>
      ${renderRemediationTable(remedPlan)}
    </div>
  </div>

  <!-- Tab: All Findings -->
  <div id="tab-findings" class="tab-panel">
    <div class="section">
      <div class="section-title">Findings Detail</div>
      <div class="filter-bar">
        <span class="muted" style="font-size:0.75rem;padding:0.3rem 0;align-self:center">Filter:</span>
        ${['CRITICAL', 'HIGH', 'MEDIUM', 'EXPOSURE'].map(sev =>
          counts[sev] > 0
            ? `<button class="filter-btn" data-sev="${sev}" style="border-color:${SEV_COLOR[sev]}40;color:${SEV_COLOR[sev]}">${sev} (${counts[sev]})</button>`
            : ''
        ).join('')}
      </div>
      ${renderFindingsDetail(findings, repoRoot)}
    </div>
  </div>

  <!-- Tab: Deep Analysis -->
  ${deepResults && deepResults.size > 0 ? renderDeepTab(deepResults, findings) : ''}

  <!-- Footer -->
  <footer class="report-footer">
    <span>Generated by <strong>Secure Code by Design</strong></span>
    <span>${formatDate(scanDate)} · ${findings.length} findings · ${totalFiles} files</span>
  </footer>

</div>
<script>${buildJS()}</script>
</body>
</html>`;

  return html;
}

// ── File output ────────────────────────────────────────────────────────────

function writeReport(html, outputPath) {
  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(outputPath, html, { encoding: 'utf8', mode: 0o644 });
}

module.exports = { generateReport, writeReport };

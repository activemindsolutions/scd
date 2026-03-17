/**
 * report-index.js
 * Generates the HTML index page for sc report --serve.
 * Matches the visual theme of report-html.js.
 */

'use strict';

const fs   = require('fs');
const path = require('path');

function buildIndexPage(reports, reportDir, currentFile) {
  const meta = (() => {
    try {
      return JSON.parse(fs.readFileSync(path.join(reportDir, '..', 'meta.json'), 'utf8'));
    } catch { return {}; }
  })();

  const rows = reports.map(r => {
    const date    = (r.filename.match(/(\d{4}-\d{2}-\d{2})/) || [])[1] || '—';
    const sizeStr = r.size > 1024 * 1024
      ? (r.size / 1024 / 1024).toFixed(1) + ' MB'
      : Math.round(r.size / 1024) + ' KB';
    const age     = Math.floor((Date.now() - new Date(r.mtime)) / 86400000);
    const ageStr  = age === 0 ? 'today' : age === 1 ? 'yesterday' : age + ' days ago';
    const isCurrent = r.filename === currentFile;
    const badge   = isCurrent ? '<span class="badge-latest">latest</span>' : '';

    return [
      '<tr class="' + (isCurrent ? 'current' : '') + '">',
      '  <td class="td-date"><span class="mono">' + date + '</span></td>',
      '  <td class="td-name"><span class="mono">' + esc(r.filename) + '</span>' + badge + '</td>',
      '  <td class="td-size muted">' + sizeStr + '</td>',
      '  <td class="td-age muted">' + ageStr + '</td>',
      '  <td class="td-actions">',
      '    <a class="btn btn-open" href="/' + encodeURIComponent(r.filename) + '" target="_blank">Open</a>',
      '    <a class="btn btn-dl" href="/download/' + encodeURIComponent(r.filename) + '" download="' + esc(r.filename) + '">↓</a>',
      '  </td>',
      '</tr>',
    ].join('\n');
  }).join('\n');

  const dlAll = reports.length > 1
    ? '<a class="btn btn-dl-all" href="/download-all">↓ Download all</a>'
    : '';

  const tableOrEmpty = reports.length === 0
    ? '<div class="empty">No reports found. Run <code>sc report</code> to generate one.</div>'
    : [
        '<table>',
        '  <thead><tr>',
        '    <th>Date</th><th>File</th><th>Size</th><th>Age</th><th></th>',
        '  </tr></thead>',
        '  <tbody>' + rows + '</tbody>',
        '</table>',
      ].join('\n');

  return [
    '<!DOCTYPE html>',
    '<html lang="en">',
    '<head>',
    '  <meta charset="UTF-8">',
    '  <meta name="viewport" content="width=device-width, initial-scale=1.0">',
    '  <title>Security Co-Pilot \u2013 Reports</title>',
    '  <link rel="preconnect" href="https://fonts.googleapis.com">',
    '  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">',
    '  <style>' + buildCSS() + '  </style>',
    '</head>',
    '<body>',
    '  <div class="page">',
    '    <div class="report-header">',
    '      <div>',
    '        <div class="brand">',
    '          <div class="brand-icon">\uD83D\uDEE1</div>',
    '          <div class="brand-name">Security Co-Pilot</div>',
    '        </div>',
    '        <div class="repo-name">' + esc(meta.name || 'Reports') + '</div>',
    meta.localPath ? '        <div class="repo-path">' + esc(meta.localPath) + '</div>' : '',
    '      </div>',
    '    </div>',
    '    <div class="section-title">',
    '      <span>' + reports.length + ' saved report' + (reports.length !== 1 ? 's' : '') + '</span>',
    '      ' + dlAll,
    '    </div>',
    '    ' + tableOrEmpty,
    '  </div>',
    '</body>',
    '</html>',
  ].join('\n');
}

function buildCSS() {
  return [
    '    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }',
    '    :root {',
    '      --bg:       #0a0f1a;',
    '      --surface:  #0f172a;',
    '      --surface2: #1e293b;',
    '      --border:   #1e293b;',
    '      --text:     #e2e8f0;',
    '      --muted:    #64748b;',
    '      --accent:   #38bdf8;',
    '    }',
    '    html { font-size: 15px; }',
    '    body { background: var(--bg); color: var(--text); font-family: \'Syne\', sans-serif;',
    '           line-height: 1.6; min-height: 100vh; }',
    '    .page { max-width: 900px; margin: 0 auto; padding: 0 2rem 4rem; }',
    '    .report-header { border-bottom: 1px solid var(--border); padding: 3rem 0 2rem;',
    '                     margin-bottom: 2.5rem; display: flex; align-items: center; gap: 2rem; }',
    '    .brand { display: flex; align-items: center; gap: 1rem; }',
    '    .brand-icon { width: 38px; height: 38px; background: var(--accent); border-radius: 8px;',
    '                  display: flex; align-items: center; justify-content: center; font-size: 1.2rem; }',
    '    .brand-name { font-size: 0.85rem; font-weight: 700; letter-spacing: 0.1em;',
    '                  text-transform: uppercase; color: var(--muted); }',
    '    .repo-name { font-size: 1.5rem; font-weight: 800; color: var(--text); margin-top: 0.4rem; }',
    '    .repo-path { font-family: \'JetBrains Mono\', monospace; color: var(--muted);',
    '                 font-size: 0.78rem; margin-top: 0.3rem; }',
    '    .section-title { font-size: 0.72rem; font-weight: 700; letter-spacing: 0.12em;',
    '                     text-transform: uppercase; color: var(--muted); margin-bottom: 1rem;',
    '                     display: flex; align-items: center; justify-content: space-between; }',
    '    table { width: 100%; border-collapse: collapse; }',
    '    th { font-size: 0.7rem; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase;',
    '         color: var(--muted); padding: 0 1rem 0.75rem; text-align: left;',
    '         border-bottom: 1px solid var(--border); }',
    '    td { padding: 0.85rem 1rem; border-bottom: 1px solid rgba(30,41,59,0.6); vertical-align: middle; }',
    '    tr:hover td { background: var(--surface); }',
    '    tr.current td { background: rgba(56,189,248,0.04); }',
    '    tr:last-child td { border-bottom: none; }',
    '    .mono { font-family: \'JetBrains Mono\', monospace; font-size: 0.82rem; }',
    '    .muted { color: var(--muted); font-size: 0.85rem; }',
    '    .td-actions { text-align: right; white-space: nowrap; }',
    '    .badge-latest { font-size: 0.63rem; font-weight: 700; letter-spacing: 0.06em;',
    '                    text-transform: uppercase; background: rgba(56,189,248,0.15);',
    '                    color: var(--accent); border: 1px solid rgba(56,189,248,0.3);',
    '                    border-radius: 4px; padding: 0.1rem 0.4rem; margin-left: 0.5rem;',
    '                    vertical-align: middle; }',
    '    .btn { display: inline-block; font-size: 0.78rem; font-weight: 600; border-radius: 6px;',
    '           padding: 0.3rem 0.8rem; text-decoration: none; cursor: pointer; transition: opacity 0.15s; }',
    '    .btn:hover { opacity: 0.8; }',
    '    .btn-open { background: var(--accent); color: #0a0f1a; margin-right: 0.4rem; }',
    '    .btn-dl   { background: var(--surface2); color: var(--text); border: 1px solid var(--border); }',
    '    .btn-dl-all { background: var(--surface2); color: var(--text); border: 1px solid var(--border);',
    '                  font-size: 0.78rem; font-weight: 600; border-radius: 6px;',
    '                  padding: 0.3rem 0.9rem; text-decoration: none; }',
    '    .empty { color: var(--muted); padding: 3rem 0; text-align: center; font-size: 0.9rem; }',
  ].join('\n');
}

function esc(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

module.exports = { buildIndexPage };

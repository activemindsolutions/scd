/**
 * store-verify.js
 *
 * Verifies that repos in the global store still exist on disk and are
 * valid git repositories. Reports status for each, and optionally runs
 * an interactive cleanup flow.
 *
 * Statuses:
 *   OK      – localPath exists, is a git repo, remote matches (if remote-type)
 *   STALE   – localPath exists but .git/ is gone (remote-type repos only)
 *   MISSING – localPath does not exist on disk
 *   ORPHAN  – meta.json has no localPath recorded
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const readline = require('readline');

const REPOS_DIR = path.join(
  process.env.HOME || process.env.USERPROFILE || '~',
  '.security-copilot', 'repos'
);

// ── Status constants ───────────────────────────────────────────────────────

const STATUS = {
  OK:      'OK',
  STALE:   'STALE',
  MISSING: 'MISSING',
  ORPHAN:  'ORPHAN',
};

// ── Helpers ────────────────────────────────────────────────────────────────

function daysSince(isoString) {
  if (!isoString) return null;
  const diff = Date.now() - new Date(isoString).getTime();
  return Math.floor(diff / (1000 * 60 * 60 * 24));
}

function repoStorePath(repoId) {
  return path.join(REPOS_DIR, repoId);
}

function readMeta(repoId) {
  try {
    return JSON.parse(
      fs.readFileSync(path.join(repoStorePath(repoId), 'meta.json'), 'utf8')
    );
  } catch {
    return { repoId, name: repoId, localPath: null, remote: null, type: null };
  }
}

function getStoreStats(repoId) {
  const dir = repoStorePath(repoId);
  let scanCount = 0;
  let reportCount = 0;
  let totalBytes = 0;

  // Count scans in audit.log
  const auditFile = path.join(dir, 'audit.log');
  if (fs.existsSync(auditFile)) {
    try {
      const lines = fs.readFileSync(auditFile, 'utf8').split('\n').filter(Boolean);
      scanCount = lines.filter(l => {
        try { return JSON.parse(l).event === 'scan_complete'; } catch { return false; }
      }).length;
    } catch {}
  }

  // Count reports
  const reportsDir = path.join(dir, 'reports');
  if (fs.existsSync(reportsDir)) {
    try {
      reportCount = fs.readdirSync(reportsDir).filter(f => /\.(html|md|json)$/.test(f)).length;
    } catch {}
  }

  // Total store size
  try {
    const walk = (d) => {
      for (const f of fs.readdirSync(d)) {
        const full = path.join(d, f);
        try {
          const st = fs.statSync(full);
          if (st.isDirectory()) walk(full);
          else totalBytes += st.size;
        } catch {}
      }
    };
    walk(dir);
  } catch {}

  return { scanCount, reportCount, totalBytes };
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function currentRemote(localPath) {
  try {
    return execSync('git remote get-url origin', {
      cwd: localPath, stdio: ['pipe', 'pipe', 'pipe']
    }).toString().trim();
  } catch {
    return null;
  }
}

// ── Core verify logic ──────────────────────────────────────────────────────

function verifyRepo(repoId) {
  const meta = readMeta(repoId);
  const result = {
    repoId,
    name:        meta.name      || repoId,
    localPath:   meta.localPath || null,
    remote:      meta.remote    || null,
    type:        meta.type      || 'unknown',
    lastSeen:    meta.lastSeen  || null,
    lastScan:    meta.lastScan  || null,
    daysSinceLastSeen: daysSince(meta.lastSeen),
    status:      null,
    detail:      null,
    stats:       getStoreStats(repoId),
  };

  if (!meta.localPath) {
    result.status = STATUS.ORPHAN;
    result.detail = 'No localPath recorded in meta.json';
    return result;
  }

  if (!fs.existsSync(meta.localPath)) {
    result.status = STATUS.MISSING;
    result.detail = 'Directory no longer exists on disk';
    return result;
  }

  const gitDir = path.join(meta.localPath, '.git');
  const hasGit = fs.existsSync(gitDir);

  if (meta.type === 'path-based') {
    // path-based repos are plain directory scans — .git/ is irrelevant
    // Optionally note if .git has appeared (repo was initialised after first scan)
    result.status = STATUS.OK;
    if (hasGit) {
      result.detail = 'Directory scan — .git/ present (repo was initialised after first scan)';
    }
    return result;
  }

  // For remote-type repos: .git/ must exist
  if (!hasGit) {
    result.status = STATUS.STALE;
    result.detail = '.git/ directory removed — no longer a git repository';
    return result;
  }

  // Check remote match
  if (meta.remote) {
    const actualRemote = currentRemote(meta.localPath);
    if (actualRemote && actualRemote !== meta.remote) {
      result.status = STATUS.STALE;
      result.detail = `Remote mismatch — stored: ${meta.remote}, actual: ${actualRemote}`;
      return result;
    }
  }

  result.status = STATUS.OK;
  return result;
}

function verifyAll() {
  if (!fs.existsSync(REPOS_DIR)) return [];
  const ids = fs.readdirSync(REPOS_DIR).filter(id => {
    try { return fs.statSync(path.join(REPOS_DIR, id)).isDirectory(); }
    catch { return false; }
  });
  return ids.map(verifyRepo);
}

// ── Archive a repo store entry ─────────────────────────────────────────────

function archiveRepo(repoId) {
  const { execSync } = require('child_process');
  const dir     = repoStorePath(repoId);
  const meta    = readMeta(repoId);
  const ts      = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const name    = (meta.name || repoId).replace(/[^a-z0-9_-]/gi, '_');
  const archive = path.join(
    process.env.HOME || process.env.USERPROFILE || '~',
    '.security-copilot', 'archive',
    `${name}_${ts}.tar.gz`
  );

  fs.mkdirSync(path.dirname(archive), { recursive: true, mode: 0o700 });

  execSync(`tar -czf "${archive}" -C "${path.dirname(dir)}" "${repoId}"`, {
    stdio: ['pipe', 'pipe', 'pipe']
  });

  fs.rmSync(dir, { recursive: true, force: true });
  return archive;
}

// ── Delete a repo store entry ──────────────────────────────────────────────

function deleteRepo(repoId) {
  const dir = repoStorePath(repoId);
  fs.rmSync(dir, { recursive: true, force: true });
}

// ── Interactive cleanup prompt ─────────────────────────────────────────────

async function promptClean(results) {
  const issues = results.filter(r => r.status !== STATUS.OK);
  if (issues.length === 0) return;

  const rl = readline.createInterface({
    input:  process.stdin,
    output: process.stdout,
  });

  const ask = (q) => new Promise(resolve => rl.question(q, resolve));

  const BOLD  = '\x1b[1m';
  const DIM   = '\x1b[90m';
  const RESET = '\x1b[0m';
  const CYAN  = '\x1b[36m';
  const RED   = '\x1b[31m';
  const YELLOW = '\x1b[33m';

  console.log('');

  for (const repo of issues) {
    const age = repo.daysSinceLastSeen !== null ? `last seen ${repo.daysSinceLastSeen} days ago` : 'never seen';
    const statsStr = `${repo.stats.scanCount} scan${repo.stats.scanCount !== 1 ? 's' : ''}, `
                   + `${repo.stats.reportCount} report${repo.stats.reportCount !== 1 ? 's' : ''}, `
                   + `${formatBytes(repo.stats.totalBytes)} stored`;

    console.log(BOLD + '──────────────────────────────────────────────────' + RESET);
    console.log(BOLD + repo.name + RESET + '  ' + DIM + `(${repo.repoId.slice(0, 12)}…)` + RESET);
    console.log(`  Status:  ${statusBadge(repo.status)}  ${DIM}${repo.detail}${RESET}`);
    console.log(`  Path:    ${DIM}${repo.localPath || 'unknown'}${RESET}`);
    console.log(`  History: ${DIM}${statsStr}  ·  ${age}${RESET}`);
    if (repo.remote) {
      console.log(`  Remote:  ${DIM}${repo.remote}${RESET}`);
    }
    console.log('');

    let choice = '';
    while (!['k', 'a', 'd', 's'].includes(choice)) {
      const raw = await ask(
        `  ${CYAN}[k]${RESET} Keep   `
        + `${YELLOW}[a]${RESET} Archive to .tar.gz   `
        + `${RED}[d]${RESET} Delete   `
        + `${DIM}[s]${RESET} Skip\n  → `
      );
      choice = raw.trim().toLowerCase();
    }

    console.log('');

    if (choice === 'k') {
      console.log(`  ${DIM}Kept — no changes made.${RESET}\n`);

    } else if (choice === 'a') {
      try {
        const archivePath = archiveRepo(repo.repoId);
        console.log(`  ✓ Archived to: ${archivePath}\n`);
      } catch (err) {
        console.log(`  ✗ Archive failed: ${err.message}\n`);
      }

    } else if (choice === 'd') {
      // Extra confirmation if there is scan history
      let confirmed = true;
      if (repo.stats.scanCount > 0) {
        const confirm = await ask(
          `  ${RED}Warning:${RESET} This repo has ${repo.stats.scanCount} scan(s) in history.\n`
          + `  Type the repo name to confirm deletion: `
        );
        confirmed = confirm.trim() === repo.name;
        if (!confirmed) {
          console.log(`  ${DIM}Name did not match — skipping deletion.${RESET}\n`);
        }
      }
      if (confirmed) {
        deleteRepo(repo.repoId);
        console.log(`  ✓ Deleted store entry for ${repo.name}\n`);
      }

    } else {
      console.log(`  ${DIM}Skipped.${RESET}\n`);
    }
  }

  rl.close();
}

// ── Rendering ──────────────────────────────────────────────────────────────

const STATUS_ICON = {
  OK:      '\x1b[32m✓\x1b[0m',
  MISSING: '\x1b[33m⚠\x1b[0m',
  STALE:   '\x1b[31m✗\x1b[0m',
  ORPHAN:  '\x1b[31m✗\x1b[0m',
};

function statusBadge(status) {
  const colors = {
    OK:      '\x1b[32m',
    MISSING: '\x1b[33m',
    STALE:   '\x1b[31m',
    ORPHAN:  '\x1b[31m',
  };
  return (colors[status] || '') + status + '\x1b[0m';
}

function renderResults(results, { verbose } = {}) {
  const DIM   = '\x1b[90m';
  const BOLD  = '\x1b[1m';
  const RESET = '\x1b[0m';

  const issues  = results.filter(r => r.status !== STATUS.OK);
  const ok      = results.filter(r => r.status === STATUS.OK);

  console.log('');

  for (const repo of results) {
    const icon = STATUS_ICON[repo.status] || '?';
    const age  = repo.daysSinceLastSeen !== null
      ? DIM + `  (last seen ${repo.daysSinceLastSeen}d ago)` + RESET
      : '';

    const pathStr = repo.localPath
      ? DIM + '  ' + repo.localPath + RESET
      : DIM + '  (no path)' + RESET;

    console.log(
      `  ${icon}  ${BOLD}${repo.name.padEnd(24)}${RESET}`
      + statusBadge(repo.status).padEnd(18)
      + pathStr
      + age
    );

    if (verbose && repo.status !== STATUS.OK) {
      console.log(`     ${DIM}↳ ${repo.detail}${RESET}`);
    }
  }

  console.log('');
  console.log(
    `  ${DIM}${ok.length}/${results.length} repos OK`
    + (issues.length > 0 ? `  ·  ${issues.length} issue${issues.length !== 1 ? 's' : ''} found` : '')
    + RESET
  );
  console.log('');

  if (issues.length > 0) {
    console.log(
      `  ${DIM}Run ${RESET}sc store --verify --clean${DIM} to review cleanup options.${RESET}`
    );
    console.log('');
  }
}

module.exports = {
  verifyAll,
  verifyRepo,
  promptClean,
  renderResults,
  deleteRepo,
  archiveRepo,
  formatBytes,
  STATUS,
};

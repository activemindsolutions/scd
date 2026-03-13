/**
 * git-utils.js
 * Helpers to extract which files are relevant for each hook type.
 *
 * pre-commit  → files staged for this commit (git diff --cached)
 * pre-push    → files changed vs remote (what will actually be pushed)
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

/**
 * Returns a list of { filePath, content } objects for the relevant hook.
 */
async function getChangedFiles(hookType = 'pre-push') {
  try {
    let output = '';

    if (hookType === 'pre-commit') {
      // Files staged for the upcoming commit
      output = execSync('git diff --cached --name-only --diff-filter=ACM', {
        encoding: 'utf8'
      });
    } else {
      // pre-push: files changed in commits not yet on remote
      // Falls back to last commit if no remote configured (common in new repos)
      try {
        // Try against remote tracking branch first
        output = execSync('git diff --name-only --diff-filter=ACM @{u} HEAD', {
          encoding: 'utf8'
        });
      } catch {
        try {
          // Has more than one commit – diff against previous
          output = execSync('git diff --name-only --diff-filter=ACM HEAD~1 HEAD', {
            encoding: 'utf8'
          });
        } catch {
          // Only one commit – list all tracked files
          output = execSync('git diff --name-only --diff-filter=ACM --cached HEAD', {
            encoding: 'utf8', shell: true
          });
          if (!output.trim()) {
            // Absolute fallback: all files in repo
            output = execSync('git ls-files', { encoding: 'utf8' });
          }
        }
      }
    }

    const filePaths = output
      .trim()
      .split('\n')
      .filter(Boolean)
      .filter(f => shouldScanFile(f));

    const files = [];
    for (const filePath of filePaths) {
      try {
        if (hookType === 'pre-commit') {
          // Read staged content (not working tree) via git show
          const content = execSync(`git show :${filePath}`, { encoding: 'utf8' });
          files.push({ filePath, content });
        } else {
          if (fs.existsSync(filePath)) {
            const content = fs.readFileSync(filePath, 'utf8');
            files.push({ filePath, content });
          }
        }
      } catch {
        // Binary file or unreadable – skip
      }
    }

    return files;
  } catch {
    // Not in a git repo or no commits yet
    return [];
  }
}

/**
 * Files we skip scanning (binary, dependencies, generated)
 */
function shouldScanFile(filePath) {
  const skip = [
    'node_modules/', '.git/', 'dist/', 'build/', '.next/',
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
  ];
  const skipExt = [
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.pdf',
    '.zip', '.tar', '.gz', '.map'
  ];

  if (skip.some(s => filePath.includes(s))) return false;
  if (skipExt.some(e => filePath.endsWith(e))) return false;
  return true;
}

module.exports = { getChangedFiles };

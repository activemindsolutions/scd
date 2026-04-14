# Secure Code by Design – Installation Guide

## Requirements

- Node.js 22 or later
- Git
- npm (included with Node.js)

---

## 1. Install Node.js

If you already have Node.js 22 or later installed, skip this step.

**macOS**

The recommended way is via [nvm](https://github.com/nvm-sh/nvm) (Node Version Manager):

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
# Restart your terminal, then:
nvm install 22
nvm use 22
node --version   # should show v22.x.x
```

Alternatively, download the installer directly from [nodejs.org](https://nodejs.org).

**Linux**

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
# Restart your terminal, then:
nvm install 22
nvm use 22
node --version
```

Or use your distribution's package manager — but make sure the version is 22 or later.
Many distros ship an older version of Node.js by default.

**Windows**

Download and run the Node.js 22 installer from [nodejs.org](https://nodejs.org).
Use the LTS version. The installer includes npm.

After installation, verify in PowerShell or Command Prompt:

```powershell
node --version   # should show v22.x.x
npm --version
```

> **PowerShell execution policy:** If npm scripts fail with a policy error, run this once
> in an elevated PowerShell window:
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
> ```

---

## 2. Install scd

```bash
npm install -g @activemind/scd
scd --version   # verify
```

To uninstall (your scan history in `~/.scd` is kept):

```bash
npm uninstall -g @activemind/scd
```

> **Development install:** If you have cloned the repository and want to run from source:
> ```bash
> cd scd
> npm install
> npm link
> ```
> To remove the dev link: `npm unlink -g @activemind/scd`

---

## 3. Set up a repository

Run this inside any Git repository you want to scan:

```bash
cd /path/to/your/project
scd init     # register repo + install git hooks
scd doctor   # verify setup
scd scan     # run your first scan
```

`scd init` installs pre-commit and pre-push hooks via Git's `core.hooksPath` — no files
are written to your repository.

---

## Connecting to scd-server *(Team / Professional)*

scd-server provides team dashboards, exception approval, findings history, deep analysis,
and CRA compliance reports. It runs in your own infrastructure — no data leaves your network.

Once your organisation's scd-server is running, connect the CLI:

```bash
scd configure --central-url http://your-server:3000
scd configure --token <api-token-from-scd-server-admin>
scd doctor    # verify connection
```

> `localhost` is automatically normalised to `127.0.0.1` to avoid IPv6 resolution issues.

**Adjust timeouts if needed** (defaults work for most setups):

```bash
scd configure --server-timeout 30s    # regular API calls (default: 30s)
scd configure --deep-timeout 20m      # deep analysis (default: 20m)
```

**Push local scan history to a newly connected server:**

```bash
scd sync --history
```

This is idempotent — safe to run multiple times.

---

## Store data

All scan history, configuration, and reports are stored outside your repositories:

```
~/.scd/                          # macOS / Linux
%USERPROFILE%\.scd\             # Windows (e.g. C:\Users\YourName\.scd\)
  config                         ← central URL, token, timeouts
  repos/
    {repoId}/
      meta.json                  ← repo identity, last scan, timestamps
      config.yml                 ← exceptions and rule configuration
      audit.log                  ← full scan history (append-only)
      last-scan.json             ← latest scan cache
      scans/                     ← one JSON per scan (never overwritten)
      reports/                   ← generated HTML/MD/JSON reports
      exports/                   ← exported json-files from scd export-findings command
```

Uninstalling `scd` does not remove store data — your scan history is preserved.

**Inspect or clean up store data:**

```bash
scd store --show              # info for current repo
scd store --verify            # check all repos
scd store --verify --clean    # interactive cleanup
scd remove                    # remove current repo from store
```

**Remove all store data (irreversible):**

```bash
# macOS / Linux
rm -rf ~/.scd

# Windows (PowerShell)
Remove-Item -Recurse -Force "$env:USERPROFILE\.scd"
```

---

## Shell aliases

If you have existing aliases that conflict with the `scd` command, remove them from your
shell configuration (`~/.zshrc`, `~/.bashrc`):

```bash
# Remove lines like:
alias scd=...
```

Then reload your shell:

```bash
source ~/.zshrc   # or ~/.bashrc
```

On Windows, check your PowerShell profile (`$PROFILE`) for conflicting aliases.

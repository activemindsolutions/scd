# Secure Code by Design – Installation Guide

## Requirements

- Node.js 18 or later
- Git (for hook installation)
- npm

---

## Installation (npm link)

This is the current installation method. Clone the repository and link it globally with npm.

```bash
git clone git@github.com:activemindsolutions/scd.git
cd scd
npm install
npm link
scd --version        # verify
```

To remove the dev link without touching store data:

```bash
npm unlink -g @activemind/scd
```

---

## Other machines (install from tarball)

> **Note:** Tarball distribution is planned but not yet fully verified. The steps below describe the intended workflow. Use npm link (above) in the meantime.

On the machine where scd is cloned, pack a tarball:

```bash
cd ~/Projects/scd
npm pack
# → activemind-scd-x.y.z.tgz
```

Copy the `.tgz` to the target machine (AirDrop, scp, USB), then:

```bash
npm install -g activemind-scd-x.y.z.tgz
scd --version
```

To uninstall (store data in `~/.scd` is kept):

```bash
npm uninstall -g @activemind/scd
```

---

## First use on a new repo

```bash
cd /path/to/your/project
scd init             # register repo + install git hooks
scd doctor           # verify setup
scd scan             # run first scan
```

---

## Connecting to scd-server *(Premium)*

scd-server provides team dashboards, exception approval, findings history,
deep analysis, and CRA compliance reports. It runs in your own infrastructure —
no data leaves your network.

Once your organisation's scd-server is up and running, connect your CLI to it:

```bash
scd configure --central-url http://your-server:3000
scd configure --token <api-token-from-scd-server-admin>
scd doctor    # verify connection
```

> `localhost` is automatically normalised to `127.0.0.1` to avoid IPv6 resolution issues.

### Optional: adjust timeouts

Default timeouts work for most setups. Adjust if needed:

```bash
scd configure --server-timeout 30s    # API calls (default: 30s)
scd configure --deep-timeout 20m      # Deep analysis (default: 20m)
```

### Sync existing scan history

To push local scan history to a newly connected scd-server:

```bash
cd /path/to/your/project
scd sync --history
```

This is idempotent — safe to run multiple times.

---

## Store data

All scan history, configs and reports are stored outside your repositories:

```
~/.scd/                         # macOS / Linux
%USERPROFILE%\.scd\            # Windows (e.g. C:\Users\YourName\.scd\)
  config                        ← central URL, token, timeouts
  repos/
    {repoId}/
      meta.json                 ← repo identity, last scan, timestamps
      config.yml                ← exceptions and rule configuration
      audit.log                 ← full scan history (append-only)
      last-scan.json            ← latest scan cache
      scans/                    ← one JSON per scan (never overwritten)
      reports/                  ← generated HTML/MD/JSON reports
```

**Uninstalling the `scd` binary does not remove store data.**
This is intentional — your scan history is preserved.

To inspect or clean up store data:

```bash
scd store --show              # info for current repo
scd store --verify            # check all repos
scd store --verify --clean    # interactive cleanup
scd remove                    # remove current repo from store
```

To completely remove all store data (irreversible):

```bash
# macOS / Linux
rm -rf ~/.scd

# Windows (PowerShell)
Remove-Item -Recurse -Force "$env:USERPROFILE\.scd"
```

---

## Shell aliases

If you previously had aliases set up that conflict with the global `scd` binary,
remove them from your shell configuration:

```bash
# Remove from ~/.zshrc or ~/.bashrc — lines like:
alias scd=...
alias sc=...
```

After editing, reload your shell:

```bash
source ~/.zshrc   # or ~/.bashrc
```

On Windows, check your PowerShell profile (`$PROFILE`) for any conflicting aliases.

# Secure Code by Design – Installation Guide

## Requirements

- Node.js 18 or later
- Git (for hook installation)
- npm

---

## Development machine (npm link)

Use this on your primary development machine where the source code lives.
Changes to the source take effect immediately — no reinstall needed.

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

On the development machine, pack a tarball:

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

To uninstall the binary (store data in ~/.scd is kept):

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

## scd-server setup (Team / Professional tier)

scd-server provides team dashboards, exception approval, findings history,
and CRA compliance reports. It runs in your own infrastructure — no data
leaves your network.

### Connect CLI to scd-server

```bash
scd configure --central-url http://your-server:3000
scd configure --token <api-token-from-scd-server-admin>
```

Note: `localhost` is automatically normalized to `127.0.0.1` to avoid
IPv6 resolution issues on some systems.

### Sync history from existing repos

If you are upgrading from Starter to Team, sync your local audit history
to the server once per repo:

```bash
cd /path/to/your/project
scd sync --history
```

This is idempotent — safe to run multiple times.

---

## Store data

All scan history, configs and reports are stored in:

```
~/.scd/
  config              ← central URL, token
  repos/
    {repoId}/
      meta.json
      config.yml
      audit.log
      last-scan.json
      scans/
      reports/
```

**Uninstalling the `scd` binary does not remove store data.**
This is intentional — your scan history is preserved.

To inspect or clean up store data:

```bash
scd store --show              # info for current repo
scd store --verify            # check all repos
scd store --verify --clean    # interactive cleanup
```

To completely remove all store data (irreversible):

```bash
rm -rf ~/.scd
```

---

## Shell aliases

If you previously had aliases set up (e.g. from an older installation),
remove any that conflict with the global `scd` binary:

```bash
# Remove from ~/.zshrc or ~/.bashrc — lines like:
alias scd=...
alias sc=...
export PATH=...security-copilot-poc...
```

After editing, reload your shell:

```bash
source ~/.zshrc   # or ~/.bashrc
```

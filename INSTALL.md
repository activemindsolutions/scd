# Security Co-Pilot – Installation Guide

## Requirements

- Node.js 18 or later
- Git (for hook installation)
- npm

---

## Development machine (npm link)

Use this on your primary development machine where the source code lives.
Changes to the source take effect immediately — no reinstall needed.

```bash
cd ~/Projects/security-copilot
npm install          # install dependencies
npm link             # register 'sc' globally via symlink
sc --version         # verify
```

To remove the dev link without touching store data:

```bash
npm unlink -g security-copilot
```

---

## Other machines (install from tarball)

On the development machine, pack a tarball:

```bash
cd ~/Projects/security-copilot
npm pack
# → security-copilot-0.1.0.tgz
```

Copy the `.tgz` to the target machine (AirDrop, scp, USB), then:

```bash
npm install -g security-copilot-0.1.0.tgz
sc --version
```

To uninstall the binary (store data in ~/.security-copilot is kept):

```bash
npm uninstall -g security-copilot
```

---

## First use on a new repo

```bash
cd /path/to/your/project
sc init              # register repo + install git hooks
sc doctor            # verify setup
sc scan              # run first scan
```

---

## Store data

All scan history, configs and reports are stored in:

```
~/.security-copilot/
  config              ← API key (sc configure --api-key)
  repos/
    {repoId}/
      meta.json
      config.yml
      audit.log
      last-scan.json
      reports/
```

**Uninstalling the `sc` binary does not remove store data.**
This is intentional — your scan history is preserved.

To inspect or clean up store data:

```bash
sc store --show              # info for current repo
sc store --verify            # check all repos
sc store --verify --clean    # interactive cleanup
```

To completely remove all store data (irreversible):

```bash
rm -rf ~/.security-copilot
```

---

## Zsh / shell aliases

If you previously had aliases set up in `~/.zshrc.d/30-aliases.zsh`,
remove them — the global `sc` binary replaces them.

Lines to remove:

```zsh
# (any alias or path pointing to the old security-copilot-poc directory)
alias sc=...
export PATH=...security-copilot-poc...
```

After editing, reload your shell:

```bash
source ~/.zshrc
```

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
cd ~/Projects/scd
npm install          # install dependencies
npm link             # register 'scd' globally via symlink
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
# → activemind-scd-0.1.0.tgz
```

Copy the `.tgz` to the target machine (AirDrop, scp, USB), then:

```bash
npm install -g activemind-scd-0.1.0.tgz
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

## Store data

All scan history, configs and reports are stored in:

```
~/.scd/
  config              ← API key (scd configure --api-key)
  repos/
    {repoId}/
      meta.json
      config.yml
      audit.log
      last-scan.json
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

## Zsh / shell aliases

If you previously had aliases set up in `~/.zshrc.d/30-aliases.zsh`,
remove them — the global `scd` binary replaces them.

Lines to remove:

```zsh
# (any alias or path pointing to an old scd directory)
alias sc=...
alias scd=...

```

After editing, reload your shell:

```bash
source ~/.zshrc
```

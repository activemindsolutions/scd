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

The `-g` flag installs scd globally so the `scd` command is available in all your terminals and git repositories. Without it, scd is installed locally in the current directory only and the `scd` command will not be found.

```bash
npm install -g @activemind/scd
scd --version   # verify
```

> **Development install:** If you have cloned the repository and want to run from source:
> ```bash
> cd scd
> npm install
> npm link
> ```
> To remove the dev link: `npm unlink -g @activemind/scd`

---

## 3. Set up git hooks (once per machine)

**This step must be done before `scd init`.** scd uses git hooks to scan your code automatically — before commits (secrets scan) and before pushes (full OWASP scan). The hooks are installed globally on your machine, so every git repository you work in is protected automatically.

```bash
scd install
```

You only need to run this once per machine. It sets up the hooks in `~/.scd/hooks/` and configures git to use them globally. Verify with:

```bash
scd doctor
```

If you skip this step and run `scd init` first, git hooks will not be active. Run `scd install` at any time to add them — no need to re-run `scd init`.

**To remove the hooks** from a machine (for example when switching to a different setup):

```bash
scd uninstall
```

This removes the global hooks and the git configuration, but preserves your scan history and exceptions in `~/.scd/`.

---

## 4. Register a project (once per project)

Once the hooks are installed, register each project you want to work with:

```bash
cd /path/to/your/project
scd init
scd scan     # run your first scan
```

`scd init` creates a per-project config file in `~/.scd/repos/` — nothing is written to your repository. Run it in each project you want to track separately.

### What is the difference between `scd install` and `scd init`?

| | `scd install` | `scd init` |
|---|---|---|
| **Scope** | Machine-wide | Per project |
| **Run** | Once per machine | Once per project |
| **What it does** | Installs git hooks that protect all repos | Registers the project, creates config |
| **Touches the repo** | No | No |

`scd install` is the global step — without it, hooks do not run. `scd init` is the per-project step — it sets up the local config and scan store for that specific project. `scd doctor` will tell you clearly if either step has been missed.

---

## Connecting to scd-server *(Team / Professional)*

scd-server provides team dashboards, exception approval, findings history, deep analysis,
and CRA compliance reports. It runs in your own infrastructure — no data leaves your network.

Once your organisation's scd-server is running, your admin will create a user account for
you and share a personal CLI token. Each developer has their own token — tokens are shown
once at creation and cannot be retrieved again. If you lose your token, ask your admin to
regenerate it via Admin → Users.

```bash
scd configure --central-url http://your-server:3000
scd configure --token <your-personal-token>
scd doctor    # verify connection
```

Then run a scan to activate your installation on the server:

```bash
scd scan
```

The first scan registers your machine with your user account on the server. Until you run
a scan, your installation shows as "Pending first scan" in the admin dashboard.

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

Uninstalling scd with `npm uninstall -g @activemind/scd` or `scd uninstall` does not remove store data — your scan history is preserved.

**Inspect or clean up store data:**

```bash
scd repo --show              # info for current repo
scd repo --verify            # check all repos
scd repo --verify --clean    # interactive cleanup
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

## Uninstalling scd completely

To remove everything — hooks, npm package, and store data:

```bash
# 1. Remove global hooks and git configuration
scd uninstall

# 2. Remove the npm package
npm uninstall -g @activemind/scd

# 3. Remove store data (scan history, configs, reports) — irreversible
rm -rf ~/.scd                     # macOS / Linux
# Remove-Item -Recurse -Force "$env:USERPROFILE\.scd"   # Windows
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

> **Note for nvm users:** If `scd` points to the wrong location after switching Node.js versions,
> run `hash -r` (bash/zsh) to clear the shell's command cache and force a fresh PATH lookup.

---

## Troubleshooting

### Windows

**`scd` installed but not working as expected — missing `-g` flag**

If `scd` behaves unexpectedly or a second terminal cannot find it, you may have installed without the `-g` flag. This installs scd locally in the current directory instead of globally. Fix it:

```powershell
npm uninstall @activemind/scd          # remove local install
npm install -g @activemind/scd         # reinstall globally
scd --version
```

---

**`scd` not recognized after `npm link` or `npm install -g`**

npm on Windows does not always add its global bin directory to PATH automatically.
This is common when Node.js was installed via Chocolatey or certain other package managers.

Run this in PowerShell, then open a new terminal window:

```powershell
[System.Environment]::SetEnvironmentVariable(
  "PATH",
  $env:PATH + ";$env:APPDATA\npm",
  [System.EnvironmentVariableTarget]::User
)
```

To verify that the scd shim exists where npm expects it:

```powershell
ls "$env:APPDATA\npm" | Where-Object { $_.Name -like "scd*" }
```

If no files are listed, `npm install -g` or `npm link` did not complete successfully.
Try running it again in a PowerShell window opened as Administrator (right-click → Run as administrator).

---

**PowerShell execution policy error when running `scd`**

If you see a message about scripts being disabled on this system, run this once in PowerShell:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

Then open a new PowerShell window and try again.

---

### macOS

**`scd` installed but not working as expected — missing `-g` flag**

If `scd` is not found or behaves unexpectedly, you may have installed without the `-g` flag. Fix it:

```bash
npm uninstall @activemind/scd          # remove local install
npm install -g @activemind/scd         # reinstall globally
scd --version
```

---

**`scd` not found after `npm install -g`**

If your shell cannot find `scd` after a global install, npm's bin directory is likely not in
your PATH. This is common when Node.js was installed via nvm and the shell profile was not
reloaded.

Check where npm puts global binaries:

```bash
npm config get prefix
```

The output is typically `~/.nvm/versions/node/v22.x.x` when using nvm, or `/usr/local` with
a system install. Add the `bin` subdirectory to your PATH if it is missing:

```bash
# Add to ~/.zshrc or ~/.bash_profile (replace with your actual prefix):
export PATH="$(npm config get prefix)/bin:$PATH"
```

Reload the shell:

```bash
source ~/.zshrc   # or ~/.bash_profile
```

If you installed Node.js via nvm, the simpler fix is to ensure nvm initialisation is present
in your shell profile. Check that your `~/.zshrc` or `~/.bash_profile` contains the nvm setup
lines that the nvm installer added — and that you have run `nvm use 22` (or
`nvm alias default 22` to make it permanent).

---

### Linux

**`scd` not found after `npm install -g`**

Same root cause as macOS above. Check your prefix:

```bash
npm config get prefix
```

If npm was installed via your distribution's package manager and the prefix is `/usr`, global
binaries land in `/usr/bin` — which should already be in PATH. If the prefix is something like
`~/.npm-global`, add it:

```bash
export PATH="$HOME/.npm-global/bin:$PATH"
```

Add the line to `~/.bashrc` or `~/.profile` and reload:

```bash
source ~/.bashrc
```

---

**Permission error on `npm install -g`**

If you see `EACCES: permission denied` during global install, do not use `sudo npm install -g`.
Instead, configure npm to use a user-local prefix:

```bash
mkdir -p ~/.npm-global
npm config set prefix '~/.npm-global'
export PATH="$HOME/.npm-global/bin:$PATH"   # add this to ~/.bashrc too
npm install -g @activemind/scd
```

---

**`scd` points to wrong location after switching Node.js versions (nvm)**

If you switch Node.js versions with nvm and `scd` stops working or points to an old path,
clear your shell's command cache:

```bash
hash -r
```

Then verify:

```bash
which scd
scd --version
```

If `scd` is still missing, reinstall the package for the new Node.js version:

```bash
nvm use 22
npm install -g @activemind/scd
```

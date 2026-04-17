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

---

## Troubleshooting

### Windows

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

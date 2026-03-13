# Security Co-Pilot – Claude Project Instructions

## Who I am
Mikael Jansson, penetration tester and security consultant at Activemind Solutions AB (Sweden).
CEH certified. Works exclusively within authorized, legal boundaries.
Philosophy: "360-degree security thinking / think like a hacker."

## What this project is
**Security Co-Pilot** – a Node.js CLI tool (`sc`) that automatically scans code for security
vulnerabilities, targeting SMB companies using AI coding tools (Claude Code, GitHub Copilot, Cursor)
who lack in-house security expertise.

**Not a replacement for pentesting** – it minimizes the number of vulnerabilities that reach
production so that pentests can focus on harder problems.

## Repository
- GitHub: `git@github.com:activemindsolutions/security-copilot.git`
- Local (primary dev): `~/Projects/security-copilot`
- Installed via: `npm link` (dev) or `git clone && npm install && npm link` (other machines)
- Command: `sc`

## Tech stack
- Node.js 18+ (CommonJS, no transpilation)
- commander@11 (CLI framework)
- No other runtime dependencies – deliberately lightweight
- Claude API (Anthropic) for deep analysis features (`sc insights --deep`, `sc scan --deep`)

## Key design principles
1. **Zero repo footprint** – SC never writes files to the customer's repo
2. **Global store** – all data in `~/.security-copilot/repos/{repoId}/`
3. **repoId** = SHA-256 of git remote URL (stable across re-clones), fallback = SHA-256 of abs path
4. **English only** – all rule text, CLI output, comments in English
5. **Rule IDs are stable** – never renumber or rename existing rule IDs
6. **No npm dependencies added without discussion** – keep the install lightweight

## Code conventions
- CommonJS (`require`/`module.exports`), no ES modules
- `'use strict'` in all lib files
- Descriptive variable names, comments for non-obvious logic
- ANSI color via raw escape codes (no chalk dependency)
- All user-facing strings in English

## Working style
- Mikael is hands-on and reviews all code before committing
- Discuss architecture decisions before implementing
- Always run `node --check` on modified files before presenting
- Present files via the file tool so Mikael can download and copy them in
- Commits and pushes are done by Mikael manually

## What NOT to do
- Do not add new npm dependencies without explicit discussion
- Do not rename or restructure existing rule IDs
- Do not write files to the customer's repo (zero footprint principle)
- Do not use ES module syntax (`import`/`export`)
- Do not use Swedish in code, comments, or CLI output

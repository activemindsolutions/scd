# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.3.x   | :white_check_mark: |
| < 1.3.0 | :x:                |

v1.3.0 is the first supported release. Earlier tagged versions are available in the repository history but do not receive security updates.

## Reporting a Vulnerability

Secure Code by Design is a security tool — and like any software, it may contain vulnerabilities. We encourage security testing of this product and welcome responsible disclosure.

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately to: [security@activemind.se](mailto:security@activemind.se)

Include as much detail as possible: steps to reproduce, affected version, and potential impact. We aim to acknowledge reports within 2 business days and will keep you updated on our progress. Credit is given to researchers who report valid findings responsibly.

## Expected behaviour when scanning or testing scd itself

If you run scd, other static analysis tools, or security scanners against this repository, expect a significant number of findings — particularly in the rule definition files under `rules/`.

This is by design and does not indicate real vulnerabilities.

The rule files contain the exact patterns that scd is built to detect: SQL injection constructs, command injection sequences, hardcoded secrets, path traversal patterns, insecure deserialization examples, and more. These patterns exist because the scanner needs something to match against. The same applies to test fixtures and any sample code used during rule development.

Any scanner — including scd itself — will most likely flag these patterns. A finding in a rule file means the detection logic is working as intended, not that the codebase contains an exploitable vulnerability.

Before reporting a finding, verify that it originates from actual application logic (files under `bin/` or `lib/`, excluding `lib/rules/`) rather than from rule definitions or test data. Confirmed vulnerabilities in the application code are always in scope and welcome.

# Service Buddy Security Scanner

A security scanner tuned for the Service Buddy stack:

- **Frontend:** React 18, TypeScript 5, Vite 5, React Query (on S3 + CloudFront)
- **Backend:** NestJS 10 on Express, MongoDB (Mongoose), AWS S3
- **Integrations:** Stripe, Rainforest (BuddyPay), QuickBooks Online

It runs locally on your checked-out repositories (and optionally makes a
**passive, read-only** probe of a live site), then writes an HTML report, a
Markdown report, a SARIF file for GitHub code scanning, and a ready-to-paste
Claude Code prompt that drives a deeper backend review.

> This repository contains the **tooling only**. It does not contain any
> findings, reports, URLs, or credentials. Run it against your own code to
> generate those, and keep the output private (`sb-security-report/` is
> git-ignored).

---

## Quick start

```bash
git clone https://github.com/drdhavaltrivedi/sb-security-scanner.git
chmod +x sb-security-scanner/sb-security-scan.sh

# scan your checked-out repos (static analysis only)
./sb-security-scanner/sb-security-scan.sh ../servicebuddy-web ../servicebuddy-api
```

Add a **passive, read-only** black-box probe of a running environment:

```bash
LIVE_URL=https://app.servicebuddy.io \
LIVE_API=https://api.servicebuddy.io \
./sb-security-scanner/sb-security-scan.sh ../servicebuddy-web ../servicebuddy-api
```

The live probe only makes ordinary, well-formed HTTP requests (the same shape a
browser makes) and reads the responses. It never injects, brute-forces, floods,
or forges anything, so it is safe to point at production.

Only Bash and Python 3 are required. External scanners are used automatically
when present (see below).

---

## What it checks

Results are grouped into eight gates. A gate **fails** on any High finding, and
the script exits non-zero so it can block a CI merge.

| Gate | Area |
|------|------|
| G1 | Secrets in code and git history (Stripe, Rainforest, QuickBooks, AWS, MongoDB URI, JWT secret); committed `.env` |
| G2 | Dependency CVEs (npm audit, osv-scanner, trivy, plus a curated advisory list) |
| G3 | Injection and unsafe code (Mongo operator/`$regex` injection, command exec, SSRF, path traversal, prototype pollution, weak crypto, template/XXE/deserialization) |
| G4 | AuthN/AuthZ and tenant isolation (route guards, roles, **IDOR / company scoping**, JWT handling, user enumeration, token storage) |
| G5 | Payments, QuickBooks, files and PII (webhook signatures, server-side amounts, OAuth and token encryption, S3 keys/uploads, card data) |
| G6 | Frontend (source maps, `innerHTML` / `dangerouslySetInnerHTML`, token storage, `VITE_` secrets) |
| G7 | Config and infrastructure (helmet, CORS, Docker, nginx, CI secrets, TypeScript strict) |
| G8 | Live black-box checks (security headers, public source maps, CORS, TLS, user enumeration) |

### Deep backend analysis

`lib/deep_scan.py` parses the NestJS code across multiple lines (which plain
pattern-matching cannot do) and produces an API **route inventory**
(`routes.csv`) plus findings for: every route's guard/role/tenant-context,
unscoped Mongo queries (IDOR), unvalidated or privileged DTO fields, unsafe
schema fields (card/PII/tokens), auth-flow and crypto weaknesses, exposed
docker-compose databases, and dependencies pinned to versions with known CVEs.

---

## Outputs

Everything is written to `./sb-security-report/` (git-ignored):

| File | Purpose |
|------|---------|
| `REPORT.html` | Interactive report: severity filter, gate table, per-finding fix, highlighted route table |
| `REPORT.md` | Same content in Markdown |
| `findings.sarif` | Upload to GitHub code scanning (findings appear inline on PRs) |
| `findings.tsv` | One row per finding (triage in a spreadsheet) |
| `routes.csv` | API route inventory with auth / role / tenant-context columns |
| `CLAUDE_CODE_PROMPT.md` | Paste into Claude Code in the API repo to run the full backend review |

### Backend review with Claude Code

After a scan, open the **API repo** in [Claude Code](https://claude.com/claude-code)
and paste `sb-security-report/CLAUDE_CODE_PROMPT.md`. It reads the scanner output,
verifies the backend route-by-route (auth, roles, tenant isolation, payments,
QuickBooks, files, secrets) and writes `BACKEND_RESULTS.md` with filled gate and
issue tables and a verdict for every route. It is instructed not to change code
until you approve the fixes.

---

## Options (environment variables)

| Variable | Effect |
|----------|--------|
| `LIVE_URL` / `LIVE_API` | Passive live-probe targets (web app / API) |
| `AUTH_TOKEN` | Decode-only analysis of your own session JWT (optional) |
| `OUT_DIR` | Output directory (default `./sb-security-report`) |
| `SKIP_TOOLS=1` | Only the built-in + deep checks (skip semgrep/trivy/etc.) |
| `INSTALL_TOOLS=1` | `brew install` missing scanners first (macOS) |
| `NO_DOCKER=1` | Don't fall back to Docker images for missing scanners |

### Optional external tools

Used automatically when installed; the script falls back to Docker images if
Docker is running, and skips them otherwise.

```bash
brew install semgrep gitleaks osv-scanner trivy
```

- **semgrep** — SAST rulesets (TypeScript, Node, Express, React, JWT, OWASP Top 10)
- **gitleaks** — secrets in files and full git history
- **osv-scanner** — dependency CVEs across all lockfiles
- **trivy** — Dockerfile / IaC misconfiguration and CVEs

---

## CI

`.github/workflows/security-scan.yml` runs the scan on every push and pull
request, uploads `findings.sarif` to GitHub code scanning, and attaches the full
report as a build artifact. Point the scan paths at your app code and the gates
will fail the build on any High finding.

---

## Notes

- Pattern and deep-scan results are heuristics: confirm each High/Medium in code,
  or mark it a false positive. The Claude Code prompt automates this triage.
- IDOR / tenant findings list every unscoped lookup — confirm each one also
  filters by the caller's company.
- The live probe is intentionally passive; it performs no active exploitation.

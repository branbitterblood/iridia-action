# Iridia — web security audit in CI

Scan your staging deployment after every deploy, re-test it against a committed baseline, and
fail the job on **new** findings. Runs entirely on your runner; nothing is sent anywhere except
the requests to the target itself. Linux x86-64 runners.

## What it checks

Deterministic, zero-LLM, and **detection-grade** — every check is benign and confirmed by a
differential or a signature, never an exploitation payload. Write-probes are opt-in.

- **Injection & input flaws** — SQLi (error-based and blind boolean, calibrated to the app's own
  response jitter), command/path/XPath/LDAP/SSI/XSLT/NoSQL injection, reflected and **second-order**
  (stored) XSS, out-of-band XXE, SSRF, CRLF/header and Host-header injection, padding oracles.
- **Authorization** — two-session **BOLA** (object-level IDOR) and **BFLA** (function-level: a
  privileged function any logged-in user can reach), using **your own** A/B accounts, read-only.
- **Business logic** — client-trusted price, non-positive quantity, and **mass assignment** at
  checkout and account forms (opt-in; inert markers only).
- **Known exposures & CVEs** — a built-in pack of ~50 Nuclei-format templates (exposed panels,
  config/source-control leaks, cloud & infra services, GraphQL introspection, version signatures),
  plus **import your own corpus** — ~41% of the public Nuclei HTTP templates run as-is through a
  strict detection-grade gate. Matches are confirmation-wrapped against a control path to drop
  catch-all false positives.
- **Surface discovery** — a crawl that runs **authenticated** when you supply a login, parameter
  mining for accepted-but-unlinked inputs, OpenAPI/Swagger and GraphQL schema ingestion, and an
  optional headless render for SPAs.
- **Headers, TLS & config** — security headers, cookie flags, CSP gaps, end-of-life runtimes,
  missing anti-CSRF tokens, session fixation.

Findings are fused and chained into an **attack graph** — concrete paths from a weakness to an
impact (including privilege escalation) — and scored with context-aware severity and root-cause
grouping.

## GitHub Actions

```yaml
permissions:
  contents: read
  security-events: write      # to show findings in Code scanning

jobs:
  iridia:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: iridia
        uses: branbitterblood/iridia-action@v0.8.0
        with:
          target: https://staging.example.com
          baseline: .iridia/baseline.json      # optional — omit on the first run
          fail-on: new                          # new | open | none
          severity: high                        # low | medium | high | critical
          license: ${{ secrets.IRIDIA_LICENSE }}
      - if: always() && steps.iridia.outputs.sarif != ''
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: ${{ steps.iridia.outputs.sarif }}
          category: iridia
```

A complete workflow is in [`examples/github-workflow.yml`](examples/github-workflow.yml).

Outputs: `result` (pass/fail), `failing`, `score`, `verdict` (with a baseline: verified / open /
incomplete), `sarif`, `baseline` (this run's `scan.json`). The reports (Executive HTML, SARIF,
Markdown, scan.json) are uploaded as the `iridia` artifact.

## GitLab CI

```yaml
include:
  - remote: https://raw.githubusercontent.com/branbitterblood/iridia-action/v0.8.0/iridia.gitlab-ci.yml

iridia:
  extends: .iridia
  variables:
    IRIDIA_TARGET: https://staging.example.com
    IRIDIA_BASELINE: .iridia/baseline.json
```

Put the key in a masked CI/CD variable `IRIDIA_LICENSE`.

## How the gate works

- **First run:** with no baseline every finding counts as new, so it usually fails. Commit its
  `scan.json` as `.iridia/baseline.json`.
- **After that:** each run re-tests the baseline and fails only on findings at or above
  `severity` that weren't there before. Fixed findings are confirmed in the report.
- Exit codes: 0 pass · 1 rule failed · 2 engine couldn't run · 5 license doesn't cover it.

## Authorization

Passive checks (`passive: true`) need none. Active checks on a public host require that you are
authorized to test it: set `scope` (patterns) and `accept-roe: "true"`. localhost and private
networks need nothing. Logged-in scans take credentials from a secret `IRIDIA_AUTH_JSON`, never
from the command line.

## License

CI runners need an Iridia **Team** key (`IRIDIA_LICENSE`). Without one the free Community checks
run: scans, SARIF and a watermarked report; re-testing against a baseline exits 5.

## Integrity

Each release carries `iridia-engine-linux-x64`, `iridia_ci.py` and `SHA256SUMS`. The action and
the GitLab template download the engine from the release and check it against `SHA256SUMS`
before running it.

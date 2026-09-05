# reconkit

**reconkit** is a modular, offensive-security **reconnaissance and assessment platform**. It runs a library of focused modules against a target you own or are explicitly authorized to test, then produces JSON, HTML, and Markdown engagement reports.

> **Authorized use only.** reconkit is built for lab practice, CTFs, and in-scope engagements (pentest / bug-bounty with written permission). Never point it at systems you do not own or are not authorized to test. Recon and assessment are the professional first phase of offensive security; keep exploitation in labs (Hack The Box, TryHackMe, GOAD) and vetted frameworks.

## Highlights

- **25 built-in modules** across five groups: `net`, `osint`, `web`, `vuln`, `passive` — reconkit's own recon/assessment engine.
- **Arsenal layer — 209 tools across 19 categories:** a catalog + install-detector (`shutil.which`) + authorization-gated launcher that turns reconkit into one front-end for the wider legal offensive ecosystem. (Note: reconkit is only cataloguing these third-party tools and pointing to their own projects. It does not relicense them.)
- Uniform module contract: every module exposes `run(target, ctx)` and returns a structured result (`module`, `summary`, `findings`, `data`).
- Safe by design: scope allow-listing, rate limiting, timeouts, and graceful degradation.
- Three report formats: machine-readable JSON, a styled HTML report, and Markdown engagement notes.
- Pure Python 3.9+ standard library. No third-party dependencies.

## Architecture & Flow

```
CLI
 ↓
Context / Scope / Rate limiter
 ↓
Module Registry
 ↓
25 Native Modules
 ↓
JSON / HTML / Markdown
```

Separately, the arsenal works like this:
```
CLI
 ↓
Arsenal Catalog
 ↓
Detection
 ↓
Authorization Gate
 ↓
External Tool
```

## Quick start

```bash
python -m reconkit list
python -m reconkit run example.com --authorized -g web --json report.json --html report.html --md notes.md

# the arsenal layer: browse, detect, and launch the wider legal toolset
python -m reconkit arsenal list                     # all 209 catalogued tools
python -m reconkit arsenal list -c exploitation     # filter by category
python -m reconkit arsenal check                    # what is installed on this machine
python -m reconkit arsenal run --authorized nmap -- -sV -p1-1000 scanme.nmap.org
```

## Scope & Safety

- Every request to the target is checked against a **scope allow-list** built from the target host plus any `--scope` entries. Out-of-scope hosts are skipped. HTTP redirects are also validated against scope before being followed.
- **Arsenal Authorization Gate**: External tools launched via `arsenal run` are gated behind an `--authorized` flag. This is an authorization attestation gate, not actual scope enforcement over arbitrary external tool arguments. You are responsible for ensuring the target parameters passed to external tools remain in scope.
- **TLS Verification**: Enabled by default for all HTTP requests to ensure secure connections. You can opt-out with the `--insecure` flag if you explicitly need to inspect misconfigured certificates.
- **Rate Limiting**: The `--rate` parameter controls maximum requests/sec in the HTTP client path. The native UDP and Port scanning modules do not necessarily follow this same rate limit.

## Practice lab

Run the bundled deliberately vulnerable application for safe practice:

```bash
python lab/labapp.py
```

> **Warning:** Deliberately vulnerable local-only practice target. Never expose this service to the public internet.

Example output from the included vulnerable lab can be found in the `examples/` directory.

## Design Decisions

- **Standard library only**: Maximizes portability and reduces supply chain risk.
- **Uniform run(target, ctx) module contract**: Simplifies module authoring and execution.
- **Centralized HTTP client and Scope**: Ensures all native modules respect target boundaries and redirects properly.
- **Structured result objects**: Enables deterministic JSON, HTML, and Markdown generation without writing custom parsers.
- **Separate native modules vs external arsenal**: Keeps the core engine dependency-free while still leveraging industry standard tools.

## Limitations

ReconKit is an assessment/reconnaissance platform, not a full exploitation framework. Some vulnerability checks are heuristic and may require manual validation. External arsenal tools are only catalogued/launched; ReconKit does not control their internal behavior or target semantics.

## License

MIT License. See `LICENSE` for more information.

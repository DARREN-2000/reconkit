# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - 2026-09-07

### Added
- Core security reconnaissance platform featuring 25 native modules.
- 209-tool security arsenal catalog with installation detection and execution.
- Scope enforcement with strict validation on HTTP redirects to prevent out-of-scope targets.
- TLS verification enabled by default to ensure secure connections, with an explicit `--insecure` option for inspection of misconfigured targets.
- Rate limiting to throttle HTTP requests.
- Structured reporting offering JSON, HTML, and Markdown outputs.
- A deliberately vulnerable local-only practice target (`labapp.py`) for safe testing.
- Comprehensive `pytest` test suite covering core functionality.
- Automated CI pipeline and automated PyPI packaging configuration via GitHub Actions.
- Hosted documentation infrastructure via MkDocs on GitHub Pages.

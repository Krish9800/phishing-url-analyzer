# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-06

### Added
- **Core URL Lexical Parser & Defanger**:
  - Offline canonicalization and bidirectional refanging.
  - Deconstruction of scheme, host, registered domain, and two-part TLDs.
  - Shannon entropy calculator for DGA identification.
- **Obfuscation Detection Engine**:
  - Dword, Hex, and Octal IP address detection and normalization.
  - RFC 1918 private network and AWS/GCP cloud metadata SSRF detection.
- **Lexical & Structural Heuristics**:
  - Authority masking via embedded `@` credentials.
  - High-risk disposable TLD detection (`.tk`, `.xyz`, `.top`, etc.).
  - Subdomain stuffing and excessive URL/path length flags.
  - Suspicious phishing lure keyword matchers and hyphen stuffing.
- **IDN Homoglyph & Punycode Engine**:
  - Unicode confusable character normalization table (Cyrillic, Greek, Latin lookalikes).
  - Punycode (`xn--`) decoding and visual brand impersonation matching.
- **Typosquatting & Brand Spoofing Engine**:
  - Space-efficient $O(\min(M, N))$ Levenshtein distance calculator.
  - L33tspeak substitution detection.
  - Compound domain and subdomain brand stuffing detection.
- **Scoring & Reporting**:
  - Explainable composite threat scoring (0-100) and risk level classification.
  - Prescriptive defensive countermeasures.
  - ArcSight Common Event Format (CEF) SIEM syslog export.
- **Command Line Interface (CLI)**:
  - Rich-formatted terminal threat cards.
  - `--json` and `--cef` output options.
  - Batch URL triage mode with summary tables.
- **REST API Microservice**:
  - FastAPI endpoints (`/health`, `/api/v1/analyze`, `/api/v1/analyze/batch`, `/api/v1/defang`).
  - Defensive security headers middleware.
- **DevSecOps & Deployment**:
  - Multi-stage unprivileged Docker container (`phishuser:10001`).
  - Docker Compose configuration with resource caps.
  - GitHub Actions CI pipeline with Ruff, Mypy, Bandit, and Pytest coverage gates.

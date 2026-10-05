# Phishing URL & Domain Threat Intelligence Analyzer

[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![Security: Bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![Type Checked: mypy](https://img.shields.io/badge/type_checker-mypy_strict-blue.svg)](https://mypy-lang.org/)
[![Code Style: Ruff](https://img.shields.io/badge/code_style-ruff-black.svg)](https://astral.sh/ruff)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **Educational Defensive Security Project (Cybersecurity Portfolio — Project 04)**  
> A production-grade, defensive Phishing URL, Domain Threat Intelligence, and Homoglyph Spoofing Analyzer. Deconstructs URLs, extracts domain structures, detects IP obfuscation (hex/octal/dword), identifies Punycode/IDN Unicode confusable homoglyphs, calculates Shannon lexical entropy, evaluates brand typosquatting, and produces SIEM-ready defanged telemetry and explainable threat scoring.

---

## 🔒 Security Posture & Guarantees
- **Zero Execution / Non-Interactive Inspection**: Evaluates targets purely through lexical, syntactic, and structural analysis. Does not execute malicious JavaScript or download remote payloads.
- **Defanged Output**: Automatically defangs malicious URLs (`hxxps[://]...`) in console, JSON, and CEF output to prevent accidental analyst clicks.
- **SSRF Hardening**: Strictly validates and rejects loopback, RFC 1918 private, link-local, and cloud metadata IP destinations.
- **Explainable Scoring Model**: Provides a transparent 0-100 risk score with granular heuristic factor contributions.

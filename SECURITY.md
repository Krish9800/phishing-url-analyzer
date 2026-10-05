# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Defensive Design & Non-Execution Guarantee
The **Phishing URL Analyzer** is designed strictly for offline, safe, lexical inspection of untrusted URLs and hostnames.
- **Zero Execution**: The engine does NOT download remote payloads, render untrusted DOMs, or execute active client-side code.
- **Defanged Telemetry**: By default, analyzed hostnames and URLs emitted in reports, logs, and CEF streams are defanged (`hxxps[://]...`) to avoid accidental user interaction.
- **SSRF Prevention**: Any optional network lookups (DNS/WHOIS) block reserved/private IP address ranges (RFC 1918, RFC 3927, loopback, cloud metadata IPs).

## Reporting a Vulnerability

If you discover a security vulnerability within this project, please report it privately:

- **Email**: krish@example.com
- **Response Target**: Within 48 hours.

Please do not open public GitHub issues for security disclosures.

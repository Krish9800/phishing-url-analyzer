# Threat Model & Risk Analysis — Phishing URL Analyzer

## 1. System Scope & Boundaries
The Phishing URL Analyzer operates strictly as an offline static analysis engine. It receives untrusted URL strings submitted by users, mail gateways, or SOAR automated workflows, decomposes them into structural tokens, and outputs threat classifications.

---

## 2. STRIDE Threat Matrix

| Threat Category | Potential Attack Vector | Defensive Countermeasure & Mitigation |
| :--- | :--- | :--- |
| **Spoofing** | IDN Homoglyph attack spoofing trusted financial/tech brands via Cyrillic/Greek Unicode lookalikes | `HomoglyphDetector` decodes Punycode labels and normalizes Unicode confusables to Latin equivalents before brand matching. |
| **Tampering** | Attacker injects malformed URL with authority masking (`user:pass@legit@evil.com`) | `LexicalDetector` flags embedded `@` credentials and extracts true authoritative host. |
| **Repudiation** | Lack of structured audit logging for incident response investigation | Standardized output supporting machine-readable JSON and ArcSight CEF syslog formats with UTC timestamps. |
| **Information Disclosure** | Analyzer makes outbound HTTP calls leaking SOC analyst IP or triggering canary tokens | **Strict offline policy:** Zero network sockets, zero DNS queries, and zero HTTP requests are initiated. Analysis is purely lexical. |
| **Denial of Service** | Regular Expression Denial of Service (ReDoS) or memory exhaustion via 10,000+ char input strings | Non-backtracking linear regexes, maximum batch payload caps (200 URLs), and input length validation limits. |
| **Elevation of Privilege** | Container breakout or local process execution vulnerabilities | Rootless Docker user (`phishuser:10001`), `read_only: true` filesystem, and `no-new-privileges: true` runtime security options. |

---

## 3. Threat Actors & Evasion Vectors

### 3.1 Dword and Hexadecimal IP Masking
- **Attacker Goal:** Bypass perimeter URL blocklists that look for decimal dotted-quad patterns (`192.168.1.1`).
- **Engine Defense:** Resolves integer Dwords (`http://2130706433`), octals (`http://0177.0.0.1`), and hex notation (`http://0x7f000001`) into normalized IP representations.

### 3.2 Server-Side Request Forgery (SSRF) Vectors
- **Attacker Goal:** Coerce downstream services into retrieving internal microservices or cloud metadata endpoints (`169.254.169.254`).
- **Engine Defense:** Evaluates parsed IP against RFC 1918, RFC 3927 (link-local), and loopback ranges, flagging `PRIVATE_IP_SSRF_RISK` at CRITICAL severity.

### 3.3 Subdomain Stuffing & Authority Masking
- **Attacker Goal:** Exploit mobile browser URL truncation by embedding legitimate brands in deep subdomains (e.g. `paypal.com.verify.identity.portal.attacker.com`).
- **Engine Defense:** Decomposes multi-level subdomain hierarchies, checks two-part TLD tables, and triggers `BRAND_IN_SUBDOMAIN` and `SUBDOMAIN_STUFFING` alerts.

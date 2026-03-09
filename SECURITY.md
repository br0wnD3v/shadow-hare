# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Shadowhare, please report it
responsibly. **Do not open a public issue.**

Email: security@shadowhare.dev (or open a private GitHub Security Advisory)

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We aim to acknowledge reports within 48 hours and provide a fix timeline
within 7 days.

## Scope

This policy covers:
- **False negatives**: detectors that fail to flag known vulnerability patterns
- **Crashes / panics**: inputs that cause Shadowhare to panic or hang
- **Malicious Sierra input**: crafted JSON that causes unbounded memory or CPU

Out of scope:
- Feature requests or enhancement suggestions (use GitHub Issues)
- Vulnerabilities in analyzed contracts (report those to the contract author)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

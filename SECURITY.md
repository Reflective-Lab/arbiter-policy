# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Report through [GitHub Security Advisories](https://github.com/Reflective-Lab/arbiter/security/advisories/new) or by emailing **Kenneth Pernyer** at [kenneth@reflective.se](mailto:kenneth@reflective.se).

You should receive a response within 48 hours.

## Built-in Security Practices

- `unsafe_code = "forbid"` across the workspace
- ed25519-signed delegation tokens with verifiable provenance
- Cedar policy engine for declarative authorization
- Regex-based data classification supporting PII redaction (email, SSN, credit card, phone)

## Shared Responsibility

arbiter is a Policy Decision Point. Operators are responsible for:

- Key management and rotation for the ed25519 signing keys
- Policy authoring, review, and version control
- TLS or upstream auth on the HTTP service surface
- Audit log retention for policy decisions
- Vetting third-party policies before loading

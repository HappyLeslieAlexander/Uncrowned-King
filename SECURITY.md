# Security Policy

Uncrowned King (UK) is a secure proxy protocol and implementation. We take
security issues seriously and appreciate coordinated disclosure.

## Supported versions

UK is pre-1.0 and developed in small, testable increments. Security fixes are
applied to the `main` branch and the latest tagged release. There is no support
commitment for older tags before 1.0.

| Version | Supported |
| --- | --- |
| `main` and latest tag | ✅ |
| older pre-1.0 tags | ❌ |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
("Report a vulnerability" under the repository's **Security** tab), which opens
a private advisory visible only to maintainers.

Please include:

- affected component (`uk-proto`, `uk-auth`, `uk-policy`, `uk-server`,
  `uk-client`) and version/commit,
- a description of the issue and its impact,
- reproduction steps or a proof of concept,
- any suggested remediation.

### What to expect

- **Acknowledgement** within 3 business days.
- **Initial assessment** (severity, affected versions) within 7 business days.
- **Fix and coordinated disclosure**: we aim to release a fix and publish a
  GitHub Security Advisory within 90 days, sooner for actively exploited
  issues. We will credit reporters who wish to be named.

## Scope

In scope — vulnerabilities in this repository's protocol design or
implementation, for example:

- authentication bypass, replay, or downgrade,
- policy-enforcement bypass (reaching a target the policy should deny,
  including private/reserved ranges or cloud metadata endpoints),
- memory-safety or panic-based denial of service reachable from untrusted
  input (the crates set `unsafe_code = "forbid"`; any `unsafe` reintroduction
  is itself in scope),
- resource-exhaustion beyond the configured limits,
- leakage of secrets (shared secrets, private keys) into logs, errors, or
  memory that outlives its need.

Out of scope:

- vulnerabilities in dependencies (report upstream; we track them via the
  RustSec audit and `cargo-deny` in CI),
- issues requiring a already-compromised host or a already-disclosed shared
  secret / private key,
- traffic-analysis / fingerprinting resistance, which UK does not claim to
  provide beyond the underlying TLS/QUIC transport (see
  [`docs/threat-model.md`](docs/threat-model.md)),
- operator misconfiguration explicitly warned against in the docs (for example,
  exposing the unauthenticated observability endpoint or a non-loopback SOCKS
  listener without network controls).

## Hardening references

- Threat model and residual risks: [`docs/threat-model.md`](docs/threat-model.md)
- Key and certificate lifecycle: [`docs/key-management.md`](docs/key-management.md)
- Protocol security requirements: [`docs/whitepaper.md`](docs/whitepaper.md) §16

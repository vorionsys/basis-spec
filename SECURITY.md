# Security Policy

## Reporting a vulnerability

Report security issues **privately** — not through public GitHub issues or discussions.

**Preferred:** use GitHub's private vulnerability reporting for this repository — open the **Security** tab → **Report a vulnerability**. This keeps the report, the maintainers, and any fix in one private thread.

**Alternative:** email **security@vorion.org**.

> The `security@vorion.org` inbox and the response timeframes below are a stated intent, **pending inbox and SLA verification** — they are not yet a contractual commitment. If you do not get an acknowledgment, please open a private GitHub vulnerability report as well.

Include:
- Affected package and version (`@vorionsys/basis-spec`, or a specific RFC / schema)
- Reproduction steps or a minimal test case
- Your assessment of severity and impact
- Whether you intend to disclose publicly, and on what timeline

**Target (not a guaranteed SLA):** acknowledge within 3 business days; confirm or refute within 14 days of acknowledgment.

## Scope

In-scope:
- Spec ambiguities, constant errors, or formula flaws that would lead conformant implementations into an insecure or incorrect posture
- Errors in the published **proof-event chain shape** or hash-chain rules that would make a conformant audit trail forgeable or non-tamper-evident
- Bugs in the Zod validators that would let a non-conformant artifact pass as conformant
- Schema flaws in `schemas/` that misrepresent what they claim to validate

Out-of-scope:
- Vulnerabilities in dependencies (report those upstream)
- Issues in runtimes, signing-key handling, or executors — **this repository ships no runtime and holds no keys**; report those against the implementation that does (e.g. the reference runtime in `vorionsys/basis-gate`, or a third-party implementation)
- Issues in products that consume this spec — report those to the respective product teams

## Supported versions

Until `@vorionsys/basis-spec` reaches v2.0.0, the current minor is supported through the next minor; there is no LTS commitment, and users on early versions should expect to upgrade. After a future major, we plan to support the current and previous minor with security fixes.

## Disclosure

We prefer coordinated disclosure. Once we acknowledge and have a fix in progress, we will agree on a public disclosure date. The reporter is credited unless anonymity is requested. If an issue is already being exploited in the wild, we may disclose immediately.

## Cryptography

This package defines the **shape** of the proof-event chain — Ed25519 signatures and SHA-256 hash linkage — but does not itself perform signing or implement primitives. If you find that the documented shape, canonicalization, or hash-chain rules permit forgery or replay, that is in scope. Flaws in a specific implementation's crypto belong to that implementation.

## PGP

Not offered at this time. GitHub private reporting or email is sufficient for our scale. If you require encrypted communication, ask and we will arrange it.

# Changelog

All notable changes to this repository are documented here. This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Repo-level — 2026-04-25

### Added
- **RFC-0003: Conformance Attestation v1** — defines the signed scorecard each BASIS-compliant product publishes at `https://<product>.example/attestations/<product>-<version>.json`. Decouples "we conform" from "trust us" by making the claim machine-verifiable.
- `schemas/attestation-v1.json` — strict JSON Schema for the attestation document. Anyone can validate any vendor's attestation file with stock Ajv, no Vorion tooling required.
- `schemas/README.md` — usage doc for the JSON Schema artifacts.

## [@basis-spec/basis@1.1.0] — 2026-04-25

### Added
- **RFC-0002: Proof Event Chain v1** — public spec for the shape of every audit event a BASIS-compliant runtime emits, plus the hash-chain semantics that make the trail tamper-evident.
- `proof-chain.ts` — canonical TypeScript types: `ProofEvent`, 10 typed payload variants + `GenericPayload` escape hatch, `ShadowModeStatus`, `ProofEventFilter`, `ChainVerificationResult`, `LogProofEventRequest`, `ProofEventSummary`. Timestamps as ISO 8601 strings for cross-language interop.
- `proof-chain-schema.ts` — Zod validators for all of the above. Importable from `@basis-spec/basis/zod`.
- Re-exported the new types from the package entry point and the new validators from `/zod`.

### Why
- Closes the public-trust verification gap: customer SOC teams + external auditors can now validate any vendor's audit log against the public schema without trusting vendor tooling.
- Decouples the audit-record SHAPE (public) from the cryptographic operations that produce it (proprietary). Runtimes stay competitive on impl quality; the contract anyone reads stays open.

### Notes
- This is a non-breaking minor bump. No existing exports changed; only new ones added.
- Companion RFC-0003 (Conformance Attestation) coming in the next release — defines the signed scorecard that proprietary impls publish per release.

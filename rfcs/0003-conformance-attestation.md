# RFC-0003: Conformance Attestation v1

**Status:** Draft
**Date:** 2026-04-25
**Author:** Vorion LLC
**Related:** RFC-0002 (Proof Event Chain), `@basis-spec/basis` proof-chain.ts, `schemas/attestation-v1.json`

---

## Summary

This RFC defines the **canonical signed scorecard** that a BASIS-compliant runtime publishes for each release. The scorecard records what conformance suite was run, what passed, what failed, and who signed off — so a buyer or auditor can verify a vendor's compliance claim without reading proprietary source code.

Together with RFC-0002 (the public shape of audit events) and the forthcoming `@basis-spec/basis-conformance` test suite, this is the third leg of public-trust verification:

1. RFC-0002 — what every event LOOKS like (the receipt format)
2. `basis-conformance` — what every implementation must DO (the test suite)
3. **RFC-0003 — what every release SAYS about its conformance (this document)**

A runtime claims BASIS conformance by publishing a signed attestation conforming to this RFC at a well-known URL on its own domain.

---

## Motivation

A buyer evaluating a closed-source AI governance product today has three options:

1. Trust the vendor's marketing claims. Weak.
2. Negotiate access to source under NDA. Slow, expensive, unscalable.
3. Hire an auditor to test the running system end-to-end. Slow, expensive, vendor-dependent.

The RFC-0003 attestation gives them a fourth option:

4. **Read the vendor's signed scorecard at `https://<product>.example/attestations/<product>-<version>.json`. Validate the signature against the vendor's published key. Run any failing tests yourself locally to confirm. Done in minutes.**

This is the same shape as `apt-get` package signatures, npm provenance attestations, Sigstore Cosign claims, and SOC 2 reports — but specific to AI governance conformance. The artifact is small, the signature is mechanical to verify, and the data is human-readable.

---

## The attestation document

A conformance attestation is a single JSON document. Full schema in `schemas/attestation-v1.json`. Required fields:

```jsonc
{
  // Spec version this attestation conforms to.
  "attestationVersion": 1,

  // The product being attested.
  "product": "Cognigate",
  "version": "0.1.0",
  "releasedAt": "2026-04-25T14:30:00Z",

  // The conformance suite the impl was tested against.
  "conformanceSuite": {
    "name": "@vorionsys/basis-conformance",
    "version": "0.1.0",
    // Git sha of the suite source — the exact code that produced these results.
    "revision": "1a2b3c4d5e6f...",
    // Optional: URL where the suite source lives.
    "source": "https://github.com/vorionsys/basis-conformance"
  },

  // Aggregate test results.
  "results": {
    "passed": 187,
    "failed": 0,
    "skipped": 3,
    "total": 190,
    // Per-test results. Required when failed > 0; recommended always.
    "details": [
      { "id": "tier-transition.t0-t1", "status": "passed", "durationMs": 12 },
      { "id": "hash-chain.linearity", "status": "passed", "durationMs": 47 },
      { "id": "shadow-mode.hitl-required", "status": "skipped", "reason": "feature flagged off in this release" }
    ]
  },

  // Detached Ed25519 signature over the canonical JSON of every other field.
  "signature": "base64url(64-byte-sig)",

  // Signer fingerprint or DID. Used to fetch the public key out-of-band.
  "signedBy": "did:web:vorion.org#release-signing-2026",

  // ISO 8601 of when the attestation was signed.
  "signedAt": "2026-04-25T14:35:00Z"
}
```

---

## Publication convention

Each Vorion product publishes attestations at a well-known URL on its own domain:

```
https://<product-domain>/attestations/<product>-<version>.json
```

Examples:

```
https://cognigate.dev/attestations/cognigate-0.1.0.json
https://agentanchorai.com/attestations/agentanchor-1.2.3.json
https://aurais.net/attestations/aurais-2.0.0.json
```

A `latest` redirect MAY also be served:

```
https://cognigate.dev/attestations/cognigate-latest.json
```

The product page MUST link to its attestation index (e.g., `https://cognigate.dev/attestations/`), and the page describing each release MUST link to that release's specific attestation.

---

## Signing procedure

1. **Compose the document** with all fields except `signature` populated.
2. **Canonicalize** to JSON per the same rules as RFC-0002 §"Canonical serialization": keys sorted ASCII, no whitespace, shortest decimal numbers, UTF-8 strings.
3. **Compute** Ed25519 signature over the canonical bytes using the runtime's release-signing key.
4. **Base64url-encode** the 64-byte signature (no padding).
5. **Set `signature`** to the base64url string.
6. **Compute `signedAt`** as the ISO 8601 of signing.
7. **Publish** at the canonical URL.

The signing key MUST be advertised somewhere fetchable (a `did:web` document, a `.well-known/keys.json` on the vendor's domain, or a transparency log entry). Verifiers fetch by `signedBy` to validate.

---

## Verification procedure

A consumer verifies an attestation by:

1. Fetching the attestation JSON from the canonical URL.
2. Validating the document against `schemas/attestation-v1.json`.
3. Fetching the signing public key by `signedBy` (out-of-band).
4. Re-canonicalizing the document with `signature` removed.
5. Verifying the Ed25519 signature over the recomputed canonical bytes.
6. (Optional) Checking the conformance suite revision against an expected version policy ("we only trust attestations against suite ≥ v0.5.0").
7. (Optional) Re-running any subset of tests locally against the running product to confirm — the suite is open source, the product endpoint is reachable, the results should reproduce.

---

## Revocation

If a passing attestation later proves wrong (a defect found after release), the vendor MUST publish a **revocation attestation** at the canonical URL replacing the original:

```jsonc
{
  "attestationVersion": 1,
  "product": "Cognigate",
  "version": "0.1.0",
  // ... all original fields ...
  "revoked": true,
  "revokedAt": "2026-05-12T09:00:00Z",
  "revokedReason": "CVE-2026-12345 — hash-chain linkage broken under concurrent writes",
  "supersededBy": "0.1.1",
  // signature recomputed over the new canonical bytes
  "signature": "...",
  "signedAt": "2026-05-12T09:01:00Z"
}
```

Consumers caching attestations MUST honor revocation. Publishers MAY also push to a transparency log to make revocation discoverable beyond the canonical URL.

---

## Third-party attestations

A second party (e.g., an external auditor, a customer's compliance team, a standards body) MAY publish their own attestation about a product. The shape is identical. The `signedBy` field carries the third party's identity instead of the vendor's:

```jsonc
{
  "product": "Cognigate",
  "version": "0.1.0",
  "conformanceSuite": { ... },
  "results": { "passed": 187, ... },
  "signature": "...",
  "signedBy": "did:web:trail-of-bits.com#auditor-key-2026",
  "signedAt": "2026-06-01T10:00:00Z",
  "thirdParty": true,
  "vendorAttestation": "https://cognigate.dev/attestations/cognigate-0.1.0.json"
}
```

Third-party attestations live at a URL of the third party's choosing (e.g., `https://trail-of-bits.com/audits/vorion-cognigate-0.1.0.json`) and SHOULD reference the vendor's original attestation for cross-checking.

This is the path to building an ecosystem of independent BASIS auditors over time — analogous to how SOC 2 auditors operate today, but with a machine-verifiable artifact instead of a PDF report.

---

## What conformance does NOT mean

A passing attestation says: "this version of this product passed this version of this suite at this point in time, signed by this entity." It does NOT claim:

- The product is bug-free.
- Future versions will pass.
- The conformance suite is exhaustive (it's a finite test set).
- Any business outcomes (security posture, regulatory compliance, etc.).

Conformance is a floor, not a ceiling. Buyers should treat it as one input alongside SOC 2, ISO 42001, security reviews, and operational track record.

---

## Backward compatibility

- `attestationVersion` is currently `1`. Future versions of this RFC MAY add new optional fields (non-breaking). Removing or repurposing fields requires `attestationVersion: 2` and a separate migration RFC.
- Verifiers MUST ignore unknown fields (forward compatibility). Producers SHOULD NOT emit fields not specified in the version they declare.

---

## Implementation references

- **JSON Schema:** `schemas/attestation-v1.json` in this repo. Anyone can `ajv compile` it and validate any attestation file.
- **Reference signing tool (forthcoming):** `npx @vorionsys/basis-conformance attest --product Cognigate --version 0.1.0 --suite-results suite-output.json --key release-signing.pem` will produce a valid signed attestation. Slated for the basis-conformance v0.1 release.
- **Reference verifier (forthcoming):** `npx @vorionsys/basis-conformance verify https://cognigate.dev/attestations/cognigate-0.1.0.json` will fetch + validate + signature-check + report. Same v0.1 release.

---

## Open questions

- **Transparency log integration.** Should attestations also be published to an append-only log (Sigstore Rekor, certificate transparency-style)? Useful for revocation discoverability; adds infrastructure dependency. Defer to v2 unless a concrete use case argues for it sooner.
- **Standardized test ID namespace.** `tier-transition.t0-t1` is illustrative — the basis-conformance test suite will fix the actual ID format. This RFC defers to the suite.
- **Multi-signature attestations.** A consortium attestation (multiple auditors co-signing) is plausible but out of scope here. Could ride on `details: [{signature, signedBy}, ...]` in v2.

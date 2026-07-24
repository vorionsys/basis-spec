# RFC-0004: Proof-Chain Hash-Suite Declaration & Convergence

**Status:** Draft
**Date:** 2026-07-23
**Author:** Vorion LLC
**Related:** RFC-0002 (Proof Event Chain), [vorionsys/basis-spec#17](https://github.com/vorionsys/basis-spec/issues/17), `@vorionsys/proof-plane`, `@vorionsys/aurais-core`, `@vorionsys/verify`, `@vorionsys/aurais-verify`

---

## Summary

Two proof-chain formats ship under the Vorion umbrella today, and a chain from
one family does not verify under the other family's verifier:

| Family | Hashing | Producers | Verifier |
|---|---|---|---|
| BASIS | SHA-256 + SHA3-256 (dual) | `proof-plane`, `gate-core`, `mcp-server` | `@vorionsys/verify` (`basis-verify`) |
| Aurais | SHA-256 (single) | `aurais-core` + the five `aurais-mcp-*` bots | `@vorionsys/aurais-verify` |

This RFC makes the hash suite an **explicit, declared property of the chain**
instead of an implicit property of whichever library produced it, and defines
the path to one verifier that checks both — eliminating the cross-implementation
verification failure that any independent evaluator currently hits.

The honesty framing matters: until convergence lands, the divergence is
documented in both producers' READMEs. This RFC exists so that the statement
"anyone can verify the chain" becomes true with **one tool**, regardless of
producer.

## Normative changes

### 1. `hashSuite` declaration (envelope level)

Every chain document (and each event envelope, for streamed contexts) MUST
declare its suite:

```json
{ "hashSuite": "sha256" }
{ "hashSuite": "sha256+sha3-256" }
```

- Absent `hashSuite` → verifiers MUST apply legacy detection (see §3) and
  MUST flag the chain as `suite: inferred` in the verification report.
- Unknown `hashSuite` values → verification FAILS closed.

### 2. Canonical serialization is shared

Both families already canonicalize JSON (sorted keys, no whitespace, shortest
decimals). RFC-0002 §"Canonical serialization" becomes the single normative
text for BOTH families. `aurais-core.canonicalJSON` and the proof-plane
canonicalizer MUST produce byte-identical output for identical values; the
conformance suite gains cross-family vectors proving it (§4).

### 3. One verifier

`@vorionsys/verify` learns both suites:

- `hashSuite` declared → verify with the declared suite.
- Not declared → detect: dual-hash events carry two digest fields; Aurais
  events carry `prev_hash` + `sig`/`pubkey`/`key_id` in the RFC'd shape.
- `@vorionsys/aurais-verify` becomes a thin delegation wrapper on parity
  proof, then deprecates with a pointer (same pattern as `basis` →
  `basis-spec`).

### 4. Golden vectors in the conformance suite

`@vorionsys/basis-spec-conformance` adds fixtures: one known-good and one
known-tampered chain **per suite**, produced by the real libraries. `run`
fails if `verify` mis-verifies any of the four.

## Acceptance criteria

- [ ] `hashSuite` field specified in RFC-0002 envelope (this RFC merged as its amendment)
- [ ] `aurais-core` emits `hashSuite: "sha256"`
- [ ] `proof-plane` emits `hashSuite: "sha256+sha3-256"`
- [ ] `@vorionsys/verify` validates golden chains from BOTH producers
- [ ] conformance suite ships the four cross-family vectors
- [ ] `aurais-verify` deprecated to a wrapper
- [ ] README divergence warnings replaced by convergence notes

## Non-goals

- Choosing a single hash suite for all producers. Dual-hash is a deliberate
  proof-plane property; single-hash is adequate for the Aurais bots' threat
  model. Declaration, not uniformity, is the fix.
- Retroactive re-hashing of existing chains. Legacy chains verify via §3
  detection, flagged `suite: inferred`.

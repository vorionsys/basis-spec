# RFC-0002: Proof Event Chain v1

**Status:** Draft
**Date:** 2026-04-25
**Author:** Vorion LLC
**Related:** `@basis-spec/basis` proof-chain.ts (types), proof-chain-schema.ts (Zod validators)

---

## Summary

This RFC defines the **canonical shape of every audit event a BASIS-compliant runtime emits**, plus the hash-chain semantics that make the audit trail tamper-evident. Together with RFC-0003 (Conformance Attestation), this is the substrate that lets a Fortune 500 CISO independently verify a Vorion-governed agent without reading proprietary source.

Implementations — open or commercial — MUST emit events that validate against `ProofEventSchema` from `@basis-spec/basis/zod`. They MAY add internal fields for their own runtime needs but MUST NOT change the meaning or constraints of the public fields.

---

## Motivation

Without a public proof-event contract, every claim of "BASIS-compliant" is unfalsifiable:

- A buyer can't compare two vendors' audit trails because they emit different shapes.
- An auditor can't verify a chain end-to-end without vendor-specific tooling.
- A regulator can't write a generic procurement clause ("agent governance MUST emit events conforming to BASIS RFC-0002").
- A customer's SOC team can't pipe events into their existing SIEM without per-vendor adapters.

The proof-chain is the receipt the customer takes to court. The shape of the receipt has to be public.

---

## Schema (canonical)

The full TypeScript shape is in `packages/basis/src/proof-chain.ts` and the Zod validators in `packages/basis/src/proof-chain-schema.ts`. Summary:

```ts
interface ProofEvent {
  eventId:        string;            // UUID, impl-assigned
  eventType:      ProofEventType;    // one of 10 canonical types (extensible via RFC)
  correlationId:  string;            // links related events end-to-end
  agentId?:       string;            // omitted for non-agent platform events
  payload:        ProofEventPayload; // typed union, structure varies by eventType
  previousHash:   string | null;     // sha256 hex, null for chain head
  eventHash:      string;            // sha256 hex of canonical serialization
  eventHash3?:    string;            // optional sha3-256 dual anchor
  occurredAt:     string;            // ISO 8601 — when it happened
  recordedAt:     string;            // ISO 8601 — when committed to chain
  signedBy?:      string;            // signer fingerprint / DID / runtime id
  signature?:     string;            // detached signature over eventHash
  shadowMode?:    'production' | 'shadow' | 'testnet' | 'verified' | 'rejected';
  verificationId?: string;           // HITL review id (required for shadow→verified|rejected)
  verifiedAt?:    string;            // ISO 8601 of HITL transition
}
```

The 10 canonical `eventType` values (lowercase, snake_case):

`intent_received`, `decision_made`, `trust_delta`, `execution_started`, `execution_completed`, `execution_failed`, `incident_detected`, `rollback_initiated`, `component_registered`, `component_updated`.

Each has a typed `payload` interface — see `proof-chain.ts` for the full set.

A `GenericPayload` escape hatch exists for forward-compatibility; new event types SHOULD migrate to a typed variant via RFC amendment.

---

## Hash-chain semantics

### Canonical serialization

To compute `eventHash`, the runtime serializes the event's hashable fields to a **canonical JSON string** with these rules:

1. Object keys sorted in ASCII-byte order.
2. Strings encoded as UTF-8, no escape variants beyond what JSON requires.
3. Numbers as the shortest decimal that round-trips exactly (no trailing zeros, no leading `+`, no exponent unless required).
4. No whitespace.
5. `null` values are serialized; `undefined` keys are omitted.

The hashable fields are `previousHash`, `eventType`, `agentId` (or empty string when absent), `occurredAt`, and `payload`. `eventId`, `recordedAt`, `signedBy`, `signature`, `eventHash`, `eventHash3`, and the shadow-mode trio are **excluded** from the hash input — they are computed or attached after the hash is sealed.

Concretely, the input string is:

```
{"agentId":"<...>","eventType":"<...>","occurredAt":"<...>","payload":<...>,"previousHash":"<...>"}
```

(keys sorted lexicographically; agentId is the empty string when absent; previousHash is the literal string `null` when there is no prior event).

### Hash computation

```
eventHash  = lowercase(hex(sha256(canonical_json_bytes)))
eventHash3 = lowercase(hex(sha3-256(canonical_json_bytes)))   ; optional
```

Both hashes are over the **same byte string**. Verifiers that recompute the hash MUST produce byte-identical results.

### Chain linkage

Each event's `previousHash` MUST equal the immediately prior event's `eventHash` for the same chain. The first event has `previousHash: null`.

The "chain" boundary is impl-defined (per-tenant, per-agent, per-correlationId — vendor's call). What's canonical is that **within whatever boundary the runtime chooses, events form a strictly linear hash chain**.

### Verification procedure

A conforming verifier:

1. Loads the events in order.
2. For each event, recomputes the canonical-JSON serialization, then sha256 (and sha3-256 when present).
3. Confirms the recomputed `eventHash` matches the stored `eventHash`.
4. Confirms `previousHash` equals the prior event's `eventHash`.
5. If a signature is present, fetches the signer's public key (out-of-band — runtime advertises its key set) and verifies the detached signature over the canonical bytes.
6. Returns `ChainVerificationResult` (also defined in this RFC) with `valid: true` only if every step passed for every event. On first failure, `brokenAt` is set to the event id where the chain broke.

---

## Dual-hash design rationale

Why both SHA-256 and SHA3-256?

- **SHA-256** is the universal primary. Required.
- **SHA3-256** is an optional integrity anchor. Recommended for chains that may need to verify past the SHA-256 security horizon (current academic consensus expects ~80-bit collision resistance to remain durable into the 2040s, but compliance audits asked decades hence may want belt-and-suspenders).

The two hashes commit to the **same byte string**, so adding `eventHash3` later does not change `eventHash`. Implementations can begin emitting `eventHash3` at any time without breaking past chain validation.

Verifiers SHOULD check both when present; MUST check at least the primary.

---

## Shadow-mode semantics for HITL integration

Events from sandbox (`T0_SANDBOX`) or testnet contexts are tagged `shadowMode: 'shadow'` (or `'testnet'`). They are recorded to the chain and counted toward chain integrity, but **excluded from production trust accounting** until a HITL review verifies them.

State transitions:

```
shadow ──(HITL approves)──▶ verified
shadow ──(HITL rejects)───▶ rejected
testnet ─(production-cut)─▶ verified
```

When `shadowMode` is `verified` or `rejected`, the event MUST set `verificationId` (the HITL review identifier) and `verifiedAt` (ISO 8601 of the review). The Zod validator enforces this.

This solves the chicken-and-egg problem of validating sandbox behavior: an agent can act in a low-stakes context, build a record, and have a human confirm the record before the score moves.

---

## Backward-compatibility rules

- **Adding a new optional field** to `ProofEvent` is a non-breaking change. Accepted in any minor version.
- **Adding a new `eventType` value with a new typed payload** is non-breaking. Accepted in any minor version. Past chains validate unchanged. Implementations that don't yet handle the new type SHOULD log it via `GenericPayload` rather than failing.
- **Removing or renaming** any field, payload, or event type is breaking. Requires a major version bump and a separate migration RFC.
- **Changing the canonical-serialization rules** is breaking — past chains stop verifying. Requires a major version bump, a migration RFC, and a versioned `serializationVersion` field on the chain head.

The current `serializationVersion` is implied as `1`. RFC-0002.1 (forthcoming if needed) will introduce explicit versioning before any breaking serialization change ships.

---

## Conformance requirements

A runtime claims RFC-0002 conformance by:

1. Emitting events whose JSON shape parses successfully against `ProofEventSchema`.
2. Computing `eventHash` per the canonical-serialization rules above.
3. Producing chains whose `ChainVerificationResult` from a generic verifier returns `valid: true`.
4. Honoring shadow-mode semantics (including the verificationId requirement).
5. (Optional but recommended) emitting `eventHash3` and `signature` so external auditors can verify integrity and provenance independently.

The RFC-0003 attestation format (companion document) describes how a runtime publishes signed evidence of conformance test results per release.

---

## Implementation references

- **Public reference impl (forthcoming):** `vorionsys/basis-conformance` will include a verifier that walks any chain and produces `ChainVerificationResult` per the rules above. The conformance test suite (also forthcoming) will validate that a runtime correctly seals, links, and signs a representative chain.
- **Vorion private impls** (`@vorionsys/proof-plane` and the audit-event subsystem of `cognigate-api`) emit events conforming to this RFC. The cryptographic operations (key management, batch sealing, Merkle tree commitments, TSA timestamping) are out of scope here — they are runtime business as long as the public output validates.

---

## Open questions

- **Multi-chain merge semantics.** When an agent moves between tenants or a correlation spans federated runtimes, how do separate chains merge? Out of v1; track for v2.
- **Chain pruning / archival.** Long-running runtimes will accumulate millions of events. Compaction strategies (Merkle root commitments + cold-storage tail) need a follow-up RFC.
- **Cross-runtime federation.** If two BASIS runtimes share a tenant, how do they coordinate `previousHash` to avoid forks? Today, "the chain" is per-runtime; a federation RFC would address this.

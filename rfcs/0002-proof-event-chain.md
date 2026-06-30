# RFC-0002: Proof Event Chain v1

**Status:** Draft
**Version:** 1.1 (RFC-0002.1 — adds signed in-chain risk; see Changelog)
**Date:** 2026-04-25 (v1.0); 2026-06-17 (v1.1)
**Author:** Vorion LLC
**Related:** `@vorionsys/basis-spec` proof-chain.ts (types), proof-chain-schema.ts (Zod validators)

---

## Summary

This RFC defines the **canonical shape of every audit event a BASIS-compliant runtime emits**, plus the hash-chain semantics that make the audit trail tamper-evident. Together with RFC-0003 (Conformance Attestation), this is the substrate that lets a Fortune 500 CISO independently verify a Vorion-governed agent without reading proprietary source.

Implementations — open or commercial — MUST emit events that validate against `ProofEventSchema` from `@vorionsys/basis-spec/zod`. They MAY add internal fields for their own runtime needs but MUST NOT change the meaning or constraints of the public fields.

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

## `intent_received` and signed in-chain risk (RFC-0002.1)

The `intent_received` payload records the action a governed agent is asking to perform:

```ts
interface IntentReceivedPayload {
  type:          'intent_received';
  intentId:      string;
  action:        string;            // human-readable description
  actionType:    string;            // free-form classifier (e.g. "db.write")
  resourceScope: string[];          // resources the action touches
  riskLevel?:    RiskLevel;         // RFC-0002.1 — OPTIONAL signed in-chain risk
}
```

`RiskLevel` is one of the canonical `RISK_LEVELS` keys: `READ`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `LIFE_CRITICAL`.

### Why risk belongs in the chain

Before RFC-0002.1, the action's **risk classification lived entirely outside the proof chain**. A scorer (e.g. `@vorionsys/basis-scorer`) had to take an action's risk from a caller-supplied `ScoringPolicy.riskByActionType` map — an **out-of-chain trust dependency**. Because risk drives the gain/loss magnitude (the risk multiplier in the canonical gain and loss formulas), whoever controlled that policy could under- or over-state how risky an action was, and the receipt could not prove what risk the operator actually assigned at the time the agent acted. The reference scorer surfaced this gap explicitly in its Limitations section.

RFC-0002.1 closes the gap by letting the operator/runtime **declare the action's risk at intent time** and seal it into the event:

- `riskLevel` lives inside `payload`, and `payload` is part of the **canonical-JSON hash input** (see Hash semantics below). It is therefore covered by `eventHash` / `eventHash3` and, when a `signature` is attached, **signed**. Once sealed it is tamper-evident: the risk an action was authorised at cannot be silently re-classified after the fact.
- Risk becomes **evidence**, not policy. A verifier reading the chain can see, per action, what risk the operator committed to.

### Precedence and back-compatibility

`riskLevel` is **OPTIONAL** so existing RFC-0002.0 chains (which never carried it) validate and score unchanged.

A conforming scorer resolves an action's risk with this precedence:

1. **In-chain (signed) takes precedence.** If `intent_received.riskLevel` is present and is a canonical `RISK_LEVELS` key, the scorer MUST use it and MUST NOT consult any caller policy for that action's risk.
2. **Policy fallback (deprecated, out-of-chain).** If `riskLevel` is absent, the scorer MAY fall back to the caller's `riskByActionType` mapping. This path is retained for back-compat with RFC-0002.0 chains and is explicitly the weaker, out-of-chain dependency described above.
3. **Fail-closed.** If neither resolves (no signed risk, no policy mapping, or a broken linkage), the scorer fails closed to the maximum configured risk (`LIFE_CRITICAL` by default).

Runtimes SHOULD emit `riskLevel` on every `intent_received` event going forward. New chains that omit it are valid but rely on the deprecated out-of-chain path for their risk integrity.

The reference scorer surfaces a per-outcome `riskSource` of `'chain' | 'policy' | 'failclosed'` so a consumer can audit exactly where each action's risk came from.

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

The current `serializationVersion` is implied as `1`. RFC-0002.1 adds the **optional** `intent_received.riskLevel` field (a non-breaking minor addition — see Changelog) and does **not** change the serialization rules: past chains verify byte-identically, because an absent optional field is simply omitted from the canonical-JSON input. A future RFC will introduce explicit `serializationVersion` before any *breaking* serialization change ships.

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

## Changelog

### v1.1 — RFC-0002.1 (2026-06-17): signed in-chain risk

- **Added** the OPTIONAL `riskLevel?: RiskLevel` field to the `intent_received` payload. Risk is now **SIGNED evidence**: the operator/runtime declares the action's risk at intent time, and because the field lives in `payload` it is part of the canonical-JSON hash input — covered by `eventHash` / `eventHash3` and by the event `signature` when present.
- **Motivation.** Risk drives the gain/loss multiplier. Before v1.1, a scorer obtained risk from a caller-supplied `ScoringPolicy.riskByActionType` map — an out-of-chain trust dependency controlled by the same party that asserts the agent's tier. v1.1 moves that integrity into the signed chain.
- **Precedence.** In-chain `riskLevel` **takes precedence** over the caller's policy mapping. The policy mapping becomes a **deprecated fallback** consulted only when an action carries no signed `riskLevel` (RFC-0002.0 chains). When neither resolves, scorers fail closed to maximum risk (`LIFE_CRITICAL`).
- **Back-compat.** The field is optional. Existing RFC-0002.0 chains validate and score **unchanged** (they take the deprecated policy fallback path). No serialization-rule change; this is a non-breaking minor addition per the Backward-compatibility rules above.
- **Reference impl.** `@vorionsys/basis-scorer` prefers in-chain risk and surfaces a per-outcome `riskSource` (`'chain' | 'policy' | 'failclosed'`) for attribution. The Zod validator (`proof-chain-schema.ts`) accepts the optional field, constrained to the canonical `RISK_LEVELS` keys.

---

## Open questions

- **Multi-chain merge semantics.** When an agent moves between tenants or a correlation spans federated runtimes, how do separate chains merge? Out of v1; track for v2.
- **Chain pruning / archival.** Long-running runtimes will accumulate millions of events. Compaction strategies (Merkle root commitments + cold-storage tail) need a follow-up RFC.
- **Cross-runtime federation.** If two BASIS runtimes share a tenant, how do they coordinate `previousHash` to avoid forks? Today, "the chain" is per-runtime; a federation RFC would address this.

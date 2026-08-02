# RFC-0005: Quorum Authorization Events v1

**Status:** Draft
**Version:** 1.0
**Date:** 2026-08-02
**Author:** Vorion LLC
**Related:** [RFC-0002](0002-proof-event-chain.md) (Proof Event Chain), [RFC-0003](0003-conformance-attestation.md) (Conformance Attestation), [RFC 9591](https://datatracker.ietf.org/doc/rfc9591/) (FROST), `@vorionsys/basis-spec-conformance` ≥ 0.2.0

> **Numbering note.** RFC-0004 is reserved for the vendor-endpoint conformance spec, already referenced in the published `@vorionsys/basis-spec-conformance` package (`src/index.ts`, README roadmap). This RFC takes 0005 to avoid invalidating that pointer.

---

## Summary

This RFC defines how a BASIS runtime records an action that required **more than one party to authorize it**, in a form a third party can verify.

It adds three event types to RFC-0002 — `quorum_requested`, `validator_vote`, `quorum_resolved` — and specifies a **two-record structure**:

1. The **aggregate threshold signature** proves *quorum authority* ("a valid m-of-n quorum authorized this").
2. The **individual validator votes**, each separately signed and chained, provide *attribution* ("these specific validators voted this way, and this one dissented").

Both records verify with the **existing** RFC-0002 verifier. No new signature type, no new verifier code path, no change to the RFC-0002 event schema.

---

## Motivation

RFC-0002 records what a single governed agent did. For high-consequence actions — irreversible data destruction, fund movement, production credential use — a single agent's authorization is the wrong trust unit, whether that agent is hijacked, prompt-injected, or simply wrong.

The natural answer is to require several independent parties to authorize before execution. But a naive implementation produces an audit trail that is *worse* than the single-agent case:

- The record says "approved" with no way to check that enough parties actually approved.
- A compromised coordinator can drop dissenting votes and present a clean unanimous result.
- Nobody can tell *which* parties authorized, so no party can be held accountable for a bad authorization.

This RFC makes the quorum itself **auditable evidence** rather than an internal implementation detail.

---

## Terminology, and what this is *not*

| Term | Meaning here |
|---|---|
| **Proposer** | The agent requesting a high-consequence action. |
| **Validator** | A party that independently evaluates the proposal and votes. |
| **Validator set** | The `n` validators asked to evaluate a given proposal. |
| **Threshold** (`m`) | Signatures required to authorize. |
| **Coordinator** | The component that distributes the proposal and collects votes. **Untrusted** — see Security considerations. |

**This is `m`-of-`n` threshold authorization with an ensemble judgment layer. It is NOT Byzantine fault-tolerant consensus**, and implementations MUST NOT describe it as such.

The distinction is load-bearing. pBFT's safety argument assumes honest replicas are **deterministic**: the same input produces the same output, which is what makes "matching signatures" meaningful. Validators that exercise judgment are **stochastic** — two honest validators can legitimately disagree about an identical proposal. The population is therefore not "`f` faulty plus `n−f` correct", but `n` noisy judges whose errors may be **correlated**. No liveness guarantee, no state-machine replication, and no partition tolerance is claimed or provided.

---

## The two-record structure

The central design constraint comes from a measured property of threshold signatures:

> **An aggregate threshold signature is subset-anonymous.** Every valid `m`-subset of the validator set produces a *different* signature that verifies under the *same* group public key. A verifier holding only the aggregate can confirm that a valid quorum signed — and cannot determine which members composed it.

*(Verified empirically 2026-08-02 against `@noble/curves` `ed25519_FROST`: all four valid 3-subsets of a 3-of-4 group produced distinct signatures, all verifying under one group key.)*

This is the intended cryptographic property, and it means **the aggregate alone cannot support validator accountability**. A record that carries only the aggregate destroys exactly the information needed to (a) detect a suppressed dissent and (b) adjust an individual validator's trust tier honestly.

Therefore a conforming runtime MUST emit **both**:

| Record | Event | Signed by | Answers |
|---|---|---|---|
| Aggregate | `quorum_resolved` | quorum **group** key (threshold signature) | "Was this authorized?" |
| Attribution | `validator_vote` (one per validator) | that **validator's own** key | "Who authorized it, and who objected?" |

Emitting only the aggregate is non-conforming.

---

## New event types

These extend the RFC-0002 `ProofEventType` set. Per RFC-0002 §"Backward-compatibility rules", adding new event types with new typed payloads is a **non-breaking minor addition**: existing chains validate unchanged, and implementations that do not yet handle these types SHOULD log them via `GenericPayload` rather than failing.

### `quorum_requested`

Emitted when policy escalates a proposed action to a quorum. MUST be chained **before** any vote.

```ts
interface QuorumRequestedPayload {
  type:          'quorum_requested';
  quorumId:      string;            // UUID, unique per authorization round
  intentId:      string;            // links to the intent_received being authorized
  policyId:      string;            // which policy escalated this
  threshold:     { m: number; n: number };
  /**
   * Every validator ASKED. Declaring the full set up front is what makes a
   * suppressed vote detectable — see Security considerations.
   */
  validatorSet:  Array<{
    validatorId:  string;           // stable identity; MUST match validator_vote.validatorId
    publicKey?:   string;           // Ed25519 key used to sign that validator's vote
    attributes?:  Record<string, string>;  // OPTIONAL, e.g. {"independence":"distinct-model-family"}
  }>;
  escalationReason: {
    riskLevel?:   RiskLevel;        // canonical RISK_LEVELS key
    proposerTier?: TrustTier;       // canonical T0–T7
    actionType?:  string;
  };
  deadline:      string;            // ISO 8601 — after this, the round MUST resolve as 'timeout'
}
```

`m` MUST satisfy `1 < m <= n`. A "quorum" of one is not a quorum; implementations MUST reject `m < 2`.

### `validator_vote`

One event per validator, **individually signed by that validator's own key** (`signedBy` = the validator's identity, `signature` = plain Ed25519 over the canonical bytes per RFC-0002 Erratum E-1).

```ts
interface ValidatorVotePayload {
  type:          'validator_vote';
  quorumId:      string;
  validatorId:   string;
  vote:          'approve' | 'reject' | 'abstain';
  rationale?:    string;            // human-readable; NOT machine-authoritative
  /**
   * OPTIONAL supporting signals. Recorded as EVIDENCE ONLY — see
   * §"Evidence is not proof". A verifier MUST NOT treat these as
   * independently checkable.
   */
  evidence?:     Array<{
    kind:        string;            // e.g. 'policy-check', 'static-analysis', 'classifier'
    source:      string;            // producing component identity
    version:     string;            // exact version — evidence without a version is unreproducible
    score?:      number;
    threshold?:  number;
    fired?:      boolean;
  }>;
  /**
   * OPTIONAL commit-reveal binding. When the runtime uses blind voting
   * (RECOMMENDED — see §"Tier feedback"), this is the hash the validator
   * published before any vote was revealed.
   */
  commitment?:   string;            // sha256 hex
  votedAt:       string;            // ISO 8601
}
```

### `quorum_resolved`

Emitted once per `quorumId`, after the round closes. Its **event signature is the aggregate**: `signedBy` = the quorum group key identity, `signature` = the threshold signature over the canonical bytes.

```ts
interface QuorumResolvedPayload {
  type:            'quorum_resolved';
  quorumId:        string;
  outcome:         'approved' | 'rejected' | 'timeout' | 'insufficient_quorum';
  threshold:       { m: number; n: number };
  tally:           {
    approve:       number;
    reject:        number;
    abstain:       number;
    noResponse:    number;
  };
  /**
   * eventIds of EVERY validator_vote chained for this quorumId. The four
   * tally counts MUST sum to `n`, and every validator in the declared
   * validatorSet MUST be accounted for here or counted in noResponse.
   */
  votesRecorded:   string[];
  /** Validators from the set that never responded. */
  noResponders?:   string[];
  signatureScheme: string;          // e.g. 'FROST-ED25519-SHA512-v1'
  groupPublicKey:  string;          // the key the aggregate verifies under
  resolvedAt:      string;          // ISO 8601
}
```

An `approved` outcome MUST NOT be emitted unless `tally.approve >= m`. When `outcome` is anything other than `approved`, the proposed action MUST NOT execute.

---

## Signature semantics

The aggregate is produced with a threshold signature scheme whose output is a **standard Ed25519 signature**. **FROST** ([RFC 9591](https://datatracker.ietf.org/doc/rfc9591/)), ciphersuite `FROST-ED25519-SHA512-v1`, is the REQUIRED default.

This choice is deliberate and consequential:

- A FROST aggregate is a 64-byte Ed25519 signature verifying under a 32-byte group public key.
- It therefore verifies with the **already-shipped** RFC-0002 verifier — `verifyChain()` / `basis-conformance verify` — with **zero modifications**.
- An auditor verifies a quorum-authorized action with the *exact same command* as a single-agent one.

*Verified 2026-08-02:* a 3-of-4 FROST group (real distributed key generation, no trusted dealer) signed a live `intent_received` event; the aggregate verified under stock `node:crypto` Ed25519 and under `basis-conformance verify --require-signatures` (`valid: true`, `signaturesValid: 2`, exit 0), with no changes to the verifier.

Implementations MAY offer other schemes, but a scheme whose output does not verify as standard Ed25519 (e.g. BLS) requires a new signature type and a new verifier path, and MUST NOT be the default.

### The aggregate attests the record, not the approval

This distinction is easy to get wrong and has a security consequence.

The aggregate signature on `quorum_resolved` attests **"a quorum agrees this is the accurate resolution of this round."** It does *not* mean "a quorum approved the action." Those are separate acts:

| Act | Recorded by | Meaning |
|---|---|---|
| Voting on the action | `validator_vote`, individually signed | "I approve / reject / abstain on this action" |
| Attesting the resolution | `quorum_resolved`, aggregate-signed | "I agree this is what the round decided" |

Consequently **a `quorum_resolved` event MUST carry an aggregate signature regardless of outcome** — including `rejected`, `timeout`, and `insufficient_quorum`. Validators that voted `reject` participate in signing the resolution; signing it attests to the accuracy of the tally, not agreement with the action.

Requiring the aggregate only on approval would be a serious weakness: a rejection is precisely the record a malicious coordinator has the strongest motive to forge or suppress, and leaving it unsigned would make the *denial* of a dangerous action the least protected event in the chain.

Where fewer than `m` validators respond at all, no aggregate can be produced. The round MUST then resolve as `insufficient_quorum`, the event MUST be signed by whatever authority the runtime can offer (typically the runtime's own key, `signedBy` naming it), and the payload MUST record that no quorum attestation was obtainable. Such an event is verifiable as a record but MUST NOT be presented as quorum-attested.

**Key generation.** The group key SHOULD be produced by distributed key generation so that no single party — including the coordinator — ever holds the group private key. Trusted-dealer generation (RFC 9591 Appendix C) is permitted for testing and MUST be recorded as such; a runtime using trusted-dealer generation in production MUST disclose it in its RFC-0003 attestation.

**Nonces.** FROST round-one commitments are one-time-use. Reuse across signing sessions leaks key material. Implementations MUST NOT reuse a nonce package.

---

## Verification procedure

A conforming verifier, given a chain containing a quorum round:

1. Verify the chain itself per RFC-0002 §"Verification procedure" — hashes, linkage, signatures. This alone establishes that no record was altered.
2. Locate the `quorum_requested` for the `quorumId` and read the declared `validatorSet` and `threshold`.
3. Collect every `validator_vote` with that `quorumId`. For each, verify its signature against the **validator's own** public key (from `validatorSet[].publicKey` or an out-of-band registry).
4. Verify the `quorum_resolved` event's aggregate signature against `groupPublicKey`.
5. **Recompute the tally from the chained votes** and confirm it matches `tally`.
6. Confirm `votesRecorded` ∪ `noResponders` accounts for **every** member of `validatorSet`.
7. Confirm `outcome` is consistent with the tally and threshold (`approved` ⟹ `approve >= m`).
8. Confirm every vote's `votedAt` precedes `resolvedAt`, and that `resolvedAt` precedes `deadline` unless `outcome` is `timeout`.

Any mismatch is a verification failure. In particular, a `tally` that does not match the chained votes, or a validator set member neither voted nor listed as a non-responder, indicates **vote suppression** and MUST fail.

---

## Evidence is not proof

`validator_vote.evidence` exists so that a validator's *reasoning inputs* are on the record. It is deliberately constrained.

A verifier **can** check: that a vote was cast, by whom, when, with what claimed supporting signals, and that the record was not altered afterward.

A verifier **cannot** check whether those signals were correct. An entry reporting a classifier score is not independently reproducible — reproducing it requires the model weights, the exact runtime, and the exact input state. It is a **claim recorded under signature**, not a verifiable fact.

Implementations MUST NOT present evidence entries as proof of an agent's intent, awareness, or internal state. "Our detector fired, and we chained that fact under signature" is supportable. "Our detector proves the agent was deceptive" is not, and publishing the latter converts a verifiable system into an unfalsifiable claim.

Every evidence entry MUST carry a `version`. Evidence whose producing component cannot be identified and versioned is not evidence; it is an assertion.

---

## Tier feedback

A resolved quorum SHOULD adjust trust scores using the canonical formulas in `@vorionsys/basis-spec` (`calculateGain`, `calculateLoss`, `penaltyRatio`), with the action's risk taken from the in-chain signed `riskLevel` per RFC-0002.1.

### Proposer

A proposer whose actions are repeatedly rejected by quorum SHOULD lose trust, applying `calculateLoss` with the in-chain risk. Existing hysteresis and promotion-delay rules apply unchanged; a single rejection MUST NOT by itself move a tier.

### Validators — scoring rules

Validator scoring is where this design is easiest to get wrong, so the rules are normative.

**Validators MUST NOT be scored on agreement with the quorum majority.**

Rewarding agreement with the majority creates herding: validators learn to predict consensus rather than judge independently. That collapses the very decorrelation a diverse validator set exists to provide, converging the set toward a single effective opinion and restoring the correlated blind spot the design was meant to eliminate. A validator set optimized for agreement is a validator set with `f = n`.

Instead:

- Validators SHOULD be scored against **ground truth resolved later** — did an approved action cause an incident (`incident_detected`, `rollback_initiated`)? Was a rejected action subsequently shown to be harmful or benign?
- Scoring SHOULD reward **calibration** (being right when confident, uncertain when uncertain), not conformity.
- A validator that correctly dissents against a wrong majority MUST be capable of *gaining* trust.

**Voting SHOULD be blind.** A validator MUST NOT be shown other validators' votes for the same `quorumId` before submitting its own. Where the coordinator cannot be trusted to enforce this, implementations SHOULD use commit-reveal via the `commitment` field: each validator publishes `sha256(canonical(vote))` first, and votes are revealed only after all commitments are collected.

---

## Fail-closed requirements

Consistent with the rest of BASIS:

1. **No quorum, no execution.** `timeout`, `insufficient_quorum`, or an unreachable validator set MUST deny the action. Unavailability is never an implicit approval.
2. **A vote that cannot be verified is not a vote.** A `validator_vote` whose signature does not verify MUST NOT count toward the tally and MUST be recorded as such.
3. **An incomplete round never resolves as `approved`.** If any validator in the declared set is neither recorded nor listed as a non-responder, the round is malformed and MUST fail verification.
4. **`m < 2` is rejected at policy load**, not at runtime.
5. **An empty or single-member validator set is not a quorum** and MUST be rejected.

Implementers should note the cost this imposes: an unavailable validator set denies legitimate actions. That is the intended trade, and it MUST be stated plainly in any operator-facing documentation rather than tuned away silently.

---

## Security considerations

### The coordinator is untrusted

The coordinator routes proposals, collects votes, and assembles the aggregate. A design in which it is also *trusted* concentrates authority more tightly than the single gate it replaces. It MUST NOT be trusted, and the following are what make that true:

- **Vote binding.** Each validator signs over canonical bytes that include the `quorumId`, the intent's `previousHash` linkage, and `votedAt`. A coordinator cannot re-scope a vote to a different action or replay it into a later round.
- **Target-side verification.** The system executing the action SHOULD verify the aggregate itself rather than trusting the coordinator's assertion that a quorum was reached.
- **Suppression detection.** Because `quorum_requested` declares the full validator set and `quorum_resolved` MUST account for every member, a coordinator that silently drops a dissenting vote produces a chain that fails verification step 6.
- **Independent publication.** Validators SHOULD retain their signed votes and MAY publish them independently. A validator-signed vote that does not appear in the chain is direct evidence of suppression — this works precisely because the vote is signed by the validator's own key, not the group key.

### Deadline and replay

`deadline` bounds the round. Verifiers MUST reject votes recorded after `resolvedAt` and rounds resolved after `deadline` with an outcome other than `timeout`.

### Group key rotation and compromise

Compromise of `m` validator shares compromises the quorum. Rotation requires a new distributed key generation and therefore a new group public key; the transition MUST be recorded on-chain (`component_updated`) so an auditor can tell which key was authoritative for a given event's `occurredAt`. Chains signed under a retired group key remain verifiable against that key — the historical record does not become invalid because the key rotated.

### Validator independence is an assumption, not a guarantee

A diverse validator set is intended to prevent one exploit from compromising the whole quorum. That intent rests on an **empirical** assumption: that validators built on different foundations do not share the relevant blind spots.

That assumption is known to be imperfect. Adversarial inputs transfer across systems trained on overlapping data with similar methods. Implementations claiming independence SHOULD **measure** transfer rate across their actual validator set and publish the result, and MUST NOT assert independence as a design property. The `validatorSet[].attributes` field exists to record the claimed basis for independence so an auditor can assess it; it does not establish it.

### Availability

Requiring a quorum introduces a denial-of-service surface: an adversary who can reliably induce rejections or prevent responses can halt legitimate high-value work. Because the system fails closed, this is an availability attack, not a safety failure — but it is real and MUST be documented in operator guidance.

---

## What this RFC does not provide

Stated plainly, because a governance standard that overstates its guarantees is worse than none:

- **Not Byzantine consensus.** No liveness, no partition tolerance, no state-machine replication.
- **No guarantee that the decision was correct.** Threshold cryptography proves `m` parties signed. It says nothing about whether their judgment was right. A quorum can be unanimously, verifiably wrong.
- **No protection against a colluding quorum.** If `m` validators collude or are jointly compromised, they produce a perfectly valid authorization. The record will be accurate and the outcome will be bad.
- **No attribution from the aggregate alone.** Attribution comes from the chained `validator_vote` events, which is why they are mandatory.
- **No third-party verifiability of evidence entries.** See §"Evidence is not proof".
- **No latency guarantee.** A quorum round is bounded by the slowest validator. Where validators perform model inference, rounds are measured in seconds, not milliseconds — orders of magnitude above a single-party policy check. Quorum is intended for **rare, high-consequence actions**, and policy SHOULD scope it accordingly (e.g. `CRITICAL`/`LIFE_CRITICAL` risk, or high-tier destructive `actionType`s). Implementations MUST NOT characterize the quorum path as low-latency.

---

## Backward compatibility

- Adds three `eventType` values with new typed payloads — a **non-breaking minor addition** under RFC-0002 §"Backward-compatibility rules". Pre-existing chains validate byte-identically.
- **No change to the RFC-0002 event schema.** `signedBy` carries a group key identity as ordinarily as it carries a single-signer identity; `signature` carries a 64-byte Ed25519 signature either way.
- **No change to canonical serialization.** Hashes over existing chains are unaffected.
- Verifiers that do not implement this RFC will still verify the chain's integrity (hashes, linkage, signatures) and will treat the new payloads as `GenericPayload`. They will not perform the tally and set-accounting checks in §"Verification procedure" steps 5–7, and therefore MUST NOT report quorum conformance.

---

## Conformance requirements

A runtime claims RFC-0005 conformance by:

1. Emitting `quorum_requested` before any vote, with a complete `validatorSet` and `threshold`.
2. Emitting one `validator_vote` per responding validator, each signed by **that validator's own key**.
3. Emitting exactly one `quorum_resolved` per `quorumId`, signed by the group key, with a tally that reconciles against the chained votes and accounts for every declared validator.
4. Never executing an action whose round did not resolve `approved` with `approve >= m`.
5. Honoring the fail-closed requirements above.
6. Scoring validators by outcome rather than by peer agreement.

---

## Open questions

- **Cross-runtime quorums.** When validators belong to different operators, whose chain records the round? Related to RFC-0002's open "cross-runtime federation" question; out of scope for v1.
- **Weighted quorums.** Should a higher-tier validator's vote count for more? Attractive, but it reintroduces a single-point dependency at the top tier and interacts badly with the anti-herding rules. Deferred.
- **Delegation.** Can a validator delegate its share? FROST supports resharing; the governance semantics (does the tier follow the share?) are unresolved.
- **Evidence schema registry.** `evidence[].kind` is currently free-form. A registry would improve comparability but risks implying that registered evidence kinds are verifiable, which they are not.
- **Quorum-of-quorums.** Nesting for extremely high-consequence actions. No demand identified yet.

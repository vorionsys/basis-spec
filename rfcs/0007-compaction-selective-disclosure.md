# RFC-0007: Chain Compaction and Selective Disclosure v1

**Status:** Draft
**Version:** 1.0
**Date:** 2026-08-02
**Author:** Vorion LLC
**Related:** [RFC-0002](0002-proof-event-chain.md) (Proof Event Chain), [RFC-0003](0003-conformance-attestation.md) (Conformance Attestation), [RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962) (Certificate Transparency — Merkle construction)

> Closes the RFC-0002 open question *"Chain pruning / archival… Compaction strategies (Merkle root commitments + cold-storage tail) need a follow-up RFC."*

---

## Summary

A long-running runtime accumulates millions of proof events. This RFC defines how a range of them collapses into a single signed **Merkle root**, and how an operator then proves that a specific decision sits under that root **without disclosing the rest of the range**.

It adds two event types — `chain_compacted` and `disclosure_issued` — plus a canonical Merkle construction and an audit-path proof format.

Everything here is built from primitives already in use: SHA-256 and the Ed25519 signatures RFC-0002 already carries. **No trusted setup, no pairing-friendly curves, no new cryptographic assumptions.** A third party verifies a disclosure offline with a public key and the proof package.

---

## The constraint that shapes this entire design

**Compaction cannot rewrite the chain. Not "should not" — cannot.**

RFC-0002 puts `previousHash` inside the canonical hash input. Re-pointing an event at a different parent therefore changes that event's own `eventHash`, which invalidates every event after it. This was verified empirically when the reference verifier was built: a chain with re-pointed linkage fails on *both* the linkage check and the hash check, because the two are not independent.

That property is the entire tamper-evidence guarantee. So compaction is **strictly append-only**: it adds an event attesting to a range that already exists. It never removes, rewrites, or re-links anything. The original events may then move to cold storage — but the chain that remains is unchanged, not edited.

The consequence has to be stated plainly rather than buried, because it is the real cost:

> **Compaction trades full-chain verification for root-attested membership.** A verifier holding the underlying events verifies everything, exactly as today. A verifier holding only the compacted form verifies the root signature and membership proofs — and **cannot** verify the hash linkage of the elided events, because it does not have them.

That is not a flaw to be engineered away. It is what "we no longer store these" means, said out loud.

---

## Verification levels

Because two verifiers holding different data can both be correct while reaching different conclusions, a conforming verifier MUST report **which level it achieved**. Returning a bare `valid: true` without the level is misleading and is non-conforming.

| Level | Verifier holds | Establishes |
|---|---|---|
| `full` | every event in the range | hashes, linkage, and signatures across the whole range — the RFC-0002 guarantee, undiminished |
| `attested` | the `chain_compacted` event, plus disclosed leaves and their audit paths | the root is validly signed, and the disclosed events sit under it. **Says nothing about undisclosed events beyond their count.** |
| `none` | insufficient data | nothing. Not a pass. |

A verifier that finds a compaction event for a range it also holds in full MUST verify **both** — the root it recomputes from the events must equal the root the compaction event attests. A mismatch means the compaction event is lying about what it summarizes, and MUST fail.

---

## Canonical Merkle construction

Interoperability requires that two implementations build the identical tree from the identical events. Two details below are not stylistic; getting either wrong produces distinct trees that share a root, which breaks the security property.

### Leaves

Leaves are the events of the range **in chain order**. Not sorted — chain order carries meaning, and re-ordering would let a compactor present a different sequence under the same root.

```
leaf(e) = SHA-256( 0x00 || canonical_event_bytes(e) )
```

`canonical_event_bytes` is exactly RFC-0002 §"Canonical serialization" — the same bytes `eventHash` is computed over, so a leaf is derivable from the event alone with no extra state.

### Internal nodes

```
node(L, R) = SHA-256( 0x01 || L || R )
```

**The `0x00` / `0x01` domain separators are mandatory.** Without them a leaf hash and an internal-node hash are drawn from the same space, and an attacker can present an internal node as though it were a leaf — the classic Merkle second-preimage attack. RFC 6962 uses this construction for the same reason.

### Odd nodes are PROMOTED, never duplicated

When a level has an odd number of nodes, the final node is **promoted unchanged to the next level**.

It MUST NOT be duplicated and paired with itself. Duplication makes two *different* leaf sequences produce the *same* root — the defect behind Bitcoin's CVE-2012-2459 — which would let a compactor swap the contents of a range while keeping its attested root.

### Empty and single-leaf ranges

A zero-leaf range has no root and MUST be rejected: there is nothing to attest, and an empty compaction is indistinguishable from a suppressed range. A single-leaf range has `root = leaf(e0)`.

---

## Events

Both extend the RFC-0002 set. Per RFC-0002 §"Backward-compatibility rules", new event types with new typed payloads are a **non-breaking minor addition**.

### `chain_compacted`

Appended at the chain tail. Attests that a contiguous, already-chained range has the given Merkle root.

```ts
interface ChainCompactedPayload {
  type:            'chain_compacted';
  compactionId:    string;
  /** Merkle root over the range, lowercase hex. */
  merkleRoot:      string;
  /** Inclusive range boundaries, by eventId. */
  firstEventId:    string;
  lastEventId:     string;
  /** Number of leaves. Required — a root without a count is unauditable. */
  leafCount:       number;
  /**
   * Anchors that let a holder of the underlying data re-attach the segment:
   * the `previousHash` of the first event, and the `eventHash` of the last.
   */
  rangePreviousHash: string | null;
  rangeEventHash:    string;
  /** Where the elided events went, when they were retained. */
  archiveUri?:     string;
  /** Whether leaves were salted (see "Residual disclosure"). */
  salted:          boolean;
  compactedAt:     string;
}
```

The event MUST be signed. An unsigned `chain_compacted` is not a compaction — it is an unattributed assertion that some range had some root, which is worth nothing.

### `disclosure_issued`

Issuing a disclosure is itself an auditable act. It is chained so an operator can later answer *"what did we hand to whom, and when?"* — a question that comes up in exactly the proceedings this system exists to serve.

```ts
interface DisclosureIssuedPayload {
  type:            'disclosure_issued';
  disclosureId:    string;
  compactionId:    string;
  /** eventIds disclosed. The recipient sees these; this records that. */
  disclosedEventIds: string[];
  /** Free-text recipient identifier, e.g. an auditor engagement id. */
  recipient?:      string;
  /** Why — retained for the operator's own record. */
  purpose?:        string;
  issuedAt:        string;
}
```

---

## Disclosure package

The artefact an operator hands over. Self-contained: verifiable with only this plus the signer's public key.

```ts
interface DisclosurePackage {
  disclosureVersion: 1;
  /** The compaction event verbatim, including its signature. */
  compaction:      ChainCompactedEvent;
  /** One entry per disclosed leaf. */
  disclosed: Array<{
    event:         ProofEvent;      // the full RFC-0002 event
    leafIndex:     number;          // position in chain order
    salt?:         string;          // required when compaction.salted
    /** Audit path from leaf to root, ordered leaf-upward. */
    path: Array<{ hash: string; side: 'left' | 'right' }>;
  }>;
  /** Signer identity → public key, so verification needs nothing external. */
  keys:            Record<string, string>;
}
```

### Verification procedure

1. Verify the `compaction` event as an ordinary RFC-0002 event — recompute its `eventHash`, check its signature. If this fails, stop; nothing else is meaningful.
2. For each disclosed entry: recompute `leaf(event)` (salted if applicable), fold the audit path, and confirm the result equals `compaction.payload.merkleRoot`.
3. Confirm each `leafIndex` is within `[0, leafCount)`.
4. Report `level: 'attested'`, the disclosed count, and `leafCount` — so the recipient can see how much of the range they were *not* shown.

Step 4 is not optional. A disclosure that reveals 3 of 40,000 events is a very different artefact from one revealing 3 of 4, and a verifier that hides the denominator is helping to mislead.

---

## Residual disclosure — what a proof still reveals

Selective disclosure is not concealment, and an operator handing one over deserves to know exactly what travels with it.

A disclosure package reveals:

- **The audit path hashes.** These are opaque, but they are stable identifiers for sibling subtrees. A recipient who receives two disclosures from the same range can tell which parts overlap.
- **`leafCount`** — how many events were in the range. Often this alone is informative (activity volume, deployment scale).
- **The leaf index** — roughly *when*, within the range, the disclosed event occurred.
- **Tree shape** — path length bounds the range size even without `leafCount`.
- **That the undisclosed events exist.** Their content is hidden; their existence and count are not.

Salting (`leaf(e) = SHA-256(0x00 || salt || canonical_event_bytes(e))`) breaks cross-range linkability of identical events at the cost of managing salts and disclosing them for disclosed leaves. It is **optional and default-off**: it adds operational burden and should be a deliberate choice, not a default nobody understands.

---

## Fail-closed requirements

1. **An unsigned or unverifiable compaction attests nothing.** Never report membership as verified against a root whose signature did not check.
2. **Root mismatch is fatal.** If a verifier holds the range in full and the recomputed root differs from the attested one, the compaction event is false and verification MUST fail — even though every individual event may be perfectly intact.
3. **A zero-leaf compaction is invalid.** Nothing to attest, and indistinguishable from a suppressed range.
4. **A verifier MUST report its level.** `attested` MUST NOT be presented as, or abbreviated to, the `full` guarantee.
5. **`leafCount` MUST accompany any disclosure.** A membership proof without the denominator invites a misleading reading.
6. **Compaction MUST NOT delete anything the retention obligation still covers.** This RFC defines the cryptographic form; it does not authorize discarding records the law requires you to keep.

---

## What this RFC does not provide

- **This is not zero-knowledge**, and implementations MUST NOT describe it as such. The recipient learns path hashes, range size, and leaf position. It is *selective disclosure*: a smaller, deliberate reveal — not the absence of one.
- **It does not prove the elided events were valid.** It proves they had this root. A range of perfectly-chained bad decisions compacts exactly as cleanly as a good one.
- **It does not reduce what you must retain for full verification.** Discard the events and `full` verification is gone permanently, for you as well as for everyone else.
- **It does not prove a range is complete.** A compaction attests to the events it covered. Proving no *further* events existed in that window is outside what a Merkle root can say.
- **It does not compress the chain's growth rate.** Compaction reduces what you *store*, not what you *emit*.

---

## Backward compatibility

- Adds two `eventType` values with new typed payloads — a **non-breaking minor addition**. Existing chains validate byte-identically.
- **No change to the RFC-0002 event schema or to canonical serialization.** Leaf hashing reuses `canonical_event_bytes` unchanged.
- A verifier that does not implement this RFC still verifies chain integrity and treats the new payloads as `GenericPayload`. It will not perform root or membership checks and MUST NOT report RFC-0007 conformance.
- **Chains that never compact are entirely unaffected.** This is opt-in.

---

## Conformance requirements

A runtime claims RFC-0007 conformance by:

1. Building trees per §"Canonical Merkle construction" — domain-separated leaves and nodes, chain order, odd nodes promoted rather than duplicated.
2. Signing every `chain_compacted` event, with `leafCount` and both range anchors.
3. Producing self-contained disclosure packages that verify offline against a public key alone.
4. Reporting a verification **level** on every result, never presenting `attested` as `full`.
5. Failing on root mismatch when the underlying range is held.
6. Chaining a `disclosure_issued` event for each package released.

---

## Open questions

- **Compaction of compactions.** A root over a range that itself contains compaction events is well-defined but the verification-level semantics compose awkwardly. Deferred.
- **Key rotation across compactions.** A root signed under a retired key must remain verifiable years later. RFC-0005 defers rotation generally; this inherits that gap and it is the more urgent of the two, because retention windows outlive keys.
- **Range-completeness proofs.** Proving "no other events existed in this window" needs an append-only log structure (consistency proofs, à la RFC 6962 §2.1.2), not just membership. A natural v2.
- **Predicate proofs** — proving "zero DENY events in this range" without disclosing leaves. Achievable for some predicates with sorted auxiliary trees; deliberately out of v1, which does membership only.
- **Salt custody.** If salts are lost, disclosed leaves can no longer be proved. Salt storage is currently the operator's problem and probably should not be.

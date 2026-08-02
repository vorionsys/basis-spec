# `@vorionsys/basis-merkle`

Public reference implementation of **[BASIS RFC-0007](../../rfcs/0007-compaction-selective-disclosure.md)** — chain compaction and Merkle selective disclosure.

A long-running runtime accumulates millions of proof events. This collapses a range into one **signed Merkle root**, then lets an operator prove a specific decision sits under that root **without disclosing the rest of the range**.

Built from SHA-256 and the Ed25519 signatures RFC-0002 already carries. **No trusted setup, no pairing-friendly curves, no new cryptographic assumptions.**

## Compaction is append-only — and cannot be otherwise

`previousHash` sits inside the RFC-0002 canonical hash input, so re-pointing an event changes its own `eventHash` and invalidates every event after it. The chain **cannot** be edited. That is the tamper-evidence guarantee working, not a limitation to route around.

So compaction *attests* to a range that already exists. It never removes, rewrites, or re-links.

**The cost, stated plainly:** compaction trades **full-chain verification** for **root-attested membership**. Discard the events and `full` verification is gone permanently — for you as well as for everyone else. That is what "we no longer store these" means, said out loud.

## Verification levels

Two verifiers holding different data can both be correct and reach different conclusions. So every result carries a level, and **reporting `valid` without it is non-conforming**:

| Level | Holder has | Establishes |
|---|---|---|
| `full` | every event in the range | hashes, linkage, signatures — the RFC-0002 guarantee, undiminished |
| `attested` | compaction event + disclosed leaves + paths | root validly signed, disclosed events sit under it. **Nothing about undisclosed events beyond their count.** |
| `none` | insufficient data | nothing. Not a pass. |

## Use

```ts
import {
  buildCompaction, buildDisclosure, verifyDisclosure, verifyAgainstRange,
} from '@vorionsys/basis-merkle';

// 1. Compact a contiguous chain segment. Does NOT sign — seal and sign the
//    payload into an RFC-0002 event yourself; an unsigned compaction attests
//    nothing.
const payload = buildCompaction({ compactionId, range, compactedAt });

// 2. Hand an auditor 3 of 40 events, with proofs.
const pkg = buildDisclosure({ compaction, range, disclose: ['e5','e17','e39'], keys });

// 3. They verify offline, with the package and a public key. Nothing else.
const r = verifyDisclosure(pkg);
// { valid: true, level: 'attested', disclosedCount: 3, leafCount: 40 }
```

`leafCount` is always reported next to `disclosedCount`, because **3-of-4 and 3-of-40,000 are very different artefacts** and a verifier that hides the denominator is helping to mislead.

If you still hold the events, cross-check the compaction against them:

```ts
verifyAgainstRange(compaction, range);  // → level: 'full'
```

A root mismatch here **must** fail even when every individual event is perfectly intact — that is precisely the check that catches a compactor swapping a range's contents.

## Two Merkle details that are security, not style

Both produce distinct leaf sequences that share a root, which would let a compactor swap a range's contents while keeping its attested root. Both have tests that pin them.

**1. Domain separators.** Leaves are `SHA-256(0x00 ‖ canonical_bytes)`, internal nodes `SHA-256(0x01 ‖ L ‖ R)`. Without the prefixes, leaf and node hashes share a space and an internal node can be presented as a leaf — the classic second-preimage attack. RFC 6962 does this for the same reason.

**2. Odd nodes are PROMOTED, never duplicated.** Duplicating the last odd node makes `[a,b,c]` and `[a,b,c,c]` produce an **identical** root — the defect behind Bitcoin's CVE-2012-2459. The test asserts the two roots differ *and* spells out the value the buggy construction would have produced, so a refactor that reintroduces duplication fails loudly.

Leaves are in **chain order**, not sorted — order carries meaning, and sorting would let a compactor present a different sequence under the same root.

## Residual disclosure — what a proof still reveals

Selective disclosure is not concealment. A package reveals:

- **Path hashes** — opaque, but stable identifiers for sibling subtrees, so two disclosures from the same range are correlatable.
- **`leafCount`** — how many events the range held. Often informative on its own.
- **Leaf index** — roughly *when*, within the range, the event occurred.
- **Tree shape** — path length bounds the range size even without the count.
- **That undisclosed events exist.** Their content is hidden; their existence and count are not.

Optional per-leaf salting breaks cross-range linkability of identical events, at the cost of managing salts. **Default-off**: it adds real operational burden and should be a deliberate choice, not a default nobody understands. A salt that is lost means that leaf can never be proved again — the library rejects a salted disclosure missing its salt rather than silently failing membership.

## What this does not provide

- **Not zero-knowledge**, and it must not be described as such. See residual disclosure above. It is a smaller, deliberate reveal — not the absence of one.
- **Not proof the elided events were valid.** It proves they had this root. A range of perfectly-chained bad decisions compacts exactly as cleanly as a good one.
- **Not a completeness proof.** It attests to the events it covered; proving no *further* events existed in that window needs consistency proofs (RFC 6962 §2.1.2), noted as a v2.
- **Not a reduction in emission.** It reduces what you *store*, not what you *emit*.
- **Not authorization to delete.** This defines the cryptographic form. It does not license discarding records a retention obligation still covers.

## A subtlety worth knowing

A leaf covers the **canonical bytes**, which RFC-0002 deliberately **excludes `eventId` from** (it is implementation-assigned). Two events differing only in `eventId` therefore produce the same leaf. Within a real chain this cannot collide, because `previousHash` differs — but a test fixture that varies only the id is not constructing a different range. There is a test documenting this, because it cost us one during development.

## License

Apache-2.0 — see [LICENSE](LICENSE).

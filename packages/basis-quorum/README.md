# `@vorionsys/basis-quorum`

Public reference implementation of **[BASIS RFC-0005](../../rfcs/0005-quorum-authorization.md)** — *m*-of-*n* threshold authorization for high-consequence agent actions.

When an agent proposes something irreversible — dropping a production table, moving funds, using a production credential — a single agent's authorization is the wrong trust unit, whether that agent is hijacked, prompt-injected, or simply wrong. This package makes the quorum that authorizes it **auditable evidence** rather than an internal implementation detail.

## The two-record structure

A quorum round produces two kinds of record, and **both are required**:

| Record | Signed by | Answers |
|---|---|---|
| `quorum_resolved` | quorum **group** key (FROST aggregate) | "Was this authorized?" |
| `validator_vote` × n | each validator's **own** key | "Who authorized it, and who objected?" |

This is not a stylistic choice. A threshold aggregate is **subset-anonymous**: every valid *m*-subset produces a *different* signature that verifies under the *same* group public key. So the aggregate proves a valid quorum signed and can never say **which members**. A record carrying only the aggregate structurally cannot detect a suppressed dissent or support honest per-validator tier movement.

**Emitting only the aggregate is non-conforming.**

## Why FROST

FROST ([RFC 9591](https://datatracker.ietf.org/doc/rfc9591/), `FROST-ED25519-SHA512-v1`) emits a **standard 64-byte Ed25519 signature** over a 32-byte group key. A quorum-authorized event therefore verifies with the stock RFC-0002 verifier — no new signature type, no new code path, no changes to `@vorionsys/basis-spec-conformance`.

An auditor verifies a quorum-authorized action with the **exact same command** as a single-agent one.

Key generation runs a real **distributed key generation** — no dealer, so no single party (including the coordinator) ever holds the group private key. That is the actual security claim; trusted-dealer generation does not provide it.

## Install

```bash
npm install @vorionsys/basis-quorum
```

## Running a round

```ts
import {
  createGroupViaDkg,
  createLocalValidator,
  runQuorumRound,
  buildKeyring,
} from '@vorionsys/basis-quorum';

const validatorIds = ['claude-validator', 'gemini-validator', 'grok-validator', 'policy-validator'];

const group = createGroupViaDkg({
  groupId: 'did:vorion:quorum:prod-destructive#frost-ed25519',
  validatorIds,
  m: 3,
});

const result = await runQuorumRound({
  group,
  validators,                       // your Validator implementations
  proposal: {
    quorumId, intentId,
    proposerAgentId: 'agent:proposer-01',
    action: 'DROP TABLE production.customer_ledger',
    actionType: 'db.schema.destructive',
    resourceScope: ['db:production.customer_ledger'],
    riskLevel: 'LIFE_CRITICAL',
  },
  policyId: 'basis_risk_thresholds:life_critical_requires_quorum',
  correlationId,
  deadline: '2026-08-02T14:00:30.000Z',
  now: () => new Date().toISOString(),
  nextEventId: () => crypto.randomUUID(),
  timeoutMs: 5_000,
});

// result.events is an RFC-0002 chain, ready to append to your proof plane.
```

## Verifying — both passes are required

```ts
// 1. INTEGRITY — hashes, linkage, signatures (RFC-0002)
import { verifyChain } from '@vorionsys/basis-spec-conformance';
const integrity = verifyChain(chain, { publicKeys: keyring, requireSignatures: true });

// 2. COHERENCE — tally, accounting, attribution, outcome (RFC-0005)
import { verifyQuorumRound } from '@vorionsys/basis-quorum';
const round = verifyQuorumRound(chain, quorumId);
```

**Passing (1) alone is not enough, and the shipped vectors prove it.** A coordinator that doctors a resolution can recompute its hash and re-attest it with the group key, producing a chain whose hashes, linkage and signatures are *all perfect*:

```bash
$ basis-conformance verify vectors/tamper-approved-below-threshold.json \
    --keys vectors/keys-rejected.json --require-signatures
# exit 0 — integrity is flawless

$ # verifyQuorumRound() → valid: false, code: "approved-below-threshold"
```

Nothing about the cryptography is wrong in that chain. It simply describes an approval that never happened. That is what the second pass is for.

### What `verifyQuorumRound()` checks

Beyond RFC-0005 §"Verification procedure" steps 5–8:

- **Tally reconciliation** — the declared tally must match the votes actually chained.
- **Validator-set accounting** — every declared member must have voted or be listed as a non-responder. *A dropped dissent looks exactly like a gap here.*
- **Attribution** — `signedBy` must equal the `validatorId` inside the payload. `verifyChain()` cannot do this: given a keyring containing both validators' keys, a vote from A signed with B's key verifies as a valid signature. Only the payload/signer comparison binds a vote to its author.
- **Outcome consistency** — `approved` requires `approve >= m`; only `insufficient_quorum` may be unattested.
- **Ordering and deadline** — votes fall between request and resolution; a resolution past its deadline must be a `timeout`.
- **Group signing** — the resolution must be signed by the group key, never by an individual member.

## Known limitation: suppression vs. silence

The chain **cannot distinguish a suppressed vote from a genuine non-response.** A coordinator that drops a dissent *and* relabels that validator as a non-responder produces an internally consistent record, and the accounting check passes.

The defence is not cryptographic, it is procedural: validators retain their signed votes and may publish them independently. **A validator-signed vote that does not appear in the chain is direct evidence of suppression** — which works precisely because votes are signed with the validator's own key rather than the group key.

The naive version — dropping the vote without relabelling — *is* caught, and `vectors/tamper-suppressed-dissent.json` pins that behaviour.

## Golden vectors

`vectors/` ships two valid rounds (approved, rejected-with-dissent) and four tampered variants. All deterministic — seeded DRBG, fixed key seeds, fixed clock — so regeneration is byte-identical and a diff means something actually changed.

`scripts/generate-vectors.mjs` carries its **own canonicalizer**, written from the RFC-0002 text rather than imported, and re-derives every `eventHash` with it. If the two implementations disagree, generation fails. Sharing the implementation would make the check circular.

```bash
npm run vectors   # regenerate
npm test          # 19 tests
```

## What this is not

- **Not Byzantine fault-tolerant consensus**, and it must not be described as such. pBFT's safety argument assumes honest replicas are *deterministic* — same input, same output — which is what makes "matching signatures" meaningful. Validators that exercise judgment are **stochastic** and can legitimately disagree. No liveness guarantee, no partition tolerance, no state-machine replication.
- **Not a guarantee the decision was correct.** Threshold cryptography proves *m* parties signed. It says nothing about whether their judgment was right. A quorum can be unanimously, verifiably wrong.
- **Not protection against a colluding quorum.** If *m* validators are jointly compromised, they produce a perfectly valid authorization.
- **Not low-latency.** A round is bounded by the slowest validator — seconds where validators perform model inference, orders of magnitude above a single-party policy check. Quorum is for rare, high-consequence actions; scope policy accordingly.
- **Not a source of verifiable evidence.** `ValidatorVotePayload.evidence` records a *claim under signature*. A verifier can confirm the entry was chained; it cannot confirm the signal was correct, because reproducing a classifier score would require the model weights, runtime, and input state.

## Validator independence

A diverse validator set is meant to stop one exploit from compromising the whole quorum. That rests on an **empirical** assumption: that validators built on different foundations do not share the relevant blind spots. Adversarial inputs are known to transfer across systems trained on overlapping data with similar methods.

**Measure transfer rate across your actual validator set and publish it. Do not assert independence as a design property.** `validatorSet[].attributes` records the *claimed* basis for independence so an auditor can assess it; recording a claim does not establish it.

Related: **correlated validators are one validator for threshold purposes.** Two instances of the same policy engine must not both count toward *m*, or the threshold is theatre.

## Event types and RFC status

RFC-0005 is **Draft**, so its three event types are not yet in the canonical `PROOF_EVENT_TYPES` union in `@vorionsys/basis-spec`. Practical consequence:

- `basis-conformance verify` — **unaffected.** It does not inspect event types.
- `basis-conformance validate` — will report `quorum_requested` / `validator_vote` / `quorum_resolved` as non-canonical, correctly, until the RFC is accepted.

## Determinism and the `rng` option

`createGroupViaDkg`, `aggregateAttestation` and `runQuorumRound` accept an optional `rng`. **It exists to make golden vectors byte-stable and must never be supplied in production** — FROST nonce reuse leaks key material, and a predictable DKG secret is not a secret. Leave it undefined and the library's cryptographically secure default is used.

## License

Apache-2.0 — see [LICENSE](LICENSE).

<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2024-2026 Vorion LLC -->

# @vorionsys/basis-registry

A reference **library of verifiable primitives** for the BASIS trust substrate.

It provides two cryptographic primitives so an identity and its history can be
checked **offline** — with no call to any server (including Vorion) and no DID
resolution:

1. **Self-certifying CAR identifier** — an id that is the hash of its own
   genesis object, so identity is forgery-resistant without an allocator.
2. **RFC-6962 append-only Merkle transparency log** — inclusion proofs,
   consistency proofs, and Signed Tree Heads, with leaf/interior domain
   separation for second-preimage resistance, plus split-view detection.

> **This is a LIBRARY, not a running registry.** It computes and verifies the
> math. It does **not** run a registry server, a witness cosigning network,
> gossip, the AgentAnchor dual-write, or federation/sovereign profiles. It is
> **not** "a decentralized registry" and is **not** "trustless" on its own.
> See [Honest scope](#honest-scope-what-this-is-and-is-not) below.

## Install

```sh
npm install @vorionsys/basis-registry
```

ESM, Node `>=18`. Only dependency: `@vorionsys/basis-spec` (for ecosystem type
alignment). All cryptography uses Node's built-in `crypto` — no heavy deps. A
minimal base58btc / multibase / multihash / RFC-8785 JCS is implemented
in-package, each with its own unit tests.

## The two primitives

### 1. Self-certifying CAR id

```ts
import { mint, verify, type CarGenesis } from '@vorionsys/basis-registry';

const genesis: CarGenesis = {
  idSpec: 'car/v1',
  specVersion: 'basis-spec@1.2.0+sha256:…',  // pinned TrustSpec version
  category: 'AGENT',
  controller: ['did:key:z6Mk…'],             // sorted, unique ed25519 did:key(s)
  registryRoot: 'z…',                         // issuing root PUBLIC key (multibase Multikey)
};

const id = mint(genesis, rootPublicKey);      // car:<registryRootFp>:v1:<idHash>
const r  = verify(id, genesis, rootPublicKey); // { valid: true } | { valid: false, reason }
```

Id grammar (5 ASCII fields, 4 colons):

```
car:<registryRootFp>:v1:<idHash>
```

- `registryRootFp` = `multibase('z', multihash(sha2-256, sha-256(rootMultikey)))`
  — a **full** sha-256 multihash (prefix `0x12 0x20`, **no truncation** — a
  truncated fingerprint would be a collision footgun for the namespace root).
  It depends **only** on the registry root public key, so two independently
  generated registries collide only on a sha-256 preimage/2nd-preimage break.
- `v1` pins the construction; it is also bound **into** the hashed bytes via
  `genesis.idSpec = 'car/v1'`, so a future `v2` can never be confused for `v1`.
- `idHash` = `multibase('z', multihash(sha2-384, sha-384(JCS(genesis))))`
  — a **full** sha-384 multihash (prefix `0x20 0x30`, code `0x20`, length
  `0x30` = 48). The length is part of the multihash, so a truncated digest is
  structurally rejected on decode.

`controller` is a **did:key** list (Ed25519 Multikey: multicodec `0xed01` +
base58btc multibase `z`). v1 is **Ed25519 only**; a non-ed25519 controller (P-256,
P-384, X25519, secp256k1) is rejected. A P-384/FIPS profile is a *future,
distinct* construction pinned by `idSpec`, never a silent downgrade.

Proving the holder currently controls the key is a separate, still-offline step:

```ts
import { verifyControl } from '@vorionsys/basis-registry';
// relying party supplies a fresh >=16-byte challenge; holder signs it
verifyControl(didKey, challenge, signature); // boolean, fail-closed
```

### 2. RFC-6962 transparency log

```ts
import {
  TransparencyLog, hashLeaf,
  verifyInclusion, verifyConsistency, verifySthSignature,
} from '@vorionsys/basis-registry';

const log = new TransparencyLog();
const { leafIndex, leafHash } = log.append({
  type: 'registration', carId, genesisHash,
});
const sth = log.signSth(
  { sthVersion: 'v1', treeSize: log.size(), rootHash: log.rootHash(), logId },
  logPrivateKey, logPublicKey,
);

const proof = log.inclusionProof(leafIndex);
verifyInclusion({ leafHash, leafIndex, treeSize: sth.treeSize, auditPath: proof.auditPath, sth });
```

- Domain separation (RFC-6962 §2.1): leaf hash `= H(0x00 || leafBytes)`,
  interior hash `= H(0x01 || left || right)`, empty tree `= H()` (sha-256 of
  the empty string). The prefix byte puts leaf and interior hashes in disjoint
  domains, so a forged leaf whose bytes equal `0x01 || a || b` cannot collide
  with `interior(a, b)`. There is **no un-prefixed hashing path** in the API.
- Leaf records are a tagged union (`registration` / `key_rotation` /
  `provenance_anchor`); raw evidence never enters the log — only commitments.
- The log records **commitments only**. For `provenance_anchor`, `chainHead`
  is the **last event's `eventHash`** (lowercase hex sha-256) of an RFC-0002
  proof-chain — that chain is a *linear* per-runtime hash chain with no Merkle
  root, so we anchor its head hash, not an invented chain-MTH.

#### Offline verifiers (the load-bearing surface)

All four are pure functions over `{ leafHash, auditPath/proof, STH, public
keys }` — **zero** network calls, **zero** DID resolution:

| function | proves |
|---|---|
| `verifyInclusion` | a leaf is in the tree the STH commits to |
| `verifyConsistency` | the new tree is an append-only extension of the old |
| `verifySthSignature` | the STH was signed by the supplied log key |
| `verifySthWitness` | one *supplied* witness cosignature is valid over the STH |

#### Split-view / equivocation detection

```ts
import { detectEquivocation } from '@vorionsys/basis-registry';
detectEquivocation(sthA, sthB, optionalConsistencyProof);
// { equivocation, kind?, reason?, misbehaviorCertificate? }
```

Two rules, both fail-closed:

1. **Same-size fork** — equal `treeSize`, different `rootHash` => equivocation
   (`same_size_divergent_root`). A single honest tree has exactly one root per
   size.
2. **Non-extending** — for `m < n`, a *supplied* consistency proof that fails
   to reconstruct both roots => equivocation (`non_extending`). An **absent**
   proof is reported as *undetermined*, never as "consistent" (absence of a
   proof is never proof of consistency).

When equivocation is found, the two signed STHs are returned as a
`misbehaviorCertificate` — anyone can re-verify the contradiction offline.

## Algorithm choices (deliberate, internally consistent)

Two hash algorithms, by design:

- **CAR id = sha-384.** The arch doc pins it, and the id is *permanent*: a
  2nd-preimage break here is identity forgery, so the strongest, FIPS-friendly
  long-horizon hash guards the identity preimage. 48-byte digest, length-bound
  inside a multihash.
- **RFC-6962 log = sha-256.** RFC-6962 is *defined* over sha-256 (32-byte
  nodes); anything else would break interop with the CT/Trillian/Rekor lineage.
  The log records short-lived operational commitments, continuously re-anchored.
  `registryRootFp` also uses sha-256 (it is a log-namespace identifier).

This split is a domain choice, not an inconsistency: heavy permanent hash for
the identity preimage, standard interoperable hash for the append-only tree.

**Canonicalization = RFC-8785 (JCS).** This package ships **one** JCS serializer
(object keys sorted by UTF-16 code unit, ECMAScript `Number::toString`, rejects
NaN/Infinity/-0/cycles, minimal lowercase-`\u` escaping). It deliberately does
**not** "mirror" the repo's proof-chain canonicalizer, which sorts keys in
ASCII-byte order. For the pure-ASCII keys this package uses (`ASCII_KEY_INVARIANT`,
asserted in tests) the two orderings provably coincide; choosing RFC-8785 as the
single source of truth means a future non-ASCII field can never silently diverge.

This library contains **zero floating-point arithmetic** of its own (only byte
and hash operations), so it is immune to libm ULP drift — a determinism strength.
**No `Date.now`, no `Math.random`** anywhere in the library (test helpers may
generate keys). `treeHeadTime` in an STH, if present, is **caller-supplied** —
the library never reads a wall clock.

## Fail-closed contract

This ecosystem has a documented fail-open history (a prior verifier returned
`true` for any sufficiently long blob without comparing the hash it computed).
This package is written against that:

- Every `verify*` returns `boolean` / `{ valid:false, reason }` and **never
  throws to a trusted state**; all decode + compare is wrapped in `try/catch`
  that returns false on any throw.
- A verifier **never returns true on an input it could not fully check**:
  `verifyInclusion` recomputes the entire root and compares all 32 bytes;
  `verifyConsistency` reconstructs **both** roots and requires **both** to match.
- Lengths are structural: a digest that is not exactly the expected byte length
  (32-byte node, 48-byte id digest, 64-byte sig, 34-byte multikey) is rejected
  **before** any comparison. A multihash length field must match its digest.
- All equality is constant-time (`timingSafeEqual`), **length-checked first** so
  it can never throw `ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH`.
- An empty / present-but-empty signature is **not** "valid by omission".
- `mint()` is a constructor and may **throw** on malformed caller input;
  `verify()` never throws through to a trusted state.

The negative-test suite (the anti-fail-open gate) covers: truncated/short
multihash, wrong-length signature, key-type confusion (non-ed25519 multikey),
wrong multibase prefix, leaf-vs-interior 2nd-preimage forgery, tampered /
over-long / short audit path, inclusion against the empty-tree root,
`index >= treeSize`, consistency with `m >= n` and `m === 0`, same-size
divergent STH, extra/missing/reordered/duplicate genesis key, non-canonicalizable
genesis, unsorted controllers, and empty-string signatures.

## Offline verification (what a relying party needs)

To verify a **CAR identity**, the RP needs only: the id string, the genesis
object, and the registry root **public key** (from the RP's own pinned trust
list, not fetched live). To verify **history**, the RP needs only: the leaf
record (or its hash), the inclusion `auditPath`, an STH it trusts, and the log
signer (and optionally chosen witness) public keys. All verifiers are pure
functions over these bytes — **no `api.vorion.org`, no DID resolution**.

The irreducible bootstrap is the RP's **pinned trust list** — *which* root,
log, and witness keys are canonical. This library ships **no default trust
list**, on purpose, so it cannot re-centralize trust by inertia. "Offline,
zero-server" means *no server trust given a pinned key set* — not "trustless".

## Honest scope (what this is and is **not**)

**In scope (this library):**
- Self-certifying CAR id: `mint` / `verify` / `registryRootFp`, did:key
  encode/decode, and the holder-of-key challenge (`verifyControl`).
- RFC-8785 JCS canonicalizer; base58btc / multibase / multihash.
- RFC-6962 append-only Merkle log with leaf/interior domain separation:
  `append`, `rootHash`, `inclusionProof`, `consistencyProof`.
- STH structure + Ed25519 sign/verify; hold + verify **one** supplied witness
  cosignature.
- Offline, fail-closed verifiers: `verifyInclusion`, `verifyConsistency`,
  `verifySthSignature`, `verifySthWitness`.
- Split-view / equivocation **detectors** over a supplied STH pair.

**Out of scope (infra / operator follow-ons — deferred):**
- The **witness cosigning network** itself: running witnesses, enrollment,
  diversity/Sybil policy, gossip/transport. (The library only holds + verifies
  a *supplied* witness signature; it does not run, enroll, or diversify
  witnesses, and single-org / all-Vorion quorums are an RP-policy reject the
  library cannot enforce alone.)
- Any **server / HTTP** surface, log storage backend, AgentAnchor dual-write,
  read-only proof endpoints.
- **Federation / sovereign** profiles, cross-certification, multi-enclave CDS
  exchange (arch Stages 4-5).
- Constitutional governance, threshold root-set (FROST / M-of-N), genesis
  convener decentralization.
- **Key-rotation race / equivocation ordering** resolution and social recovery.
  (The library verifies a rotation leaf's signature *shape* only; it does not
  adjudicate the legitimate-vs-thief race.)
- **P-384 / FIPS-CMVP** profile, TEE/TPM attestation, trusted-time-without-NTP.
  (v1 is Ed25519-only; time is caller-supplied.)
- **Freshness policy** and the **default trust list** (both RP-side).
- The reference **scorer** / TrustSpec lattice (that is `@vorionsys/basis-scorer`).
- SD-JWT / VC selective disclosure and DPoP holder-binding.

### Honest ceiling on split-view detection

Split-view detection **requires** the relying party to actually *see* >= 2 STHs
from independent vantage points (its own plus >= 1 witness/peer). The library
detects a contradiction *when given two heads*; it **cannot manufacture the
second head** — that needs the gossip/witness network, which is out of scope.

Therefore, in a **single-operator / single-witness air-gap profile**, where only
the operator's own head exists, the second independent head does not exist and
split-view detection **structurally cannot fire**. In that profile the residual
trust root is the **honest enclave operator**. This library does **not** claim
"non-equivocation" for the single-enclave profile.

## License

Apache-2.0. See [LICENSE](./LICENSE).

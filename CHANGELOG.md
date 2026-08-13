# Changelog

All notable changes to this repository are documented here. This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [@vorionsys/basis-spec-conformance@0.3.0] — 2026-08-13

**Security fix.** The reference verifier reported a chain whose signatures had been **deleted** as `valid: true`, exit `0` — including under `--require-signatures`. Anyone holding a signed chain could strip every `signature` field, leave `signedBy` in place, and the chain still verified: hashes and linkage are computed over the canonical event bytes, which do not include the signature, so removing it breaks nothing the verifier was checking. No key, no forgery and no hash work required — the cheapest possible attack on a receipt chain, against the one property the chain exists to provide.

### Fixed
- **Stripped signatures are detected and always fail** — with or without `--require-signatures`, because the attacker chooses whether the verifier runs in strict mode and we do not. An event whose `signedBy` names a signer while `signature` is absent now reports `signature: 'stripped'`, is counted in the new `signaturesStripped`, breaks the chain at that event, and prints an explicit stderr warning.
- **`--require-signatures` now means what it says** — every event must carry a signature that *verified*. Unverifiable, stripped and absent all fail it. It previously covered only the present-but-unverifiable case, so a chain with no signatures at all passed the flag whose entire purpose is to demand them.
- **`SUITE_VERSION` had silently drifted** — `suite-meta.ts` reported `0.1.1` while the published package was `0.2.0`, so every conformance results document cited a suite version that was never released. Verifiers are told to compare that field against known-good releases, which makes a stale value a confident *wrong* provenance claim rather than a missing one. Corrected, and `src/tests/suite-meta.test.ts` now asserts it against `package.json` so it cannot drift again.

### Added
- `vectors/chain-stripped-signature.json` — ninth golden vector. Hashes and linkage are perfect; only the proof of authorship is gone. Deliberately distinct from `chain-valid-unsigned.json`, which carries **neither** `signedBy` nor `signature` and remains legitimately valid: telling those two apart is the whole fix.
- `signaturesStripped` on `ChainVerificationReport`, and `'stripped'` on the per-event `signature` union.
- 9 tests (110 → 119), including a regression guard asserting a stripped chain fails with no keyring supplied — stripping is not a key-availability problem.

### Compatibility
- **Behavioural change to `--require-signatures`.** If you used it to check hash and linkage integrity on unsigned chains, drop the flag — that is the default and still exits `0`. Unsigned chains are unaffected without it.
- `signature: 'stripped'` is a new member of an existing union; consumers exhaustively switching on that field will need a branch.

## [@vorionsys/basis-merkle@0.1.0] — 2026-08-02

First release. Public reference implementation of RFC-0007 — chain compaction and Merkle selective disclosure. Pure SHA-256 + the Ed25519 signatures already in use; no trusted setup, no pairings, no new cryptographic assumptions.

### Added
- **Canonical Merkle construction** — domain-separated leaves (`0x00`) and internal nodes (`0x01`), leaves in chain order, odd nodes **promoted rather than duplicated**.
- **Audit paths** — `auditPath` / `foldPath` / `verifyPath`, O(log n) per leaf, pure and dependency-free so a third party can re-implement from the RFC in any language.
- **`buildCompaction` / `buildDisclosure` / `verifyDisclosure` / `verifyAgainstRange`** — compaction payload construction (unsigned; signing belongs to the key holder), self-contained disclosure packages, and a cross-check for verifiers that still hold the range.
- 39 tests.

### Notes
- **Two known Merkle defects are pinned by test**, because each produces distinct leaf sequences that share a root — which would let a compactor swap a range's contents while keeping its attested root:
  1. *Second-preimage.* Without domain separators, leaf and node hashes share a space and an internal node can be presented as a leaf. RFC 6962 uses the same construction for the same reason.
  2. *CVE-2012-2459.* Duplicating an odd last node makes `[a,b,c]` and `[a,b,c,c]` produce an **identical** root. The test asserts the roots differ *and* spells out the value the buggy construction would have produced, so a refactor reintroducing duplication fails loudly rather than silently.
- **Verification levels are mandatory.** `full` / `attested` / `none`, reported on every result — two verifiers holding different data can both be correct and reach different conclusions, so a bare `valid: true` is misleading and non-conforming. `leafCount` accompanies `disclosedCount` for the same reason: 3-of-4 and 3-of-40,000 are very different artefacts.
- **Fail-closed:** zero-leaf trees and zero-length compactions are refused (an empty compaction is indistinguishable from a suppressed range); non-contiguous ranges are refused (compacting an arbitrary selection would attest to a range that never existed); an unsigned compaction attests nothing; a missing public key is never a silent pass; a root mismatch against a held range fails even when every individual event is intact.
- **A test fixture bug, not a code bug, cost one red test and is now documented.** A leaf covers the canonical bytes, which RFC-0002 deliberately excludes `eventId` from. Two events differing only in their id therefore produce the same leaf, so a fixture varying only the id is *not* constructing a different range. Within a real chain this cannot collide because `previousHash` differs. There is now an explicit test pinning the property.
- Salting is optional and default-off — it adds real operational burden, and a lost salt means that leaf can never be proved again. A salted disclosure missing its salt is rejected explicitly rather than silently failing membership.
- Not zero-knowledge, and the README and module docs say so: path hashes, range size, and leaf position all travel with a disclosure.

## [@vorionsys/basis-plan@0.1.0] — 2026-08-02

First release. Public reference implementation of RFC-0006 — symbolic verification of multi-step agent execution plans.

### Added
- **`encodePlan()`** — compiles a plan DAG plus its invariants into SMT-LIB2. The program is satisfiable **exactly when some executable path violates some invariant**, so `unsat` is the safe answer. That polarity is deliberate: asking the solver to *find a violation* rather than to *confirm safety* makes an undecided solve conservative — `unknown` denies instead of falsely reporting safety. Output is deterministic (sorted declarations, fixed formatting) so the published artefact has a stable content hash, and readable on purpose — an auditor sees their own resource names in it.
- **`verifyPlan()` / `verifyEncoded()`** — Z3 driver via `z3-solver@5.0.0` (WASM, no Python sidecar). Publishes the exact program solved, its sha256, solver name, version, and seed, so a third party re-runs the solve without trusting the runtime that produced it.
- Invariants: `bound` (linear over accumulators), `forbid` (resource untouched on any path), `never_after` (ordering/taint — catches read-restricted-then-write-external), `predicate`.
- Symbolic quantities with optional bounds.
- 17 tests covering composition, sequencing, branch coverage, and the encoder guards.

### Notes
- **Two solver traps, both found by testing Z3 rather than trusting it, and both producing a FALSE SAFE** — the one direction a verification tool must never fail in. Each has a regression test.

  1. *Context state leaks.* `eval_smtlib2_string` retains declarations and `set-logic` across calls on the same context. A genuinely violating plan was observed reporting `unsat` — safe — purely from the previous solve's leftover state. Every solve now runs in a fresh context.
  2. *Errors do not stop the solve.* A malformed program emits `(error ...)` and then **continues**, printing a result derived from whatever it parsed; a broken program was observed printing `sat` after erroring. Any `(error` now forces `inconclusive`, and output is never read past it.

  The strict single-token output classifier applies to the **decision** run only. The diagnostic run that extracts a counterexample legitimately produces a model and value bindings, and is read separately — conflating the two silently dropped every counterexample until it was caught by a failing test.
- **A plan with no invariants is refused**, rather than returning `proved_safe`. A verdict with nothing checked is unfalsifiable. Cycles are rejected rather than approximated, since acyclicity is what keeps the obligation decidable.
- **An unbounded symbol cannot satisfy a bound** and yields a counterexample. That is correct — you cannot prove a limit over a quantity you never constrained — and it is documented rather than hidden.
- The RFC was corrected to match the implementation: invariants carry a required `id` (without it `invariantsChecked` cannot name anything and the verdict is unfalsifiable), `symbols` is part of the plan, and `assign` values are integers since v1 encodes in QF_LIA.

## [@vorionsys/basis-quorum@0.1.0] — 2026-08-02

First release. Public reference implementation of RFC-0005 — *m*-of-*n* threshold authorization for high-consequence agent actions.

### Added
- **Real distributed key generation** (`createGroupViaDkg`) over `@noble/curves` `ed25519_FROST` (RFC 9591). No dealer, so no single party — including the coordinator — ever holds the group private key. Degenerate thresholds are rejected at construction: `m < 2` ("a quorum of one is not a quorum"), `m > n`, single-member sets, and duplicate validator ids, which would otherwise double-count toward the threshold.
- **Round orchestration** (`runQuorumRound`) emitting the three RFC-0005 event types. Votes are collected concurrently and **blindly** — no validator is given another's result — and chained in *declared validator order* rather than completion order, so a round is reproducible regardless of how the async races resolve.
- **`verifyQuorumRound()`** — the coherence pass. Tally reconciliation against chained votes, validator-set accounting, outcome/threshold consistency, ordering, and deadline.
- **`createLocalValidator` / `buildKeyring`** — reference validator holding its own Ed25519 key, and the keyring helper for chain verification.
- **Golden vectors** — two valid rounds (approved; rejected-with-dissent) and four tampered variants. Deterministic via seeded DRBG, fixed key seeds, and a fixed clock, so regeneration is byte-identical. `scripts/generate-vectors.mjs` carries its **own** canonicalizer written from the RFC-0002 text and re-derives every `eventHash` with it; generation fails if the two implementations disagree.
- 19 tests. Conformance suite unaffected at 110/110.

### Notes
- **The tampered vectors pass `verifyChain()`.** This is the point, and it is verified in the test suite: a coordinator that doctors a resolution can recompute its hash and re-attest it with the group key, producing a chain whose hashes, linkage and signatures are all flawless. `basis-conformance verify --require-signatures` exits **0** on `tamper-approved-below-threshold.json`. Integrity verification alone would accept a forged approval; only the quorum pass catches it. Two passes are required, and the vectors are the proof rather than the assertion.
- **The attribution check cannot live in the chain verifier.** `verifyChain()` verifies a signature against a supplied keyring but has no way to know which validator a vote was *supposed* to come from — given a ring containing both keys, validator A's vote signed with B's key verifies as valid. `verifyQuorumRound()` compares `signedBy` against the payload's `validatorId`, which is what actually binds a vote to its author.
- **Known limitation, documented rather than papered over:** the chain cannot distinguish a suppressed vote from a genuine non-response. A coordinator that drops a dissent *and* relabels that validator as a non-responder produces an internally consistent record. The defence is procedural — validators retain their signed votes and may publish independently, and a validator-signed vote absent from the chain is direct evidence of suppression. The naive version (dropping without relabelling) *is* caught, and `tamper-suppressed-dissent.json` pins that.
- The optional `rng` parameter exists solely to make vectors byte-stable and is documented as fixtures-only in the type, the README, and every call site. FROST nonce reuse leaks key material.

## [@vorionsys/basis-spec@1.3.0] — 2026-08-02

### Added
- **Canonical JSON serialization hoisted into the spec package** (`canonical-json.ts`): `canonicalize`, `canonicalEventString`, `canonicalEventBytes`, and the `HashableEventFields` type. It had lived in `basis-spec-conformance`'s chain verifier since 0.2.0, which meant a second consumer (the quorum reference implementation) would have had to either depend on a test suite or re-implement it. Byte-identity is the property every other guarantee rests on, and a second implementation is a second chance to diverge — so the normative serializer now sits alongside the proof-event types it serializes.

  `basis-spec-conformance` re-exports all three, so its public API is unchanged; `canonicalEventBytes` there still returns a `Buffer` (rather than the spec package's platform-neutral `Uint8Array`) because that has been its published return type since 0.2.0. Verified non-breaking: the pre-existing golden vectors, sealed under the old code path, still verify byte-identically, and the suite stays at 110/110.

## Repo-level — 2026-08-02

### Added
- **RFC-0005: Quorum Authorization Events v1** — how a runtime records an action that required more than one party to authorize it. Adds three event types (`quorum_requested`, `validator_vote`, `quorum_resolved`) as a non-breaking minor addition under RFC-0002's back-compat rules.

  Core design is a **two-record structure**, forced by a measured property of threshold signatures: the aggregate is *subset-anonymous* — every valid `m`-subset produces a different signature verifying under the same group key, so the aggregate proves *that* a quorum signed but never *which members*. The aggregate therefore carries authority, and separately-chained per-validator votes carry attribution. Emitting only the aggregate is non-conforming, because it destroys exactly the information needed to detect a suppressed dissent or adjust a validator's tier honestly.

  FROST (RFC 9591, `FROST-ED25519-SHA512-v1`) is the required default specifically because its output is a standard Ed25519 signature — a conforming quorum chain verifies with the **existing** verifier, unchanged. Validated end to end: a 6-event chain mixing individually-signed validator votes with a FROST aggregate verified under `basis-conformance verify --require-signatures` (`valid: true`, `signaturesValid: 4`, exit 0) with no verifier modifications.

  The RFC is explicit that this is **not** Byzantine consensus (validators exercising judgment are stochastic, not deterministic replicas, so pBFT's safety argument does not transfer), that evidence entries are recorded claims rather than verifiable facts, that validators must be scored on outcome rather than peer agreement (scoring for agreement produces herding and collapses the independence the design depends on), and that validator independence is an empirical assumption to be measured rather than asserted.

### Fixed
- **RFC-0003 example block referenced a package that does not exist** — `@vorionsys/basis-conformance` / `github.com/vorionsys/basis-conformance`. Corrected to `@vorionsys/basis-spec-conformance` and `github.com/vorionsys/basis-spec`. Same dead-pointer class as the RFC-0002 fix in 0.2.0.

## [@vorionsys/basis-spec-conformance@0.2.0] — 2026-08-02

### Added
- **Public reference verifier for RFC-0002 proof chains** (`src/chain-verifier.ts`). Until now the only public tool was `validate`, which is truth-only/structural and explicitly does *not* touch cryptography — so no third party could actually verify a BASIS chain without vendor tooling, which made "tamper-evident, independently verifiable audit trail" an unfalsifiable claim. `verifyChain()` closes that gap: it rebuilds each event's canonical-JSON bytes, recomputes `eventHash` (sha256) and `eventHash3` (sha3-256) when present, walks `previousHash` linkage from a null head, and verifies detached Ed25519 signatures. Dependency-free beyond `node:crypto`, so an auditor can read it end to end.
- **`basis-conformance verify <chain.json>` CLI**, with `--keys`, `--require-signatures`, and `--signature-domain`. Exits `0` on a verified chain, `1` on a broken one.
- **Golden test vectors** (`vectors/`) — a valid signed chain, an unsigned chain, and five tampered variants (payload edit, cut linkage, non-null head, corrupted signature, signature-domain mismatch). Deterministic: fixed key seed and fixed timestamps, so regeneration is byte-identical. Generated by `scripts/generate-vectors.mjs`, which carries its **own independent canonicalizer written from the spec text** — the vectors and the verifier are deliberately not the same code, so a passing run proves two independent readings of §"Canonical serialization" agree on the bytes.
- **Exported canonicalizer** (`canonicalize`, `canonicalEventString`, `canonicalEventBytes`) so vendor implementations can hash the exact same bytes this verifier does. Previously the canonicalizer existed only as a test-local reference.
- 20 new tests (`chain-verification.test.ts`); suite total **90 → 110**.

### Fixed
- **RFC-0002 Erratum E-1 — what the signature covers.** The RFC was self-contradictory: §"Schema" annotated `signature` as covering `eventHash`, while §"Verification procedure" step 5 said the canonical bytes. Those are different messages, so two implementations conforming to the letter could fail to verify each other's chains. Resolved in favor of the **canonical bytes** (the §"Verification procedure" reading is normative); the §"Schema" annotation was corrected. The verifier accepts `signatureDomain: 'eventHash'` for chains sealed under the old reading and reports `domain-mismatch` rather than a bare "bad signature" when signer and verifier disagree.
- **RFC-0002 §"Implementation references" was stale** — it described the public reference impl as "forthcoming" and pointed at `vorionsys/basis-conformance`, a package name that does not exist on npm (the suite ships as `@vorionsys/basis-spec-conformance`). A reader following that pointer hit a dead end. Now documents the shipped verifier with a runnable example.
- **README test count corrected** — it advertised "≈40 tests across 6 suites"; the suite actually ran 90 across 6, and now runs 110 across 7.

### Notes
- `valid: true` is an integrity verdict about the **record**, not a trust or compliance verdict about the agent. A cryptographically perfect chain of bad decisions verifies just fine. The CLI help, README, and module docs all state this explicitly.
- Fail-closed posture extended: an empty chain is never a valid verification, a present-but-unverifiable signature is never silently counted as good (it is surfaced in `signaturesUnverified` and noted on stderr even outside strict mode), and a malformed public key is a hard error rather than a skipped check.

## [@vorionsys/basis-spec-conformance@0.1.1] — 2026-07-01

### Fixed
- **Fail closed on zero discovered tests** — a run that discovers 0 tests now prints an error to stderr and exits `2` instead of exiting `0` ("all tests passed"). The 0.1.0 tarball shipped without the test vectors (`files` listed only `dist`/`README.md`/`LICENSE`), so a consumer install ran zero tests and still reported success. `runConformance()` now also rejects on an empty run.
- **Published tarball is now self-sufficient** — `src/` (test vectors + fixtures) and `vitest.config.ts` ship in the package; the repo-root `schemas/` directory is copied into `dist/schemas` at build time; `vitest` moved from devDependencies to dependencies and the runner resolves the locally installed vitest binary (npx fallback); the runner's default working directory is now the installed package root (override with `--cwd`), so `npx basis-conformance run` works from anywhere.
- **Real revision stamping** — `npm run build` now writes `dist/revision.json` with the git sha the build was cut from (`GITHUB_SHA` in CI, `git rev-parse HEAD` locally); results documents report that sha as `suite.revision` instead of the baked `dev-build` placeholder, which now appears only for unstamped local dev builds.
- **`SUITE_NAME` corrected** to `@vorionsys/basis-spec-conformance` — results documents previously self-identified as `@vorionsys/basis-conformance`, a package name that does not exist on npm.

## Repo-level — 2026-04-25

### Added
- **RFC-0003: Conformance Attestation v1** — defines the signed scorecard each BASIS-compliant product publishes at `https://<product>.example/attestations/<product>-<version>.json`. Decouples "we conform" from "trust us" by making the claim machine-verifiable.
- `schemas/attestation-v1.json` — strict JSON Schema for the attestation document. Anyone can validate any vendor's attestation file with stock Ajv, no Vorion tooling required.
- `schemas/README.md` — usage doc for the JSON Schema artifacts.

## [@vorionsys/basis-spec@1.2.0] — 2026-06-08

### Renamed
- **Package renamed `@basis-spec/basis` → `@vorionsys/basis-spec`** (and the conformance suite `@basis-spec/basis-conformance` → `@vorionsys/basis-spec-conformance`) before first publish — no version was ever published under the old names, so there is no consumer migration. Owner decision 2026-06-11: publish under the controlled `@vorionsys` scope rather than the separate `@basis-spec` scope. Note this package is NOT `@vorionsys/basis` — that name remains withdrawn; this is a new name per publishing rules.

### Added
- **Canonical `TRUST_FACTORS`** — the 16 core trust factors (9 Foundation/Security `CT-*`, 4 Operational `OP-*`, 3 Sophisticated `SF-*`), ported verbatim from the assembled monolith source of record, plus `TOTAL_CORE_FACTORS = 16`. Exported from the package root via `canonical.ts`.
- `.github/workflows/release.yml` — tokenless OIDC `latest` release workflow (`v*` tag → gates → `npm publish --provenance` of `packages/basis`). No npm token is stored in CI.
- `LICENSE` now ships inside the `packages/basis` tarball (the `files` array already listed it, but the file lived only at the repo root, so published artifacts would have carried no license text).

### Notes
- Non-breaking minor bump; only new exports added. This is the surface `@vorionsys/rainbow` consumes (`TRUST_FACTORS`, `TRUST_TIERS`, `OBSERVATION_TIERS`, `RISK_ACCUMULATOR`, `RISK_LEVELS`, `PENALTY_RATIO_MIN`/`MAX`).

## [@vorionsys/basis-spec@1.1.0] — 2026-04-25

### Added
- **RFC-0002: Proof Event Chain v1** — public spec for the shape of every audit event a BASIS-compliant runtime emits, plus the hash-chain semantics that make the trail tamper-evident.
- `proof-chain.ts` — canonical TypeScript types: `ProofEvent`, 10 typed payload variants + `GenericPayload` escape hatch, `ShadowModeStatus`, `ProofEventFilter`, `ChainVerificationResult`, `LogProofEventRequest`, `ProofEventSummary`. Timestamps as ISO 8601 strings for cross-language interop.
- `proof-chain-schema.ts` — Zod validators for all of the above. Importable from `@vorionsys/basis-spec/zod`.
- Re-exported the new types from the package entry point and the new validators from `/zod`.

### Why
- Closes the public-trust verification gap: customer SOC teams + external auditors can now validate any vendor's audit log against the public schema without trusting vendor tooling.
- Decouples the audit-record SHAPE (public) from the cryptographic operations that produce it (proprietary). Runtimes stay competitive on impl quality; the contract anyone reads stays open.

### Notes
- This is a non-breaking minor bump. No existing exports changed; only new ones added.
- Companion RFC-0003 (Conformance Attestation) coming in the next release — defines the signed scorecard that proprietary impls publish per release.

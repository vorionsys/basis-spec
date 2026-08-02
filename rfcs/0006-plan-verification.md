# RFC-0006: Execution Plan Verification v1

**Status:** Draft
**Version:** 1.0
**Date:** 2026-08-02
**Author:** Vorion LLC
**Related:** [RFC-0002](0002-proof-event-chain.md) (Proof Event Chain), [RFC-0005](0005-quorum-authorization.md) (Quorum Authorization), [SMT-LIB 2.6](https://smtlib.cs.uiowa.edu/)

---

## Summary

This RFC defines how an agent submits a **multi-step execution plan** for symbolic verification before its first step runs, and how the result is recorded so that **anyone can re-derive it**.

An agent declares a directed acyclic graph of steps, each with its declared effects, together with the invariants the plan must not violate. A solver is asked to find any execution path through that graph which reaches a violating state. If none exists, the plan is proved safe **over all paths**, not merely over the path that happened to be sampled. If one exists, the solver returns it, and that counterexample becomes the audit artefact — it names the exact branch that violates.

Two event types are added: `plan_submitted` and `plan_verified`.

The property that makes this worth standardising is **reproducibility**. A verification result is not a vendor assertion. The exact SMT-LIB2 constraint program and the solver identity are published in the chain, so a buyer, auditor, or regulator re-runs the solve and obtains the same answer without trusting the runtime that produced it.

---

## Motivation

Pre-action gating evaluates one action at a time. That is the right unit for most enforcement and it is genuinely hard to evade at the level of a single call. But it is structurally blind to a class of attack that no single-action check can see:

- **Composition.** Each of five transfers is individually under the limit; together they exceed it.
- **Sequencing.** Reading from a restricted store is permitted. Writing to an external endpoint is permitted. Doing the first and then the second is exfiltration.
- **Branch coverage.** A plan is tested on its expected path and behaves. The violating state lies down a conditional branch that testing never took.

Reviewing a plan by reading it does not solve this either. The number of paths through a branching plan grows exponentially, and human review samples rather than covers.

Symbolic verification covers. Asking a solver "does *any* path reach a violating state" is a question about all paths at once, and the answer is a proof rather than a sample.

---

## What this verifies — and what it does not

Stated first, and prominently, because a verification standard that overstates its guarantee is worse than none.

### What a `proved_safe` result means

Exactly this: **no path through the declared graph, under the declared effect semantics, reaches a state violating the declared invariants.**

Every one of those qualifiers is load-bearing.

### What it does not mean

- **It is not a proof about the agent's code.** It is a proof about the plan the agent submitted.

- **It does not establish that the declared effects are truthful.** This is the sharpest limitation in the RFC. If a step declares that it writes 100 units and it actually writes 10,000, the verification is sound about a fiction. Effect declarations are a **trust input**, not a verified output. Two things mitigate this and neither eliminates it: effects are chained under signature, so a false declaration is attributable after the fact; and per-step gating at execution time (see §"Composition with pre-action gating") checks the actual call against the declared effect, converting a lie into a runtime denial rather than a silent success.

- **It does not guarantee the agent follows the plan.** A verified plan is a verified *plan*. Binding it to execution requires the gating in §"Composition with pre-action gating"; verification alone permits an agent to submit a safe plan and then do something else.

- **It does not model what was not declared.** Side effects outside the effect vocabulary are invisible to the solver. Absence of a modelled violation is not absence of harm.

- **It is not a decision-quality judgement.** A plan can be provably safe and commercially catastrophic. This says nothing about whether the plan is a good idea.

Implementations MUST NOT describe a `proved_safe` result as proving that an action *is safe*, only that the declared plan satisfies the declared invariants.

---

## The execution plan

A plan is a DAG. Acyclicity is not a convenience — it is what keeps the verification obligation **decidable**. Unbounded loops make reachability undecidable in general; a bounded, acyclic plan does not. Runtimes that need iteration MUST unroll to a declared bound and record that bound, so that what was verified is exactly what can execute.

```ts
interface ExecutionPlan {
  planId:      string;
  /** Steps, each uniquely identified within the plan. */
  steps:       PlanStep[];
  /** Edges: `from` must complete before `to` may begin. MUST be acyclic. */
  edges:       Array<{ from: string; to: string; condition?: Condition }>;
  /** Invariants that MUST hold in every reachable state. MUST be non-empty. */
  invariants:  Invariant[];
  /** Quantities not known at plan time. See "Symbolic quantities" below. */
  symbols?:    PlanSymbol[];
  /** Loop unroll bound, when any iteration was flattened. */
  unrollBound?: number;
}

/**
 * A quantity whose value is unknown at plan time — an invoice total, a row
 * count. Bounds are not decoration: an UNBOUNDED symbol cannot satisfy any
 * accumulator bound, and a conforming verifier MUST return a counterexample
 * rather than a proof. That is correct behaviour — a limit cannot be proved
 * over a quantity that was never constrained.
 */
interface PlanSymbol {
  name: string;
  min?: number;
  max?: number;
}

interface PlanStep {
  stepId:      string;
  actionType:  string;            // same vocabulary as RFC-0002 intents
  resourceScope: string[];
  riskLevel?:  RiskLevel;         // canonical RISK_LEVELS key
  /** What this step does, in the modelled vocabulary. See the caveat above. */
  effects:     Effect[];
  /** Guard under which this step executes at all. Absent means unconditional. */
  guard?:      Condition;
}
```

### Effects

An effect is a declared state change in a vocabulary the solver can reason about. v1 defines three kinds; the set is extensible by RFC amendment.

```ts
type Effect =
  /**
   * Numeric accumulation: `counter += amount`. A string amount names a
   * declared symbol. v1 encodes accumulators in QF_LIA, so literal amounts
   * MUST be integers.
   */
  | { kind: 'accumulate'; counter: string; amount: number | string }
  /** Resource access, for reachability and taint reasoning. */
  | { kind: 'access'; mode: 'read' | 'write' | 'delete'; resource: string }
  /** Explicit integer assignment. */
  | { kind: 'assign'; variable: string; value: number };
```

### Invariants

Every invariant carries an `id`. This is required, not cosmetic: `plan_verified` records `invariantsChecked`, and a verdict whose checked set cannot be named is unfalsifiable — "proved safe" means nothing if nobody can tell which properties were proved.

```ts
type Invariant =
  /** A linear-arithmetic bound over accumulators. */
  | { kind: 'bound'; id: string; counter: string; op: '<=' | '<' | '>=' | '>'; limit: number }
  /** A resource that MUST NOT be touched in the given mode, on any path. */
  | { kind: 'forbid'; id: string; mode: 'read' | 'write' | 'delete'; resource: string }
  /**
   * Ordering/taint: if `after` executes on a path where `before` also
   * executed, the plan is violating. This is the shape that catches
   * read-restricted-then-write-external.
   */
  | { kind: 'never_after'; id: string; before: string; after: string }
  /** Arbitrary predicate in the plan's variable vocabulary. */
  | { kind: 'predicate'; id: string; expression: Condition };
```

A plan MUST declare at least one invariant. A verifier presented with none MUST refuse rather than return `proved_safe`, since a plan checked against nothing is trivially "safe" and the verdict is meaningless.

---

## The verification obligation

A conforming verifier constructs a constraint program that is **satisfiable if and only if some executable path violates some invariant**, and asks a solver to decide it.

- **UNSAT** ⟹ no violating path exists ⟹ `proved_safe`.
- **SAT** ⟹ the returned model is a concrete violating path ⟹ `counterexample`.
- **UNKNOWN / timeout / resource-exhaustion** ⟹ `inconclusive`, which **denies** (see §"Fail-closed requirements").

Note the polarity. The solver is asked to find a violation, not to confirm safety. UNSAT — a proof that no violation exists — is the safe answer. This matters because it makes the failure mode of an incomplete solver *conservative*: a solver that cannot decide returns UNKNOWN, which denies, rather than falsely reporting safety.

This RFC deliberately specifies the **obligation and the artefact**, not a single blessed encoding. Any encoding that is satisfiable exactly when a violating path exists discharges the obligation. What is normative is that the exact constraint program actually submitted to the solver is published, so the result is checkable independently of the encoding used to reach it.

---

## Reproducibility

A verification result that cannot be re-derived is a vendor assertion wearing the costume of a proof. Conforming implementations MUST record all of:

| Field | Why |
|---|---|
| `smtlib2` (or a content hash + retrieval URL) | The exact program solved. Without it there is nothing to re-run. |
| `solver.name`, `solver.version` | Solvers differ, and the same solver differs across versions. |
| `solver.seed` | Where the solver uses randomness, results are only reproducible against a fixed seed. |
| `logic` | The SMT-LIB logic used, e.g. `QF_LIA`, `QF_UFLIA`. |
| `result` | `unsat` \| `sat` \| `unknown`. |
| `model` | For `sat`, the violating assignment — the counterexample IS the audit artefact. |
| `proof` | For `unsat`, the proof certificate when the solver can emit one. OPTIONAL but RECOMMENDED: it is independently checkable without re-running the solve. |

A verifier re-running the published program against the recorded solver and seed MUST obtain the same result. An implementation that cannot produce a re-runnable artefact MUST NOT claim RFC-0006 conformance.

---

## Events

Both event types extend the RFC-0002 set. Per RFC-0002 §"Backward-compatibility rules", adding event types with new typed payloads is a **non-breaking minor addition**.

### `plan_submitted`

The plan itself, chained **before** any verdict. Chaining the plan separately is what binds the verdict to a specific plan: a runtime cannot verify plan A and then execute plan B, because the verdict names the hash of the plan that was actually verified.

```ts
interface PlanSubmittedPayload {
  type:        'plan_submitted';
  planId:      string;
  intentId?:   string;            // links to the originating intent
  plan:        ExecutionPlan;
  submittedAt: string;            // ISO 8601
}
```

### `plan_verified`

```ts
interface PlanVerifiedPayload {
  type:        'plan_verified';
  planId:      string;
  /** eventHash of the `plan_submitted` event this verdict is about. */
  planEventHash: string;
  outcome:     'proved_safe' | 'counterexample' | 'inconclusive';
  /** Invariants that were checked. A verdict is meaningless without this. */
  invariantsChecked: string[];
  verification: {
    logic:     string;
    result:    'unsat' | 'sat' | 'unknown';
    solver:    { name: string; version: string; seed?: string };
    /** The exact program solved, or its sha256 plus where to fetch it. */
    smtlib2?:  string;
    smtlib2Hash?: string;
    smtlib2Url?:  string;
    /** For `sat`: the violating path. For `unsat`: an optional proof certificate. */
    model?:    string;
    proof?:    string;
    durationMs?: number;
  };
  verifiedAt:  string;
}
```

A `proved_safe` outcome MUST correspond to `result: 'unsat'`, and `counterexample` to `result: 'sat'`. Any other pairing is malformed.

`invariantsChecked` is required because a verdict without the checked set is unfalsifiable: "proved safe" is meaningless if nobody can tell which properties were proved.

---

## Fail-closed requirements

1. **Inconclusive denies.** A timeout, an `unknown`, or a resource limit is **not** a pass. It MUST deny. "The solver could not decide" is indistinguishable from "there is a violation it could not find", and must never be reported as safety.
2. **No plan, no multi-step execution.** A runtime requiring plan verification for a class of action MUST refuse that class when no verified plan exists.
3. **A stale verdict is not a verdict.** If the plan changes after verification, `planEventHash` no longer matches and the verdict MUST be treated as absent.
4. **An unmodelled effect denies by policy, not by silence.** Where a step declares an `actionType` whose effects the runtime cannot model, the runtime MUST either deny or explicitly record that the step was unmodelled. Silently verifying a plan with unmodelled steps produces a proof about a subset while implying one about the whole.
5. **Unbounded iteration is rejected**, not approximated. Unroll to a declared bound and record the bound, or refuse the plan.

---

## Composition with pre-action gating

Plan verification does **not** replace per-action gating, and implementations MUST NOT present it as an evolution beyond gating. The two are complementary and neither is sufficient alone:

| | Plan verification | Pre-action gate |
|---|---|---|
| Scope | all paths through a declared plan | one actual call |
| Blind to | anything undeclared, and to the agent deviating from the plan | composition and sequencing across calls |
| Answers | "could this plan ever violate?" | "is this specific call permitted right now?" |

The composition is what produces the useful guarantee:

1. Plan verified → `proved_safe`, chained.
2. At execution, each action is gated **against the approved plan** — does this call correspond to a declared step, with effects within what was declared?
3. A deviation is a gate denial, chained as an ordinary RFC-0002 event.

Step 2 is what converts the untrusted effect declaration from a hole into an attributable, enforceable commitment. The agent declared what it would do; the gate holds it to that. Neither half delivers this on its own.

---

## Relationship to RFC-0005

A verification result is **not** RFC-0005 `evidence[]`, and this distinction is deliberate.

`evidence[]` exists for signals a third party **cannot** re-derive — a classifier score whose reproduction would require the model weights, runtime, and input state. Such signals are recorded as claims under signature and nothing more.

An SMT result is the opposite: fully reproducible from published artefacts. Filing it as `evidence[]` would understate it and blur the one distinction the architecture depends on — between what an auditor can check and what they must take on trust. It therefore gets first-class event types.

Where both apply, a quorum validator MAY cite a `plan_verified` event by `eventId` in its rationale. The verdict stands on its own chained record.

---

## Security considerations

**Effect declaration is the trust boundary.** Everything above rests on declared effects. An adversary's cheapest attack is not defeating the solver — it is lying in the declaration. Defences are the per-step gate (§"Composition"), signed attribution of the declaration, and policy limits on which agents may declare their own effects at all. None makes the declaration trustworthy; they make it *accountable*.

**Solver trust.** A compromised or backdoored solver reporting `unsat` yields a false proof. Mitigations: prefer solvers that emit checkable `unsat` proof certificates, since a certificate is verifiable without trusting the solver that produced it; and publish the program so an independent solver can be run against it.

**Denial of service.** Constraint programs can be made expensive. An adversary who submits pathological plans can exhaust the verification budget. Because inconclusive denies, this is an availability attack rather than a safety failure — but it is real, and resource limits MUST be enforced per plan rather than globally, so one plan cannot starve others.

**Information disclosure.** A published SMT-LIB2 program discloses the plan's structure and the invariants enforced. Where invariants are themselves sensitive, publish the content hash and disclose the program under the audit relationship rather than publicly. Do not silently omit it — an unpublished program means the result is not independently checkable, and the record MUST say so.

---

## Backward compatibility

- Adds two `eventType` values with new typed payloads — a **non-breaking minor addition** under RFC-0002 §"Backward-compatibility rules". Existing chains validate byte-identically.
- No change to the RFC-0002 event schema or to canonical serialization.
- Verifiers that do not implement this RFC still verify chain integrity and treat the new payloads as `GenericPayload`. They will not perform the checks in this document and MUST NOT report RFC-0006 conformance.

---

## Conformance requirements

A runtime claims RFC-0006 conformance by:

1. Chaining `plan_submitted` before any verification verdict for that plan.
2. Chaining exactly one `plan_verified` per verification attempt, naming the `planEventHash` it applies to.
3. Publishing a re-runnable artefact: the SMT-LIB2 program (or hash plus retrieval), solver name, version, and seed where applicable.
4. Recording `invariantsChecked`.
5. Denying on `inconclusive`, on a stale `planEventHash`, and on unbounded iteration.
6. Never reporting `proved_safe` for any solver result other than `unsat`.

---

## Open questions

- **Effect vocabulary registry.** v1 fixes three effect kinds. A registry would improve cross-vendor comparability but risks implying that registered effects are *verified* rather than declared.
- **Cross-plan invariants.** Daily limits span plans. Modelling accumulated state across plans requires a shared state abstraction and is deferred.
- **Incremental re-verification.** Re-verifying a long plan after a small amendment should not require a full re-solve. Deferred.
- **Proof certificate portability.** UNSAT certificate formats are solver-specific; a portable format would let a verifier check without any solver.
- **Interaction with `shadowMode`.** Whether a plan verified in shadow carries any weight when promoted to production is unresolved; today it does not.

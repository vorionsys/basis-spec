# `@vorionsys/basis-plan`

Public reference implementation of **[BASIS RFC-0006](../../rfcs/0006-plan-verification.md)** — symbolic verification of multi-step agent execution plans.

An agent declares a DAG of steps with their effects, plus the invariants the plan must not violate. A solver is asked to find **any** path that reaches a violating state. If none exists, the plan is proved safe **over all paths** — not merely over the path that happened to be sampled.

## What per-action gating cannot see

Pre-action gating is the right unit for most enforcement and is genuinely hard to evade one call at a time. It is structurally blind to three things:

- **Composition** — each of five transfers is under the limit; together they exceed it.
- **Sequencing** — reading a restricted store is permitted; writing to an external endpoint is permitted; doing the first *then* the second is exfiltration.
- **Branch coverage** — the plan behaves on its expected path. The violating state is down a conditional branch testing never took.

Reviewing the plan by reading it does not solve this either: paths grow exponentially, and human review samples rather than covers. Asking a solver "does *any* path violate" is a question about all paths at once, and the answer is a proof rather than a sample.

## Why it is worth standardising: the result is reproducible

This is the property that separates it from every probabilistic signal in the stack. The exact SMT-LIB2 program and the solver identity are published, so a buyer, auditor, or regulator **re-runs the solve and obtains the same answer without trusting the runtime that produced it.**

Unlike a classifier score — which nobody can reproduce without your weights, runtime, and input state — this is a claim anyone can check.

## Install

```bash
npm install @vorionsys/basis-plan
```

## Use

```ts
import { verifyPlan } from '@vorionsys/basis-plan';

const result = await verifyPlan({
  planId: 'p-demo',
  steps: [
    { stepId: 'read-pii', actionType: 'db.read', resourceScope: ['db:restricted.customers'],
      effects: [{ kind: 'access', mode: 'read', resource: 'db:restricted.customers' }] },
    { stepId: 'summarize', actionType: 'llm.call', resourceScope: [],
      effects: [{ kind: 'accumulate', counter: 'tokens', amount: 4000 }] },
    { stepId: 'post-external', actionType: 'http.post', resourceScope: ['https://x.example'],
      guard: { kind: 'var', name: 'delivery_enabled' },
      effects: [{ kind: 'access', mode: 'write', resource: 'net:external' }] },
  ],
  edges: [{ from: 'read-pii', to: 'summarize' }, { from: 'summarize', to: 'post-external' }],
  invariants: [
    { kind: 'never_after', id: 'no-exfil', before: 'read-pii', after: 'post-external' },
    { kind: 'bound', id: 'token-budget', counter: 'tokens', op: '<=', limit: 10_000 },
  ],
});

// outcome: 'counterexample' | violated: ['no-exfil']
```

The generated program is readable on purpose — an auditor should see their own resource names in it:

```smt
(assert (= |exec:post-external| (and |exec:summarize| |b:delivery_enabled|)))
(assert (= |touch:write:net:external| |exec:post-external|))

; violation of invariant "no-exfil"
(define-fun |v:no-exfil| () Bool (and |exec:read-pii| |exec:post-external|))
(assert (or |v:no-exfil| |v:token-budget|))
(check-sat)
```

and the counterexample names the branch that reaches the violating state:

```
((|v:no-exfil| true)
 (|v:token-budget| false))
```

## The polarity is the design

The program is satisfiable **exactly when some executable path violates some invariant**:

| Solver | Meaning | Outcome |
|---|---|---|
| `unsat` | no violating path exists | `proved_safe` |
| `sat` | the model is a concrete violating path | `counterexample` |
| `unknown` / timeout | undecided | **`inconclusive` → denies** |

Asking the solver to *find a violation* rather than to *confirm safety* makes the failure mode conservative. A solver that cannot decide returns `unknown`, which denies, instead of falsely reporting safety.

## What `proved_safe` means — precisely

**No path through the DECLARED graph, under the DECLARED effect semantics, reaches a state violating the DECLARED invariants.** Every qualifier is load-bearing.

It does **not** mean:

- **That the agent's code is safe.** It is a proof about the plan, not the code.
- **That the declared effects are truthful.** This is the sharpest limitation. If a step declares it writes 100 and it actually writes 10,000, the verification is *sound about a fiction*. Effects are a **trust input**, not a verified output. Two things mitigate and neither eliminates: effects are chained under signature, so a false declaration is attributable; and per-step gating at execution converts a lie into a runtime denial rather than a silent success.
- **That the agent will follow the plan.** A verified plan is a verified plan. Binding it to execution requires gating each action against it.
- **That unmodelled effects are absent.** Absence of a modelled violation is not absence of harm.
- **That the plan is a good idea.** A plan can be provably safe and commercially catastrophic.

## This does not replace pre-action gating

It must not be presented as an evolution beyond it. The two are complementary and neither is sufficient:

| | Plan verification | Pre-action gate |
|---|---|---|
| Scope | all paths through a declared plan | one actual call |
| Blind to | anything undeclared; the agent deviating | composition and sequencing |
| Answers | "could this plan ever violate?" | "is this call permitted right now?" |

The useful guarantee comes from both: verify the plan, then gate each action **against the approved plan**. That second step is what converts the untrusted effect declaration from a hole into an enforceable commitment — the agent declared what it would do, and the gate holds it to that.

## Fail-closed

- **Inconclusive denies.** A timeout or `unknown` is not a pass. "The solver could not decide" is indistinguishable from "there is a violation it could not find".
- **Cycles are rejected**, not approximated. Acyclicity is what keeps the obligation decidable; unroll to a declared bound instead.
- **A plan with no invariants is refused.** A verdict with nothing checked is unfalsifiable.
- **An unbounded symbol cannot satisfy a bound**, and the tool returns a counterexample saying so. That is correct — you cannot prove a limit over a quantity you never constrained. Declare `min`/`max`, or read the counterexample.

## Two solver traps, handled

Both were found by testing Z3 rather than trusting it, and both produce a **false safe** — the one direction this tool must never fail in. Both have regression tests.

1. **Context state leaks.** `eval_smtlib2_string` retains declarations and `set-logic` across calls on the same context. In testing, a genuinely violating plan reported `unsat` — *safe* — purely from the previous solve's leftover state. Every solve therefore runs in a **fresh context**.

2. **Errors do not stop the solve.** A malformed program emits `(error "...")` and then **continues**, printing a result derived from whatever it parsed — observed printing `sat` after erroring. Any `(error` in solver output forces `inconclusive`, and output is never read past it.

## Reproducibility caveats

- `timeout` and `random-seed` are embedded in the published program, since both affect the result.
- A re-runner on slower hardware may get `unknown` where a faster machine got `unsat`. The program is identical; the wall-clock budget is not. Compare `solver.version` before concluding a result disagrees.
- Solvers differ across versions. `solver.name` and `solver.version` are recorded for exactly this reason.

## Security notes

- **Effect declaration is the trust boundary.** The cheapest attack is not defeating the solver — it is lying in the declaration. Defences make the declaration *accountable*, not trustworthy.
- **Solver trust.** A backdoored solver reporting `unsat` yields a false proof. Prefer solvers that emit checkable UNSAT certificates, and publish the program so an independent solver can be run against it.
- **Denial of service.** Pathological plans can exhaust the verification budget. Because inconclusive denies, this is an availability attack rather than a safety failure — but enforce resource limits per plan, so one plan cannot starve others.
- **Information disclosure.** A published program discloses plan structure and enforced invariants. Where those are sensitive, publish the content hash and disclose under the audit relationship — but never silently omit it, because an unpublished program means the result is not independently checkable and the record must say so.

## Relationship to RFC-0005 quorum evidence

A verification result is **not** RFC-0005 `evidence[]`. That field exists for signals a third party *cannot* re-derive. An SMT result is fully reproducible from published artefacts, so filing it as evidence would understate it and blur the distinction the architecture depends on — between what an auditor can check and what they must take on trust. It gets first-class event types instead.

## License

Apache-2.0 — see [LICENSE](LICENSE).

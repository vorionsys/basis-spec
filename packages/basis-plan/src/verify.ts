// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Z3 driver for RFC-0006 plan verification.
 *
 * TWO TRAPS, both found by testing the solver rather than trusting it, and
 * both handled here as hard rules because each produces a FALSE SAFE — the one
 * direction a verification tool must never fail in:
 *
 * 1. CONTEXT STATE LEAKS. `eval_smtlib2_string` retains declarations and
 *    `set-logic` across calls on the same context. A second program then
 *    collides with the first's state, and observed behaviour was that a
 *    genuinely VIOLATING plan reported `unsat` — i.e. "safe" — purely from
 *    leftover state. Every solve therefore runs in a FRESH CONTEXT.
 *
 * 2. ERRORS DO NOT STOP THE SOLVE. A malformed program emits
 *    `(error "...")` and then CONTINUES, printing a result derived from
 *    whatever it managed to parse. A malformed encoding was observed printing
 *    `sat` after its errors. Any `(error` in solver output therefore forces
 *    `inconclusive`, and output is never parsed past it.
 *
 * Both rules are covered by tests. Neither is theoretical.
 */

import { createHash } from 'node:crypto';
import { encodePlan, type EncodedPlan } from './encode.js';
import type {
  ExecutionPlan,
  PlanOutcome,
  PlanVerification,
  SolverResult,
  VerificationRecord,
} from './types.js';

export interface VerifyOptions {
  /** Solver wall-clock budget in ms, embedded in the program. Default 10_000. */
  readonly timeoutMs?: number;
  /** Z3 random seed, embedded and recorded so results are reproducible. Default 0. */
  readonly seed?: number;
  /** Hard JS-level guard in case the solver does not honour its own timeout. */
  readonly hardTimeoutMs?: number;
}

/** Minimal shape of the pieces of `z3-solver` we use. */
interface Z3Module {
  Z3: {
    eval_smtlib2_string(ctxPtr: unknown, smt: string): Promise<string>;
    get_full_version(): string;
  };
  Context: new (name: string) => { ptr: unknown };
}

let z3Promise: Promise<Z3Module> | null = null;
let contextSeq = 0;

/** Lazily initialise Z3. The WASM module is expensive; init once per process. */
async function getZ3(): Promise<Z3Module> {
  if (z3Promise === null) {
    z3Promise = (async () => {
      const mod = (await import('z3-solver')) as unknown as {
        init: () => Promise<Z3Module>;
      };
      return mod.init();
    })();
  }
  return z3Promise;
}

const sha256 = (s: string): string => createHash('sha256').update(s, 'utf-8').digest('hex');

function preamble(opts: Required<Pick<VerifyOptions, 'timeoutMs' | 'seed'>>): string {
  // These options are part of the published program on purpose: they affect
  // the result, so a re-runner must apply the same ones.
  return [
    `(set-option :timeout ${opts.timeoutMs})`,
    `(set-option :random-seed ${opts.seed})`,
  ].join('\n');
}

interface RawRun {
  readonly raw: string;
  /** Set when the program could not be trusted as solved-as-written. */
  readonly failure?: string;
}

interface DecisionSolve extends RawRun {
  readonly result: SolverResult;
  readonly diagnostic?: string;
}

/**
 * Run one program in a FRESH context and return its raw output.
 *
 * TRAP 1: contexts leak declarations and `set-logic` between programs, and a
 * leaked state was observed making a violating plan report `unsat`. A new
 * context per run is the fix, and it is not optional.
 *
 * TRAP 2 is applied here too: any `(error` marks the run as untrusted, because
 * z3 continues after an error and prints a result derived from whatever it
 * managed to parse.
 */
async function runProgram(program: string, hardTimeoutMs: number): Promise<RawRun> {
  const { Z3, Context } = await getZ3();
  const ctx = new Context(`basis-plan-${contextSeq++}`);

  let raw: string;
  try {
    raw = await Promise.race([
      Z3.eval_smtlib2_string(ctx.ptr, program),
      new Promise<string>((_, reject) =>
        setTimeout(
          () => reject(new Error(`solver exceeded hard timeout of ${hardTimeoutMs}ms`)),
          hardTimeoutMs,
        ),
      ),
    ]);
  } catch (err) {
    return { raw: '', failure: `solver invocation failed: ${(err as Error).message}` };
  }

  const trimmed = raw.trim();
  if (trimmed.includes('(error')) {
    const firstError = trimmed
      .split('\n')
      .find((l) => l.includes('(error'))
      ?.trim();
    return {
      raw: trimmed,
      failure: `solver reported an error; result not trusted: ${firstError ?? '(unparsed)'}`,
    };
  }
  return { raw: trimmed };
}

/**
 * Run the DECISION program and classify its output strictly.
 *
 * The decision program ends at `(check-sat)`, so its entire output must be
 * exactly one of `sat`, `unsat`, `unknown`. Anything else — extra output,
 * an error, a hang — is `unknown`, which denies.
 *
 * This strictness applies ONLY to the decision path. The diagnostic run that
 * extracts a counterexample legitimately produces a model and value bindings,
 * and is read with {@link runProgram} directly.
 */
async function solveDecision(program: string, hardTimeoutMs: number): Promise<DecisionSolve> {
  const run = await runProgram(program, hardTimeoutMs);
  if (run.failure) return { ...run, result: 'unknown', diagnostic: run.failure };

  if (run.raw === 'sat') return { ...run, result: 'sat' };
  if (run.raw === 'unsat') return { ...run, result: 'unsat' };
  if (run.raw === 'unknown') {
    return { ...run, result: 'unknown', diagnostic: 'solver returned unknown' };
  }
  return {
    ...run,
    result: 'unknown',
    diagnostic: `unrecognised solver output: ${JSON.stringify(run.raw.slice(0, 200))}`,
  };
}

/** Map a solver result to an RFC-0006 outcome. Only `unsat` may be safe. */
function toOutcome(result: SolverResult): PlanOutcome {
  if (result === 'unsat') return 'proved_safe';
  if (result === 'sat') return 'counterexample';
  return 'inconclusive';
}

/**
 * Verify an already-encoded plan.
 *
 * Exposed separately from {@link verifyPlan} so a caller can inspect or publish
 * the encoding before solving.
 */
export async function verifyEncoded(
  planId: string,
  encoded: EncodedPlan,
  opts: VerifyOptions = {},
): Promise<PlanVerification> {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const seed = opts.seed ?? 0;
  const hardTimeoutMs = opts.hardTimeoutMs ?? timeoutMs + 5_000;

  // The DECISION program: this is what is published, and re-running it
  // reproduces the verdict. Diagnostics are obtained separately so that a
  // `get-model` against an UNSAT result cannot inject an `(error` into the
  // artefact that decided the outcome.
  const decision = `${preamble({ timeoutMs, seed })}\n${encoded.smtlib2}`;

  const started = Date.now();
  const solved = await solveDecision(decision, hardTimeoutMs);
  const durationMs = Date.now() - started;

  const { Z3 } = await getZ3();
  const record: VerificationRecord = {
    logic: encoded.logic,
    result: solved.result,
    solver: { name: 'z3', version: Z3.get_full_version(), seed: String(seed) },
    smtlib2: decision,
    smtlib2Hash: sha256(decision),
    durationMs,
    ...(solved.diagnostic ? { diagnostic: solved.diagnostic } : {}),
  };

  const outcome = toOutcome(solved.result);

  if (outcome !== 'counterexample') {
    return {
      planId,
      outcome,
      invariantsChecked: encoded.invariantIds,
      verification: record,
    };
  }

  // SAT — extract the counterexample. It is the audit artefact: it names the
  // exact assignment under which the plan violates.
  const violationVars = encoded.violationClauses.map((v) => `|v:${v.id}|`).join(' ');
  const augmented = `${decision}\n(get-model)\n(get-value (${violationVars}))\n`;
  // Read with runProgram, not solveDecision: a model and value bindings are
  // expected here, so the strict single-token classifier does not apply.
  const diag = await runProgram(augmented, hardTimeoutMs);

  // Diagnostic only. If it fails, the verdict still stands — we simply have no
  // counterexample to show, and say so by omitting it rather than inventing one.
  const model = !diag.failure && diag.raw.length > 0 ? diag.raw : undefined;

  const violated = encoded.violationClauses
    .filter((v) => new RegExp(`\\|v:${v.id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\|\\s+true`).test(diag.raw))
    .map((v) => v.id);

  return {
    planId,
    outcome,
    invariantsChecked: encoded.invariantIds,
    verification: { ...record, ...(model ? { model } : {}) },
    ...(violated.length > 0 ? { violated } : {}),
  };
}

/**
 * Encode and verify an execution plan.
 *
 * A `proved_safe` result means exactly: no path through the declared graph,
 * under the declared effect semantics, reaches a state violating the declared
 * invariants. It does NOT mean the action is safe — declared effects are a
 * trust input, and a plan can be provably safe and still commercially
 * catastrophic. See RFC-0006 §"What this verifies — and what it does not".
 */
export async function verifyPlan(
  plan: ExecutionPlan,
  opts: VerifyOptions = {},
): Promise<PlanVerification> {
  const encoded = encodePlan(plan);
  return verifyEncoded(plan.planId, encoded, opts);
}

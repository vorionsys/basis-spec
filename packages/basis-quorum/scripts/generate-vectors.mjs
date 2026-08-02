#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Generates the golden quorum-round vectors in ../vectors/.
 *
 * TWO INDEPENDENCE PROPERTIES this script is responsible for:
 *
 * 1. It carries its OWN canonicalizer, written from the RFC-0002 text rather
 *    than imported from the library, and re-derives every `eventHash` with it.
 *    If the two ever disagree, generation fails. Sharing the implementation
 *    would make the check circular and prove nothing.
 *
 * 2. The interesting tamper vectors are RE-SEALED, not mutated. A coordinator
 *    that doctors a resolution can recompute its hash and re-attest it with the
 *    group key, producing a chain whose hashes, linkage and signatures are all
 *    perfect. Those vectors pass `verifyChain()` and are caught ONLY by
 *    `verifyQuorumRound()` — which is the entire point of having a second pass.
 *    Naively mutating a payload would break the hash and prove nothing about
 *    the quorum checks.
 *
 * Everything is deterministic — seeded DRBG, fixed key seeds, fixed clock,
 * sequential event ids — so regeneration is byte-identical and a diff means
 * something actually changed.
 *
 * Usage: node scripts/generate-vectors.mjs
 */

import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  createGroupViaDkg,
  createLocalValidator,
  runQuorumRound,
  buildKeyring,
  sealEvent,
  attachSignature,
  aggregateAttestation,
  FROST_ED25519_SUITE,
} from '../dist/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTORS = join(HERE, '..', 'vectors');

// --- Independent canonicalizer, from the RFC-0002 text ----------------------

function canon(v) {
  if (v === null) return 'null';
  const t = typeof v;
  if (t === 'boolean') return v ? 'true' : 'false';
  if (t === 'number') {
    if (!Number.isFinite(v)) throw new Error('non-finite number');
    return String(v);
  }
  if (t === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  if (t === 'object') {
    const parts = [];
    for (const k of Object.keys(v).sort()) {
      if (v[k] === undefined) continue;
      parts.push(`${JSON.stringify(k)}:${canon(v[k])}`);
    }
    return `{${parts.join(',')}}`;
  }
  throw new Error(`unsupported type ${t}`);
}

function independentHash(ev) {
  const input = canon({
    agentId: ev.agentId ?? '',
    eventType: ev.eventType,
    occurredAt: ev.occurredAt,
    payload: ev.payload,
    previousHash: ev.previousHash ?? null,
  });
  return createHash('sha256').update(Buffer.from(input, 'utf-8')).digest('hex');
}

/** Cross-check the library's hashes and linkage against this file's own reading of the spec. */
function crossCheck(chain, label) {
  let previous = null;
  chain.forEach((ev, i) => {
    const expected = independentHash(ev);
    if (ev.eventHash !== expected) {
      throw new Error(
        `[${label}] event ${i} (${ev.eventType}): library hash ${ev.eventHash} != independent hash ${expected} — the two canonicalizers disagree`,
      );
    }
    if ((ev.previousHash ?? null) !== previous) {
      throw new Error(`[${label}] event ${i}: linkage break`);
    }
    previous = ev.eventHash;
  });
}

// --- Deterministic DRBG (fixtures only) -------------------------------------

function makeDrbg(seedHex) {
  let counter = 0;
  return (len = 32) => {
    const out = Buffer.alloc(len);
    let off = 0;
    while (off < len) {
      const block = createHash('sha256')
        .update(Buffer.from(seedHex, 'hex'))
        .update(Buffer.from(String(counter++), 'utf-8'))
        .digest();
      const take = Math.min(block.length, len - off);
      block.copy(out, off, 0, take);
      off += take;
    }
    return new Uint8Array(out);
  };
}

// --- Fixed fixture identities ------------------------------------------------

const GROUP_ID = 'did:vorion:quorum:prod-destructive#frost-ed25519';
const VALIDATORS = [
  { id: 'did:vorion:validator:alpha#ed25519', seed: '1'.repeat(64), family: 'family-a' },
  { id: 'did:vorion:validator:beta#ed25519', seed: '2'.repeat(64), family: 'family-b' },
  { id: 'did:vorion:validator:gamma#ed25519', seed: '3'.repeat(64), family: 'family-c' },
  { id: 'did:vorion:validator:delta#ed25519', seed: '4'.repeat(64), family: 'policy-engine' },
];

const CORRELATION = 'e8b1d2c3-4a5f-4b6c-8d9e-0f1a2b3c4d5e';
const PROPOSER = 'agent:proposer-01';
const DEADLINE = '2026-08-02T14:00:30.000Z';

/** Fixed clock — one tick per call, so rounds are byte-stable. */
function makeClock() {
  let t = 0;
  return () => {
    const ms = 100 * t++;
    const s = String(Math.floor(ms / 1000)).padStart(2, '0');
    const frac = String(ms % 1000).padStart(3, '0');
    return `2026-08-02T14:00:${s}.${frac}Z`;
  };
}

function makeIds(prefix) {
  let i = 0;
  return () => {
    const k = String(i++).padStart(2, '0');
    return `${prefix}${k}-0000-4000-8000-000000000000`;
  };
}

const proposal = (quorumId) => ({
  quorumId,
  intentId: 'i-9f3a2b1c-7d6e-4f5a-8b9c-0d1e2f3a4b5c',
  proposerAgentId: PROPOSER,
  action: 'DROP TABLE production.customer_ledger',
  actionType: 'db.schema.destructive',
  resourceScope: ['db:production.customer_ledger'],
  riskLevel: 'LIFE_CRITICAL',
  proposerTier: 'T5',
});

/** Build the four validators with a fixed vote script. Index 3 never responds. */
function buildValidators(votes) {
  return VALIDATORS.map((v, i) =>
    createLocalValidator({
      validatorId: v.id,
      privateKey: v.seed,
      attributes: { independence: v.family },
      evaluate: async () => {
        if (votes[i] === null) {
          // Non-responder: never settles within the round's budget.
          await new Promise(() => {});
        }
        return {
          vote: votes[i].vote,
          rationale: votes[i].rationale,
          evidence: [
            {
              kind: 'policy-check',
              source: 'basis_core_security',
              version: '1.4.0',
              fired: votes[i].vote === 'reject',
            },
          ],
        };
      },
    }),
  );
}

async function buildRound({ quorumId, votes, seed, idPrefix }) {
  const rng = makeDrbg(seed);
  const validators = buildValidators(votes);
  const group = createGroupViaDkg({
    groupId: GROUP_ID,
    validatorIds: VALIDATORS.map((v) => v.id),
    m: 3,
    rng,
  });

  const result = await runQuorumRound({
    group,
    validators,
    proposal: proposal(quorumId),
    policyId: 'basis_risk_thresholds:life_critical_requires_quorum',
    correlationId: CORRELATION,
    deadline: DEADLINE,
    now: makeClock(),
    nextEventId: makeIds(idPrefix),
    timeoutMs: 50,
    rng,
  });

  return { group, validators, result, rng };
}

/**
 * Re-seal a doctored resolution onto an existing prefix, re-attesting with the
 * group key. Produces a chain that is cryptographically flawless and
 * semantically false.
 */
function reseal(group, prefix, doctoredPayload, occurredAt, eventId, rng, attesterIds) {
  const previousHash = prefix[prefix.length - 1].eventHash;
  const sealed = sealEvent(
    {
      eventId,
      eventType: 'quorum_resolved',
      correlationId: CORRELATION,
      agentId: PROPOSER,
      payload: doctoredPayload,
      occurredAt,
      recordedAt: occurredAt,
      shadowMode: 'production',
    },
    previousHash,
  );
  const aggregate = aggregateAttestation(group, attesterIds, sealed.bytes, rng);
  return [
    ...prefix,
    attachSignature(sealed, group.groupId, Buffer.from(aggregate).toString('base64')),
  ];
}

// --- Generate -----------------------------------------------------------------

mkdirSync(VECTORS, { recursive: true });
const write = (name, data) =>
  writeFileSync(join(VECTORS, name), JSON.stringify(data, null, 2) + '\n', 'utf-8');

const R = (rationale) => ({ vote: 'reject', rationale });
const A = (rationale) => ({ vote: 'approve', rationale });

// 1. Valid APPROVED round — 3 approve, delta never responds.
const approved = await buildRound({
  quorumId: 'q-approved-0001',
  votes: [
    A('matches approved decommission ticket DEC-4417'),
    A('scope limited to a table already marked for deletion'),
    A('no downstream consumers registered'),
    null,
  ],
  seed: 'a'.repeat(64),
  idPrefix: 'aa',
});
crossCheck(approved.result.events, 'approved');
write('round-approved.json', approved.result.events);

// 2. Valid REJECTED round — 1 approve, 2 reject, delta never responds.
const rejected = await buildRound({
  quorumId: 'q-rejected-0001',
  votes: [
    R('irreversible destruction of a production ledger; no restore point cited'),
    R('resource scope names a financial system of record'),
    A('matches approved decommission ticket'),
    null,
  ],
  seed: 'b'.repeat(64),
  idPrefix: 'bb',
});
crossCheck(rejected.result.events, 'rejected');
write('round-rejected.json', rejected.result.events);

// --- Tampered variants, all re-sealed so they pass verifyChain ---------------

const rejEvents = rejected.result.events;
const rejPrefix = rejEvents.slice(0, -1); // request + 3 votes
const rejResolution = rejEvents[rejEvents.length - 1].payload;
const responders = rejected.result.events
  .filter((e) => e.eventType === 'validator_vote')
  .map((e) => e.payload.validatorId);
const resolvedAt = rejResolution.resolvedAt;

// 3. Outcome flipped to approved despite only 1 approval.
write(
  'tamper-approved-below-threshold.json',
  reseal(
    rejected.group,
    rejPrefix,
    { ...rejResolution, outcome: 'approved' },
    resolvedAt,
    'cc00-0000-4000-8000-000000000000',
    makeDrbg('c'.repeat(64)),
    responders,
  ),
);

// 4. Tally inflated to claim 3 approvals that were never cast.
write(
  'tamper-tally-mismatch.json',
  reseal(
    rejected.group,
    rejPrefix,
    {
      ...rejResolution,
      outcome: 'approved',
      tally: { approve: 3, reject: 0, abstain: 0, noResponse: 1 },
    },
    resolvedAt,
    'dd00-0000-4000-8000-000000000000',
    makeDrbg('d'.repeat(64)),
    responders,
  ),
);

// 5. A dissenting validator dropped entirely — never chained, never listed as a
//    non-responder. Hashes, linkage and signatures are all perfect; only the
//    validator-set accounting catches it.
{
  const keptVotes = rejEvents.filter(
    (e) => e.eventType === 'validator_vote' && e.payload.vote !== 'reject',
  );
  const dropped = rejEvents.filter(
    (e) => e.eventType === 'validator_vote' && e.payload.vote === 'reject',
  );
  // Rebuild the prefix without the dropped dissents so linkage stays intact.
  const builder = [];
  let prev = null;
  for (const ev of [rejEvents[0], ...keptVotes]) {
    const resealed = sealEvent(
      {
        eventId: ev.eventId,
        eventType: ev.eventType,
        correlationId: ev.correlationId,
        agentId: ev.agentId,
        payload: ev.payload,
        occurredAt: ev.occurredAt,
        recordedAt: ev.recordedAt,
        shadowMode: ev.shadowMode,
      },
      prev,
    );
    // Vote signatures cannot be forged — the coordinator lacks validator keys —
    // so the surviving votes keep their original signatures. Re-sealing changes
    // previousHash, so these signatures will NOT verify. That is faithful: a
    // coordinator really cannot silently re-order a signed chain. The vector
    // exists to exercise the accounting check, which runs regardless.
    builder.push(ev.signedBy ? attachSignature(resealed, ev.signedBy, ev.signature) : resealed.event);
    prev = resealed.event.eventHash;
  }
  const doctored = {
    ...rejResolution,
    outcome: 'approved',
    tally: { approve: 1, reject: 0, abstain: 0, noResponse: 1 },
    votesRecorded: keptVotes.map((e) => e.eventId),
  };
  write(
    'tamper-suppressed-dissent.json',
    reseal(
      rejected.group,
      builder,
      doctored,
      resolvedAt,
      'ee00-0000-4000-8000-000000000000',
      makeDrbg('e'.repeat(64)),
      responders,
    ),
  );
  if (dropped.length === 0) throw new Error('expected at least one dissent to drop');
}

// 6. Resolution signed by an individual member instead of the group key.
{
  const chain = rejEvents.slice();
  const last = { ...chain[chain.length - 1], signedBy: VALIDATORS[0].id };
  chain[chain.length - 1] = last;
  write('tamper-individually-signed-resolution.json', chain);
}

// --- Keyrings -----------------------------------------------------------------

write('keys-approved.json', buildKeyring(approved.validators, approved.group));
write('keys-rejected.json', buildKeyring(rejected.validators, rejected.group));

process.stdout.write(
  `wrote vectors to ${VECTORS}\n` +
    `  approved group key: ${approved.group.groupPublicKey}\n` +
    `  rejected group key: ${rejected.group.groupPublicKey}\n` +
    `  approved outcome:   ${approved.result.outcome} (${JSON.stringify(approved.result.tally)})\n` +
    `  rejected outcome:   ${rejected.result.outcome} (${JSON.stringify(rejected.result.tally)})\n`,
);

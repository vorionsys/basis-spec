// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Vorion LLC

/**
 * Public reference verifier for RFC-0002 proof event chains.
 *
 * This is the implementation of RFC-0002 §"Verification procedure". Unlike
 * `validateManifest` (which is truth-only/structural and deliberately does
 * NOT touch cryptography), this module actually:
 *
 *   1. Rebuilds each event's canonical-JSON byte string from the hashable
 *      fields (RFC-0002 §"Canonical serialization").
 *   2. Recomputes `eventHash` (sha256) and, when present, `eventHash3`
 *      (sha3-256) over those same bytes, and compares to what was stored.
 *   3. Confirms `previousHash` linkage forms a strictly linear chain, with
 *      `null` at the head.
 *   4. Verifies detached Ed25519 signatures when a public key is supplied
 *      for the event's `signedBy` identity.
 *
 * It is dependency-free beyond `node:crypto` on purpose: an auditor should
 * be able to read this file end to end and believe it.
 *
 * FAIL-CLOSED POSTURE (consistent with the rest of this suite):
 *   - An empty chain is NEVER valid. Zero events is a runner error, not a
 *     pass — the same rule the conformance runner applies to zero tests.
 *   - A signature that is PRESENT but could not be checked (no key supplied,
 *     unsupported key, malformed signature) never silently counts as good.
 *     It is reported in `signaturesUnverified`, and under
 *     `requireSignatures: true` it makes the whole chain invalid.
 *   - A STRIPPED signature — `signedBy` present, `signature` gone — is always
 *     a hard failure, with or without `requireSignatures`. It is the cheapest
 *     possible attack on a receipt chain (no key, no forgery, no hash work,
 *     just a delete) and must never read as "unsigned, that's fine".
 *   - `valid: true` means every check that ran passed AND no present-but-
 *     unverifiable signature was ignored under strict mode. It is an
 *     integrity verdict about the record — never a trust or compliance
 *     verdict about the agent.
 *
 * Spec reference: rfcs/0002-proof-event-chain.md
 */

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import {
  canonicalize,
  canonicalEventString,
  type HashableEventFields,
} from '@vorionsys/basis-spec';

// ---------------------------------------------------------------------------
// Canonical serialization (RFC-0002 §"Canonical serialization")
// ---------------------------------------------------------------------------

/**
 * The canonicalizer is NORMATIVE and lives in `@vorionsys/basis-spec`
 * alongside the proof-event types, so that the verifier, the quorum
 * reference implementation, and any vendor runtime hash identical bytes by
 * construction rather than by careful re-implementation. It is re-exported
 * here because this package has been its public entry point since v0.2.0.
 */
export { canonicalize, canonicalEventString, type HashableEventFields };

/**
 * UTF-8 bytes of the canonical event string — the exact hash/signature input.
 *
 * Returns a `Buffer` (rather than the spec package's platform-neutral
 * `Uint8Array`) because that has been this function's published return type
 * since v0.2.0 and consumers may depend on Buffer methods.
 */
export function canonicalEventBytes(event: HashableEventFields): Buffer {
  return Buffer.from(canonicalEventString(event), 'utf-8');
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

function sha256Hex(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * sha3-256 is OPTIONAL in RFC-0002. It is available in Node builds linked
 * against OpenSSL 3; where it is not, we must say so rather than quietly
 * skipping the check.
 */
function sha3_256HexOrNull(bytes: Buffer): string | null {
  try {
    return createHash('sha3-256').update(bytes).digest('hex');
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Ed25519 key + signature handling
// ---------------------------------------------------------------------------

/** DER SPKI prefix for an Ed25519 public key (RFC 8410). */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

const HEX_64 = /^[0-9a-f]{64}$/i;

/**
 * Accept an Ed25519 public key as:
 *   - a PEM SPKI string ("-----BEGIN PUBLIC KEY-----...")
 *   - a raw 32-byte key, hex-encoded (64 hex chars)
 *   - a raw 32-byte key, base64-encoded
 *   - an already-constructed node KeyObject
 *
 * Raw forms are wrapped into DER SPKI so `createPublicKey` accepts them.
 * Throws on anything else — an unparseable key must never degrade into
 * "signature skipped".
 */
export function toEd25519PublicKey(key: string | KeyObject): KeyObject {
  if (typeof key !== 'string') return key;

  const trimmed = key.trim();
  if (trimmed.includes('BEGIN PUBLIC KEY')) {
    return createPublicKey(trimmed);
  }

  let raw: Buffer;
  if (HEX_64.test(trimmed)) {
    raw = Buffer.from(trimmed, 'hex');
  } else {
    raw = Buffer.from(trimmed, 'base64');
  }
  if (raw.length !== 32) {
    throw new Error(
      `Ed25519 public key must be 32 bytes (got ${raw.length}); ` +
        'supply PEM SPKI, 64-char hex, or base64 of the raw key',
    );
  }
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

function decodeSignature(sig: string): Buffer {
  const trimmed = sig.trim();
  const buf = /^[0-9a-f]{128}$/i.test(trimmed)
    ? Buffer.from(trimmed, 'hex')
    : Buffer.from(trimmed, 'base64');
  if (buf.length !== 64) {
    throw new Error(`Ed25519 signature must be 64 bytes (got ${buf.length})`);
  }
  return buf;
}

/**
 * RFC-0002 carries an ambiguity the reference verifier has to face
 * head-on. §"Schema" annotates `signature` as "detached signature over
 * eventHash", while §"Verification procedure" step 5 says to verify "the
 * detached signature over the canonical bytes". Those are different
 * messages and a signature valid under one is invalid under the other.
 *
 * This verifier treats the normative Verification procedure as
 * authoritative and signs/verifies over the CANONICAL BYTES by default.
 * When a signature fails under the primary domain, we retry under the
 * other and, if that succeeds, report `signature-domain-mismatch` — a
 * precise interop diagnostic instead of a bare "bad signature".
 *
 * Tracked for spec erratum; see the note in the package README.
 */
export type SignatureDomain = 'canonical' | 'eventHash';

function signatureMessage(
  domain: SignatureDomain,
  canonicalBytes: Buffer,
  eventHash: string,
): Buffer {
  return domain === 'canonical' ? canonicalBytes : Buffer.from(eventHash, 'utf-8');
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/**
 * Stable, machine-readable reject reasons.
 *
 * `problem` is prose and will be reworded; nothing should ever be compared
 * against it. These codes are the compared contract: a second implementation
 * can assert that it rejects a vector *for the same reason*, rather than only
 * that it rejected. A bare boolean makes "reject" untestable — two verifiers
 * can agree a chain is bad while disagreeing completely about what is wrong
 * with it, and that agreement is worth nothing.
 *
 * These strings are API. Renaming one is a breaking change.
 *
 * NOTE: a code is not by itself a rejection. `HASH3_UNSUPPORTED` records that
 * a check could not run in this Node build; the event still passes. Whether a
 * chain was rejected is `valid`, never the presence of a code.
 */
export type FailureCode =
  // Chain-level — the whole input was refused before or after per-event work.
  | 'CHAIN_NOT_ARRAY'
  | 'CHAIN_EMPTY'
  | 'PUBLIC_KEY_UNUSABLE'
  | 'SIGNATURES_REQUIRED_SHORTFALL'
  // Structure
  | 'EVENT_MALFORMED'
  | 'PAYLOAD_NOT_CANONICALIZABLE'
  // Linkage
  | 'CHAIN_HEAD_NOT_NULL'
  | 'LINKAGE_MISMATCH'
  // Hashes
  | 'EVENT_HASH_MISMATCH'
  | 'EVENT_HASH3_MISMATCH'
  | 'HASH3_UNSUPPORTED'
  // Signatures — the split here is the point of the whole suite.
  | 'SIGNATURE_STRIPPED'
  | 'SIGNATURE_UNVERIFIED_NO_KEY'
  | 'SIGNATURE_NO_SIGNER_IDENTITY'
  | 'SIGNATURE_DOMAIN_MISMATCH'
  | 'SIGNATURE_INVALID'
  | 'SIGNATURE_UNUSABLE';

/** Per-event outcome. `null` fields mean "check did not run". */
export interface EventVerification {
  readonly index: number;
  readonly eventId: string;
  /** Recomputed sha256 matched the stored `eventHash`. */
  readonly hashValid: boolean;
  /** Recomputed sha3-256 matched `eventHash3`; null when absent/unsupported. */
  readonly hash3Valid: boolean | null;
  /** `previousHash` matched the prior event's `eventHash` (or null at head). */
  readonly linkageValid: boolean;
  /**
   * Signature outcome:
   *   'valid'         — verified against the supplied key
   *   'invalid'       — key supplied, signature did not verify
   *   'domain-mismatch' — verified only under the OTHER signature domain
   *   'unverified'    — signature present but no usable key was supplied
   *   'stripped'      — `signedBy` claims a signer but `signature` is gone
   *   'absent'        — neither `signedBy` nor `signature`: legitimately
   *                     unsigned, integrity resting on the hash chain alone
   *
   * The 'stripped' / 'absent' split is load-bearing. Collapsing them lets an
   * attacker downgrade a signed chain to an "unsigned" one by deleting a
   * field, and a verifier that cannot tell the difference will call the
   * result valid.
   */
  readonly signature:
    | 'valid'
    | 'invalid'
    | 'domain-mismatch'
    | 'unverified'
    | 'stripped'
    | 'absent';
  /** Human-readable detail for whichever check failed. Prose — never compare on it. */
  readonly problem?: string;
  /** Machine-readable counterpart to `problem`. Compare on this. */
  readonly failureCode?: FailureCode;
}

/**
 * Superset of the spec's `ChainVerificationResult`. The six spec fields are
 * present verbatim so this is drop-in for any consumer coded against
 * `@vorionsys/basis-spec`; the rest is diagnostic detail.
 */
export interface ChainVerificationReport {
  readonly valid: boolean;
  readonly verifiedEvents: number;
  readonly firstEventId: string;
  readonly lastEventId: string;
  readonly brokenAt?: string;
  readonly error?: string;
  /**
   * Why this chain was rejected, machine-readable. Present whenever
   * `valid` is false; absent when it is true. For a chain broken at an event
   * this is that event's code, so `{brokenAt, failureCode}` together say
   * where and why without parsing prose.
   */
  readonly failureCode?: FailureCode;

  readonly signaturesValid: number;
  readonly signaturesInvalid: number;
  /** Present-but-uncheckable signatures. Non-zero is never silently OK. */
  readonly signaturesUnverified: number;
  /**
   * Events whose `signedBy` survived but whose `signature` did not. Any
   * non-zero value here already forced `valid: false`.
   */
  readonly signaturesStripped: number;
  readonly hash3Checked: number;
  readonly events: ReadonlyArray<EventVerification>;
}

export interface VerifyChainOptions {
  /**
   * Map of `signedBy` identity → Ed25519 public key. Events whose
   * `signedBy` is absent from this map report `unverified`.
   */
  readonly publicKeys?: Readonly<Record<string, string | KeyObject>>;
  /**
   * When true, every event must carry a signature that actually VERIFIED.
   * Unverifiable, stripped and absent signatures all invalidate the chain.
   *
   * Default false — but note that a stripped signature fails regardless of
   * this setting, and the counts are always surfaced either way.
   *
   * Changed in 0.3.0: this previously covered only present-but-unverifiable
   * signatures, so `requireSignatures` accepted a chain carrying no
   * signatures at all — which is the opposite of what the name promises.
   */
  readonly requireSignatures?: boolean;
  /** Which message the detached signature covers. Default 'canonical'. */
  readonly signatureDomain?: SignatureDomain;
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

interface RawEvent {
  eventId?: unknown;
  eventType?: unknown;
  agentId?: unknown;
  occurredAt?: unknown;
  payload?: unknown;
  previousHash?: unknown;
  eventHash?: unknown;
  eventHash3?: unknown;
  signedBy?: unknown;
  signature?: unknown;
}

function fail(error: string, failureCode: FailureCode): ChainVerificationReport {
  return {
    valid: false,
    verifiedEvents: 0,
    firstEventId: '',
    lastEventId: '',
    error,
    failureCode,
    signaturesValid: 0,
    signaturesInvalid: 0,
    signaturesUnverified: 0,
    signaturesStripped: 0,
    hash3Checked: 0,
    events: [],
  };
}

/**
 * Verify a proof event chain end to end per RFC-0002 §"Verification
 * procedure".
 *
 * @param chain  Events in chain order (already JSON-parsed).
 * @param opts   Public keys and strictness settings.
 * @returns A `ChainVerificationReport`. `valid: true` only when every
 *          event's hash recomputed correctly, linkage held from a null
 *          head, and no signature check failed (or was skipped under
 *          `requireSignatures`).
 *
 * This reports on the INTEGRITY OF THE RECORD only. A cryptographically
 * perfect chain of bad decisions verifies just fine — that is the point of
 * a receipt, and it is not a statement about the agent's trustworthiness.
 */
export function verifyChain(
  chain: unknown,
  opts: VerifyChainOptions = {},
): ChainVerificationReport {
  if (!Array.isArray(chain)) {
    return fail('chain must be a JSON array of proof events', 'CHAIN_NOT_ARRAY');
  }
  // Fail-closed: an empty chain is not a vacuous pass.
  if (chain.length === 0) {
    return fail(
      'chain is empty — refusing to report a valid verification (fail-closed)',
      'CHAIN_EMPTY',
    );
  }

  const domain: SignatureDomain = opts.signatureDomain ?? 'canonical';
  const otherDomain: SignatureDomain = domain === 'canonical' ? 'eventHash' : 'canonical';

  // Resolve keys once, up front. A malformed key is a hard error rather
  // than a per-event surprise.
  const keys = new Map<string, KeyObject>();
  for (const [id, key] of Object.entries(opts.publicKeys ?? {})) {
    try {
      keys.set(id, toEd25519PublicKey(key));
    } catch (err) {
      return fail(
        `public key for "${id}" is unusable: ${(err as Error).message}`,
        'PUBLIC_KEY_UNUSABLE',
      );
    }
  }

  const events: EventVerification[] = [];
  let signaturesValid = 0;
  let signaturesInvalid = 0;
  let signaturesUnverified = 0;
  let signaturesStripped = 0;
  let hash3Checked = 0;
  let brokenAt: string | undefined;
  let verifiedEvents = 0;

  let previousEventHash: string | null = null;

  for (let i = 0; i < chain.length; i++) {
    const ev = chain[i] as RawEvent;
    const eventId = typeof ev?.eventId === 'string' ? ev.eventId : `(index ${i})`;

    // Structural preconditions for the crypto to mean anything.
    if (
      typeof ev?.eventType !== 'string' ||
      typeof ev?.occurredAt !== 'string' ||
      typeof ev?.eventHash !== 'string' ||
      ev?.payload === undefined ||
      !('previousHash' in (ev ?? {}))
    ) {
      events.push({
        index: i,
        eventId,
        hashValid: false,
        hash3Valid: null,
        linkageValid: false,
        signature: 'absent',
        problem:
          'event is missing one of the hashable fields (eventType, occurredAt, payload, previousHash) or eventHash — run `validate` for a full structural report',
        failureCode: 'EVENT_MALFORMED',
      });
      brokenAt = eventId;
      break;
    }

    const prevHash = (ev.previousHash ?? null) as string | null;

    // --- Linkage (RFC-0002 §"Chain linkage") -------------------------------
    const linkageValid = i === 0 ? prevHash === null : prevHash === previousEventHash;

    // `problem` and `failureCode` are set together and first-wins, so the prose
    // and the code can never describe different things.
    let problem: string | undefined;
    let failureCode: FailureCode | undefined;
    const note = (code: FailureCode, text: string): void => {
      if (problem === undefined) {
        problem = text;
        failureCode = code;
      }
    };

    if (!linkageValid) {
      note(
        i === 0 ? 'CHAIN_HEAD_NOT_NULL' : 'LINKAGE_MISMATCH',
        i === 0
          ? `chain head must have previousHash null, got ${JSON.stringify(prevHash)}`
          : `previousHash ${JSON.stringify(prevHash)} does not match prior event's eventHash ${JSON.stringify(previousEventHash)}`,
      );
    }

    // --- Hash recomputation ------------------------------------------------
    let canonicalBytes: Buffer;
    try {
      canonicalBytes = canonicalEventBytes({
        previousHash: prevHash,
        eventType: ev.eventType,
        agentId: typeof ev.agentId === 'string' ? ev.agentId : undefined,
        occurredAt: ev.occurredAt,
        payload: ev.payload,
      });
    } catch (err) {
      events.push({
        index: i,
        eventId,
        hashValid: false,
        hash3Valid: null,
        linkageValid,
        signature: 'absent',
        problem: `payload is not canonicalizable: ${(err as Error).message}`,
        failureCode: 'PAYLOAD_NOT_CANONICALIZABLE',
      });
      brokenAt = eventId;
      break;
    }

    const recomputed = sha256Hex(canonicalBytes);
    const hashValid = recomputed === ev.eventHash;
    if (!hashValid) {
      note('EVENT_HASH_MISMATCH', `eventHash mismatch — recomputed ${recomputed}, stored ${ev.eventHash}`);
    }

    let hash3Valid: boolean | null = null;
    if (typeof ev.eventHash3 === 'string') {
      const recomputed3 = sha3_256HexOrNull(canonicalBytes);
      if (recomputed3 === null) {
        hash3Valid = null;
        // Non-fatal: the check did not run. Coded so a consumer can tell this
        // apart from a mismatch without reading the prose.
        note(
          'HASH3_UNSUPPORTED',
          'eventHash3 present but sha3-256 is unavailable in this Node build — check not run',
        );
      } else {
        hash3Valid = recomputed3 === ev.eventHash3;
        hash3Checked++;
        if (!hash3Valid) {
          note(
            'EVENT_HASH3_MISMATCH',
            `eventHash3 mismatch — recomputed ${recomputed3}, stored ${ev.eventHash3}`,
          );
        }
      }
    }

    // --- Signature ---------------------------------------------------------
    let signature: EventVerification['signature'] = 'absent';
    // Narrow to concrete strings rather than booleans, so the type checker
    // carries the narrowing into the branches below instead of us casting.
    const rawSignature = typeof ev.signature === 'string' && ev.signature.length > 0 ? ev.signature : null;
    const claimedSigner = typeof ev.signedBy === 'string' && ev.signedBy.length > 0 ? ev.signedBy : null;

    if (rawSignature === null && claimedSigner !== null) {
      // The event asserts it was signed by an identity and then offers
      // nothing to check that against. No legitimate producer emits this:
      // the vector generator writes signedBy and signature together or
      // neither. Treat it as tampering, not as an unsigned chain — and do
      // so unconditionally, because an attacker chooses whether the
      // verifier runs with --require-signatures and we do not.
      signature = 'stripped';
      signaturesStripped++;
      note(
        'SIGNATURE_STRIPPED',
        `event declares signedBy "${claimedSigner}" but carries no signature — signature stripped`,
      );
    } else if (rawSignature !== null) {
      const signer = claimedSigner ?? '';
      const key = signer ? keys.get(signer) : undefined;
      if (!key) {
        signature = 'unverified';
        signaturesUnverified++;
        if (signer) {
          note('SIGNATURE_UNVERIFIED_NO_KEY', `signature present but no public key supplied for signedBy "${signer}"`);
        } else {
          note(
            'SIGNATURE_NO_SIGNER_IDENTITY',
            'signature present but event has no signedBy identity to resolve a key',
          );
        }
      } else {
        try {
          const sig = decodeSignature(rawSignature);
          const ok = cryptoVerify(
            null,
            signatureMessage(domain, canonicalBytes, ev.eventHash),
            key,
            sig,
          );
          if (ok) {
            signature = 'valid';
            signaturesValid++;
          } else {
            // Retry under the other domain to produce a precise diagnostic.
            const okOther = cryptoVerify(
              null,
              signatureMessage(otherDomain, canonicalBytes, ev.eventHash),
              key,
              sig,
            );
            if (okOther) {
              signature = 'domain-mismatch';
              signaturesInvalid++;
              note(
                'SIGNATURE_DOMAIN_MISMATCH',
                `signature verifies over '${otherDomain}' but this verifier is checking '${domain}' — signer and verifier disagree on the signed message (RFC-0002 erratum)`,
              );
            } else {
              signature = 'invalid';
              signaturesInvalid++;
              note('SIGNATURE_INVALID', 'Ed25519 signature did not verify');
            }
          }
        } catch (err) {
          signature = 'invalid';
          signaturesInvalid++;
          note('SIGNATURE_UNUSABLE', `signature unusable: ${(err as Error).message}`);
        }
      }
    }

    events.push({
      index: i,
      eventId,
      hashValid,
      hash3Valid,
      linkageValid,
      signature,
      ...(problem ? { problem } : {}),
      ...(failureCode ? { failureCode } : {}),
    });

    const eventOk =
      hashValid &&
      linkageValid &&
      hash3Valid !== false &&
      signature !== 'invalid' &&
      signature !== 'domain-mismatch' &&
      signature !== 'stripped';

    if (!eventOk) {
      brokenAt = eventId;
      break;
    }

    verifiedEvents++;
    previousEventHash = ev.eventHash;
  }

  // Under requireSignatures every event must have reached 'valid'. Counting
  // shortfall rather than testing `signaturesUnverified > 0` is what makes
  // an all-absent chain fail too: 0 unverified but 0 valid is still 0 proof.
  const strict = opts.requireSignatures ?? false;
  const signatureShortfall = chain.length - signaturesValid;
  const strictFailure = strict && signatureShortfall > 0;

  const firstEventId =
    typeof (chain[0] as RawEvent)?.eventId === 'string'
      ? ((chain[0] as RawEvent).eventId as string)
      : '';
  const lastEventId =
    typeof (chain[chain.length - 1] as RawEvent)?.eventId === 'string'
      ? ((chain[chain.length - 1] as RawEvent).eventId as string)
      : '';

  const valid = brokenAt === undefined && verifiedEvents === chain.length && !strictFailure;

  // The chain's reject reason. A break at an event carries that event's code up,
  // so {brokenAt, failureCode} answers where and why together. A strict-mode
  // shortfall is a chain-level refusal and has its own code — it is not any one
  // event's fault, and reporting it as one would point the reader at the wrong
  // place. Never set when valid.
  const brokenEvent = brokenAt !== undefined ? events.find((e) => e.eventId === brokenAt) : undefined;
  const reportCode: FailureCode | undefined = valid
    ? undefined
    : brokenEvent?.failureCode ?? (strictFailure ? 'SIGNATURES_REQUIRED_SHORTFALL' : undefined);

  return {
    valid,
    verifiedEvents,
    firstEventId,
    lastEventId,
    ...(brokenAt !== undefined ? { brokenAt } : {}),
    ...(strictFailure
      ? {
          error:
            `requireSignatures is set but only ${signaturesValid} of ${chain.length} event(s) carry a verified signature ` +
            `(${signaturesUnverified} unverifiable, ${signaturesStripped} stripped, ${signaturesInvalid} invalid)`,
        }
      : {}),
    ...(reportCode ? { failureCode: reportCode } : {}),
    signaturesValid,
    signaturesInvalid,
    signaturesUnverified,
    signaturesStripped,
    hash3Checked,
    events,
  };
}

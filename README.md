# BASIS Spec

**Baseline Authority for Safe & Interoperable Systems** — an open standard for AI agent trust and governance.

## Packages

| Package | Description |
|---|---|
| [`@basis-spec/basis`](packages/basis) | Canonical TypeScript representation of the spec — tiers, risk levels, formulas, constants, types, optional Zod validators, **proof-chain shape**. |
| [`@basis-spec/basis-conformance`](packages/basis-conformance) | Test vectors any implementation can run against itself to verify BASIS conformance. *(stub — coming next)* |

## RFCs

| # | Title | Status |
|---|---|---|
| [0001](rfcs/0001-bot-package-manifest.md) | Bot Package Manifest v1 | Draft |
| [0002](rfcs/0002-proof-event-chain.md) | Proof Event Chain v1 — the public shape of every audit event a BASIS-compliant runtime emits, plus the hash-chain rules that make it tamper-evident. | Draft |

## Why an open standard

Runtime AI-agent governance needs interoperable primitives so that an agent
trusted by one platform can be evaluated by another, and so that compliance
auditors can read a single shared definition of "what does T5 mean."

BASIS is one attempt at that shared definition. It is intentionally narrow:
the standard fixes parameters, formulas, and lifecycle semantics. It does
**not** dictate which storage backend, transport protocol, or proof system
an implementation must use.

## License

Apache-2.0 — see [LICENSE](LICENSE).

Anyone may build conforming or non-conforming implementations under any
license they choose; this repository's contents are themselves Apache-2.0.

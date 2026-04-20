# RFC-0001: Bot Package Manifest v1

**Status:** Draft
**Date:** 2026-04-15
**Author:** Vorion LLC
**Related:** `@basis-spec/basis` canonical.ts (trust tiers, risk levels, lifecycle states)

---

## Summary

This RFC defines the **canonical declarative format** for a BASIS-compliant agent/bot package. Every bot that claims conformance with the BASIS standard ships with a `bot.manifest.yaml` at the root of its package. A BASIS-compliant runtime reads this manifest to enforce tier gating, capability restrictions, policy rules, and governance requirements.

The manifest is the single source of truth for what a bot **is** — its identity, capabilities, trust-tier requirements, policies, governance bindings, runtime hooks, and UX metadata. Docker images, framework bundles (LangGraph/CrewAI/AutoGen), and tarballs are build artifacts; the manifest is canonical.

---

## Motivation

Without a standard manifest:

- Buyers can't evaluate "is this bot safe for my Tier 4 policy?" without reading code
- Runtimes can't enforce consistent gating rules across different bot authors
- Marketplaces can't sort / filter / badge bots reliably
- Compliance teams have no machine-readable basis for certification audits
- Vorion attestations can't cryptographically bind to a structured object

The manifest gives buyers, runtimes, marketplaces, auditors, and signers a single object to reason about.

---

## Schema overview

A manifest has nine top-level sections:

```
identity          — who/what/version/license
tier              — trust-tier requirements and ceilings
capabilities      — tools, data scopes, APIs, certified LLMs
policy            — risk bounds, gating, escalation, kill-switch
governance        — attestation, fingerprint, proof chain, audit level
runtime           — framework, entry point, dependencies, required env
lifecycle         — provisioning, dormancy, vanquish triggers
compliance        — NIST / EU AI Act / HIPAA / SOC 2 claims
ui                — display metadata for marketplace rendering
```

Full JSON Schema in `0001-bot-package-manifest.schema.json`. YAML is the canonical serialization for human authors; JSON is used by runtimes and signers.

---

## Full manifest example

```yaml
# bot.manifest.yaml — example: Aurais Market Scout v1.0.0
basis_manifest_version: "1.0"

identity:
  id: "aurais-market-scout"            # kebab-case, globally unique within a namespace
  namespace: "vorion-llc"              # publisher namespace
  name: "Aurais Market Scout"
  version: "1.0.0"                     # semver
  license: "UNLICENSED"                # SPDX or "UNLICENSED" for commercial-only
  author: "Vorion LLC"
  homepage: "https://aurais.net/bots/market-scout"
  created_at: "2026-04-15T12:00:00Z"

tier:
  required_runtime_tier: 3             # minimum trust tier the runtime must support to host this bot
  starting_trust_score: 0              # initial score on install (0 = PROVISIONING per canonical.ts)
  max_earnable_tier: 4                 # ceiling — bot cannot progress above this even with good behavior
  inherits_operator_tier: false        # true = bot inherits the operator account's tier; false = independent

capabilities:
  tools:                               # each tool = one capability grant
    - name: "fetch_market_data"
      risk_level: "READ"               # one of: READ, LOW, MEDIUM, HIGH, CRITICAL, LIFE_CRITICAL
      description: "Pulls public price/volume data from market-data APIs"
    - name: "compute_indicators"
      risk_level: "READ"
      description: "Runs RSI/MACD/SMA calculations locally"
    - name: "send_notification"
      risk_level: "LOW"
      description: "Sends email/push to the user's registered address"
  data_scopes:
    reads:
      - "market:public-quotes"
      - "user:watchlist"
      - "user:alert-preferences"
    writes:
      - "user:briefings"               # bot writes its briefing artifacts under this scope
  api_endpoints:
    - host: "www.alphavantage.co"
      methods: ["GET"]
    - host: "finance.yahoo.com"
      methods: ["GET"]
  certified_models:                    # LLMs this bot has been validated against
    - provider: "anthropic"
      model: "claude-sonnet-4-5"
    - provider: "anthropic"
      model: "claude-opus-4-5"

policy:
  max_action_risk_level: "LOW"         # bot may not attempt any action above this risk tier
  gating:
    pre_action: true                   # every action passes through pre_action_gate
    rate_limits:
      - scope: "send_notification"
        max_per_hour: 20
      - scope: "fetch_market_data"
        max_per_minute: 30
    blocked_tools: []                  # operator can extend at runtime
  escalation:
    enabled: false                     # this bot doesn't delegate; simple single-agent
    route_to: null
  circuit_breaker:
    trust_below: 100                   # if trust drops below this, bot halts until reinstated
    error_rate_window_minutes: 10
    error_rate_threshold: 0.25
  kill_switch:
    user_pausable: true                # user can pause in one click
    operator_pausable: true            # Vorion can pause globally
    self_pause_on_anomaly: true

governance:
  attestation:
    issuer: "Vorion LLC"
    signing_key_id: "vorion-root-2026-01"
    signed_at: null                    # filled in by signer at cert issuance
    signature: null                    # ed25519 over canonical JSON of this manifest
  paramesphere:
    fingerprint: null                  # filled in at bot-training/sealing time
    reference_workload: "market-scout-reference-v1"
  proof_chain:
    enabled: true
    audit_level: "full"                # one of: basic, full, attested
  signed_actions:
    min_risk_level_requiring_signature: "LOW"

runtime:
  framework: "langgraph"               # langgraph | crewai | autogen | custom
  entry_point: "src/main.py"
  runtime_version: ">=0.2.0,<0.3.0"
  dependencies:
    python: ">=3.11"
    packages:
      - "anthropic>=0.40.0"
      - "langgraph>=0.2.0"
      - "yfinance>=0.2.40"
      - "pandas>=2.2.0"
  required_env:                        # names only — never secrets here
    - name: "ANTHROPIC_API_KEY"
      required: true
      description: "Operator's LLM API key"
    - name: "AURAIS_BOT_ID"
      required: true
      description: "Auto-injected by the Aurais runtime"

lifecycle:
  provisioning:
    behavior: "training-course"        # training-course | auto-promote | manual-review
    reach_tier_at: 1                   # once training course passes, advance to this tier
  dormancy:
    deduction_enabled: true            # follow canonical.ts dormancy milestones
    notify_user_at_days: [7, 28]
  vanquish_triggers:
    consecutive_critical_failures: 3
    trust_below_100_for_days: 14

compliance:
  frameworks:
    - name: "NIST AI-RMF 1.0"
      alignment: "partial"             # full | partial | untested
      notes: "Read-only scope limits most high-risk practice statements."
    - name: "EU AI Act"
      article_52_risk_tier: "limited"  # high | limited | minimal | prohibited
      notes: "Generic market analysis is not personalized advice."
  data_handling:
    personal_data: false
    pii_categories: []
    retention_days: 90
    deletion_api: "DELETE /api/user/briefings"

ui:
  category: "personal"                 # personal | business | enterprise | vertical
  vertical: null
  short_description: "Daily market briefing for up to 20 tickers, with signal-driven alerts."
  long_description_md: "docs/description.md"
  icon: "assets/icon.svg"
  screenshots:
    - "assets/screenshots/briefing.png"
    - "assets/screenshots/alerts.png"
  pricing:
    model: "subscription"              # one-time | subscription | usage
    tiers:
      - name: "Free"
        price_usd: 0
        limits: { watchlist_size: 3 }
      - name: "Personal"
        price_usd_per_month: 19
        limits: { watchlist_size: 20 }
      - name: "Plus"
        price_usd_per_month: 49
        limits: { watchlist_size: -1 }  # unlimited
```

---

## Validation

A manifest is valid iff:

1. It parses as YAML (or JSON).
2. It conforms to `0001-bot-package-manifest.schema.json`.
3. All referenced files (long_description_md, icon, screenshots, entry_point) exist in the package.
4. The declared `max_action_risk_level` is ≤ the risk level implied by the highest-risk tool in `capabilities.tools`.
5. `tier.starting_trust_score` ≤ the ceiling of `tier.max_earnable_tier` (per canonical.ts observation ceilings).
6. `certified_models` lists only providers + model IDs known to the runtime.
7. The `governance.attestation.signature`, if present, verifies against the declared signing key over the canonical JSON of the manifest **excluding** the signature field itself.

A runtime MUST refuse to load a bot whose manifest fails any of items 1-6. Signature verification (item 7) is REQUIRED for tier ≥ 5; RECOMMENDED below.

---

## Signing model

1. Author writes `bot.manifest.yaml` with all fields except `governance.attestation.signed_at` and `.signature`.
2. Author submits manifest to Vorion (or delegated signer).
3. Signer runs conformance + policy checks.
4. Signer canonicalizes JSON (RFC 8785 JCS) of the manifest with the signature field removed.
5. Signer signs the canonicalized bytes using ed25519.
6. Signer fills in `signed_at` (UTC ISO 8601) and `signature` (base64url).
7. Signed manifest is embedded in the bot package tarball and published.

A runtime that sees a signed manifest on a bot package:

1. Removes the signature field, canonicalizes the remainder.
2. Verifies the signature against the declared `signing_key_id` (resolved from Vorion's public key directory or a trust-root config).
3. Rejects the bot if signature invalid.

---

## Framework binding

`runtime.framework` is the only field that cross-references an external execution model. For each declared framework, the BASIS runtime provides a Governance Adapter that:

- Intercepts tool calls → routes through `policy.gating.pre_action`
- Emits every action to the proof chain
- Enforces `max_action_risk_level` by refusing tool calls whose declared risk exceeds it
- Applies rate limits
- Triggers circuit-breaker halts

Initial adapters planned: `langgraph`, `crewai`, `autogen`. Custom frameworks MAY implement the Governance Adapter interface themselves; they're then listed as `framework: "custom"` and must supply `runtime.governance_adapter_module`.

---

## Open questions for RFC review

1. **Should `identity.namespace` be DNS-like (`com.vorion.aurais.market-scout`) or slug-like (`vorion-llc/market-scout`)?** — DNS-style is more aligned with Java/npm; slug is cleaner in URLs. Current draft picks slug; revisit after first 5 bots authored.
2. **Should `capabilities.data_scopes` have a formal ACL grammar, or stay as free-form strings?** — Free-form is faster to ship; ACL grammar is safer. Recommend ACL grammar in v1.1 after we see 10+ real bots.
3. **Is `certified_models` a hard-constraint list or a preferred-list?** — Current draft makes it hard (runtime must refuse non-listed). Alternative: list = preferred, operator can override with explicit opt-in. Decision should go to Vorion policy council.
4. **Should `pricing` live in the manifest at all?** — Puts commercial terms next to technical spec. Argument to split: marketplaces may rewrite price; don't want it in the signed canonical. Counter: buyers want one-object truth. Recommend: keep in manifest for v1, exclude `ui.pricing` from signature scope if author requests.
5. **Versioning policy.** — When should a change require a manifest version bump vs. a metadata patch? Propose: any change to `capabilities`, `policy`, `governance` = version bump. Changes to `ui`, `compliance.notes` = metadata patch, no re-sign needed.

---

## Non-goals (out of scope for v1)

- **Runtime-telemetry schema** — how a running bot reports health/trust-events. That's a separate RFC (`0002-trust-event-stream`).
- **Proof chain transport format** — also its own RFC.
- **Operator policy override syntax** — e.g., "operator X wants to tighten rate limits." Separate RFC.
- **Multi-bot composition (crews, graphs, swarms)** — a crew IS a bot (single manifest), but nested composition is v1.2+.
- **Bot-to-bot discovery / service-registry** — not in v1.

---

## Reference conformance case

The `aurais-spike-2026-04-15` Market Scout spike is the reference implementation for a Tier 3 / READ-level bot. Once the spike graduates to a real product, its manifest above is the first real-world manifest for v1.

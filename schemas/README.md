# BASIS Schemas

Standalone JSON Schema documents for parts of the BASIS spec that need
machine-validatable formats independent of the TypeScript / Zod surface
in `@vorionsys/basis-spec`.

| File | RFC | Purpose |
|---|---|---|
| [`attestation-v1.json`](attestation-v1.json) | [RFC-0003](../rfcs/0003-conformance-attestation.md) | JSON Schema for the RFC-0003 scorecard document. This repository does not publish a signed scorecard. |

## How to use

```bash
npm install ajv
```

```js
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
// The file lives in this repository at schemas/attestation-v1.json.
// @vorionsys/basis-spec does not ship it. The conformance package build
// copies schemas/ into that package's dist/schemas.
import schema from './schemas/attestation-v1.json' with { type: 'json' };

const ajv = new Ajv({ strict: false });
addFormats(ajv);
const validate = ajv.compile(schema);

// Validate a document you already have. This repo does not publish one,
// and it does not name a live attestation URL.
// const ok = validate(attestation);
```

After schema validation, fetch the signing key (by `signedBy`) and verify
the Ed25519 signature against the canonical-JSON re-serialization of all
fields except `signature`. See RFC-0003 §"Verification procedure".

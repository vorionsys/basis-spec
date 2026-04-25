# BASIS Schemas

Standalone JSON Schema documents for parts of the BASIS spec that need
machine-validatable formats independent of the TypeScript / Zod surface
in `@basis-spec/basis`.

| File | RFC | Purpose |
|---|---|---|
| [`attestation-v1.json`](attestation-v1.json) | [RFC-0003](../rfcs/0003-conformance-attestation.md) | Schema for the signed conformance scorecard each BASIS-compliant product publishes per release. |

## How to use

```bash
npm install ajv
```

```js
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import schema from '@basis-spec/basis-spec/schemas/attestation-v1.json' with { type: 'json' };

const ajv = new Ajv({ strict: false });
addFormats(ajv);
const validate = ajv.compile(schema);

const attestation = await fetch('https://cognigate.dev/attestations/cognigate-0.1.0.json').then(r => r.json());
if (!validate(attestation)) {
  console.error('attestation failed validation:', validate.errors);
} else {
  console.log('schema valid — now verify the signature');
}
```

After schema validation, fetch the signing key (by `signedBy`) and verify
the Ed25519 signature against the canonical-JSON re-serialization of all
fields except `signature`. See RFC-0003 §"Verification procedure".

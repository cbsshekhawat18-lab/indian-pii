# indian-pii — detect, validate & mask Indian PII for JavaScript

[![npm version](https://img.shields.io/npm/v/indian-pii.svg)](https://www.npmjs.com/package/indian-pii)
[![license: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#)
[![types: included](https://img.shields.io/badge/types-included-blue.svg)](#)
[![runtime: Node + Browser](https://img.shields.io/badge/runtime-Node%20%2B%20Browser-informational.svg)](#)

Detect, validate, and mask Indian personally identifiable information — **Aadhaar,
PAN, GSTIN, UPI, Voter ID, Passport, IFSC, and 11 more** — with **real checksums**,
**zero dependencies**, and first-class TypeScript types. Works in both **Node and
the browser**.

```bash
npm install indian-pii
```

## Why

JavaScript has plenty of generic PII libraries, but almost none understand Indian
identifiers — and the few that do only check shape (a regex), not authenticity.
A 12-digit number is *not* an Aadhaar unless its Verhoeff check digit is valid; a
15-character string is *not* a GSTIN unless its mod-36 digit and state code check
out. In the **DPDP Act** era, teams building redaction, logging hygiene, KYC, and
consent tooling need accurate, checksum-backed detection they can run client-side
or server-side without pulling in a dependency tree. `indian-pii` does exactly
that — and nothing else.

## Quick start

```js
import { detect, mask } from "indian-pii";

detect("My PAN is ABCPK1234Z");
// [{ type: 'pan', value: 'ABCPK1234Z', index: 9, valid: true, confidence: 0.8 }]

mask("My PAN is ABCPK1234Z"); // "My PAN is AXXXXXXXXZ"
```

## API reference

### `detect(text, options?) → DetectionResult[]`

Scans `text` and returns non-overlapping hits. Where spans overlap, the
highest-confidence hit wins (checksum-validated beats structure-only).

| Param | Type | Description |
|-------|------|-------------|
| `text` | `string` | Text to scan. Non-string input returns `[]`. |
| `options.types` | `string[]` | Restrict to these detector ids. |
| `options.requireValid` | `boolean` | Only return hits that pass validation. |
| `options.contextWindow` | `number` | Chars each side searched for a keyword (default `40`). |

Returns an array of:

```ts
interface DetectionResult {
  type: string;       // detector id, e.g. "pan"
  value: string;      // matched substring
  index: number;      // offset in text
  valid: boolean;     // passed real validation (checksum/structure)
  confidence: number; // 0–1; checksum-validated hits score highest
}
```

```js
detect("GSTIN 27AAPFU0939F1ZV, call 9876543210");
// [
//   { type: 'gstin', value: '27AAPFU0939F1ZV', index: 6,  valid: true, confidence: 0.99 },
//   { type: 'mobile_in', value: '9876543210',   index: 28, valid: true, confidence: 0.9 }
// ]
```

### `validate(type, value) → boolean`

Strictly validates a single value (checksum or structure). Returns `false` for
unknown types and non-string input — never throws.

```js
validate("gstin", "27AAPFU0939F1ZV"); // true
validate("card",  "4111111111111111"); // true  (Luhn + Visa IIN + length)
validate("upi_vpa", "user@gmail.com");  // false (that is an email, not a VPA)
```

### `maskValue(type, value) → string`

Masks one value using that type's rule. Unknown types return the input
unchanged; non-string input returns `""`.

```js
maskValue("aadhaar", "2345 6789 0124"); // "XXXX XXXX 0124"
maskValue("card", "4111111111111111");  // "XXXXXXXXXXXX1111"
maskValue("unknown", "keep me");        // "keep me"
```

### `mask(text, options?) → string`

Returns a copy of `text` with every detected value replaced by its masked form.
Accepts the same options as `detect`, plus `maskChar` (default `"X"`).

```js
mask("Card 4111 1111 1111 1111");          // "Card XXXX XXXX XXXX 1111"
mask("PAN ABCPK1234Z", { maskChar: "•" }); // "PAN A••••••••Z"
```

### `detectors → Detector[]`

The full registry of 18 detectors. Each exposes
`{ id, label, category, severity, regex, validate, mask, contextHints }`.

```js
import { detectors } from "indian-pii";
detectors.map((d) => d.id);
// ['aadhaar','card','gstin','abha','cin','pan','tan','voter_id','passport',
//  'driving_licence','ifsc','demat','upi_vpa','uan','mobile_in','micr','din','pincode']
```

## Detector table

All sample values below are **fabricated** for documentation. `Validation` is the
strongest check each detector applies; `Gated` marks loose patterns that only fire
in free text with a nearby keyword (or a self-identifying token).

| id | Format | Validation | Gated | Example |
|----|--------|-----------|:----:|---------|
| `aadhaar` | 12 digits, 1st 2–9 | checksum (Verhoeff) | | `2345 6789 0124` |
| `pan` | `AAAAA9999A` | structure (4th = holder type) | | `ABCPK1234Z` |
| `voter_id` | `AAA9999999` | structure (EPIC) | | `ABC1234567` |
| `passport` | `A9999999` | structure (`[A-PR-WY]`) | | `P1234567` |
| `driving_licence` | `SS RR YYYY NNNNNNN` | structure (state + length) | | `MH1220110012345` |
| `upi_vpa` | `name@psp` | structure (known psp / no-dot) | ✓\* | `ramesh@oksbi` |
| `ifsc` | `BANK0BRANCH` | structure (5th char `0`) | | `SBIN0001234` |
| `micr` | 9 digits | structure | ✓ | `MICR 400002007` |
| `demat` | `IN`+14 / 16 digits | structure | ✓\* | `IN30001012345678` |
| `card` | 13–19 digits | checksum (Luhn + IIN + length) | | `4111 1111 1111 1111` |
| `gstin` | 15 chars | checksum (mod-36 + state) | | `27AAPFU0939F1ZV` |
| `tan` | `AAAA99999A` | structure | | `MUMA12345B` |
| `cin` | 21 chars | structure (6 segments) | | `U72200KA2011PTC123456` |
| `din` | 8 digits | structure | ✓ | `DIN 01234567` |
| `uan` | 12 digits | structure | ✓ | `UAN 100123456789` |
| `abha` | 14 digits | checksum (Verhoeff) | | `12-3456-7890-1230` |
| `mobile_in` | `[6-9]` + 9 digits | structure | ✓\* | `+91 98765 43210` |
| `pincode` | 6 digits, non-zero start | structure | ✓ | `560001` |

\* Context-gated, but a **self-identifying** token bypasses the gate: a known UPI
handle (`name@oksbi`), an `IN`-prefixed demat id, or a `+91`-prefixed mobile is
flagged even without a nearby keyword.

## Per-detector examples

Every example uses a fake value. For context-gated detectors the `detect()` input
includes the keyword that the gate requires.

### 1. aadhaar — checksum (Verhoeff)
```js
detect("Aadhaar 2345 6789 0124");
// [{ type: 'aadhaar', value: '2345 6789 0124', index: 8, valid: true, confidence: 0.99 }]
validate("aadhaar", "2345 6789 0124"); // true
validate("aadhaar", "2345 6789 0123"); // false (bad checksum)
maskValue("aadhaar", "2345 6789 0124"); // "XXXX XXXX 0124"
```

### 2. pan — structure
```js
detect("PAN ABCPK1234Z");
// [{ type: 'pan', value: 'ABCPK1234Z', index: 4, valid: true, confidence: 0.8 }]
validate("pan", "ABCPK1234Z"); // true
validate("pan", "ABCDK1234Z"); // false (4th char not a holder type)
maskValue("pan", "ABCPK1234Z"); // "AXXXXXXXXZ"
```

### 3. voter_id — structure
```js
detect("EPIC ABC1234567");
// [{ type: 'voter_id', value: 'ABC1234567', index: 5, valid: true, confidence: 0.8 }]
validate("voter_id", "ABC1234567"); // true
validate("voter_id", "AB1234567");  // false
maskValue("voter_id", "ABC1234567"); // "ABCXXXXXXX"
```

### 4. passport — structure
```js
detect("Passport P1234567");
// [{ type: 'passport', value: 'P1234567', index: 9, valid: true, confidence: 0.8 }]
validate("passport", "P1234567"); // true
validate("passport", "Q1234567"); // false (Q/X/Z not allowed as 1st char)
maskValue("passport", "P1234567"); // "PXXXXX67"
```

### 5. driving_licence — structure
```js
detect("DL MH1220110012345");
// [{ type: 'driving_licence', value: 'MH1220110012345', index: 3, valid: true, confidence: 0.8 }]
validate("driving_licence", "MH1220110012345"); // true
validate("driving_licence", "ZZ1220110012345"); // false (bad state code)
maskValue("driving_licence", "MH1220110012345"); // "MH12XXXXXXXXX45"
```

### 6. upi_vpa — structure (self-identifies on known handle)
```js
detect("Pay ramesh@oksbi");
// [{ type: 'upi_vpa', value: 'ramesh@oksbi', index: 4, valid: true, confidence: 0.9 }]
validate("upi_vpa", "ramesh@oksbi");     // true
validate("upi_vpa", "ramesh@gmail.com"); // false (email, not a VPA)
maskValue("upi_vpa", "ramesh@oksbi"); // "rXXXXX@oksbi"
```

### 7. ifsc — structure
```js
detect("IFSC SBIN0001234");
// [{ type: 'ifsc', value: 'SBIN0001234', index: 5, valid: true, confidence: 0.8 }]
validate("ifsc", "SBIN0001234"); // true
validate("ifsc", "SBIN1001234"); // false (5th char must be 0)
maskValue("ifsc", "SBIN0001234"); // "SBINXXXXXXX"
```

### 8. micr — structure (context-gated)
```js
detect("MICR 400002007");
// [{ type: 'micr', value: '400002007', index: 5, valid: true, confidence: 0.9 }]
detect("value 400002007 here"); // [] — no "MICR" keyword nearby
validate("micr", "400002007"); // true
maskValue("micr", "400002007"); // "XXXXXX007"
```

### 9. demat — structure (CDSL 16-digit form is gated; NSDL `IN` form self-identifies)
```js
detect("Demat IN30001012345678");
// [{ type: 'demat', value: 'IN30001012345678', index: 6, valid: true, confidence: 0.9 }]
validate("demat", "IN30001012345678"); // true (NSDL)
validate("demat", "1234567890123456");  // true (CDSL)
maskValue("demat", "IN30001012345678"); // "INXXXXXXXXXX5678"
```

### 10. card — checksum (Luhn + IIN + length)
```js
detect("Card 4111 1111 1111 1111");
// [{ type: 'card', value: '4111 1111 1111 1111', index: 5, valid: true, confidence: 0.99 }]
validate("card", "4111111111111111"); // true
validate("card", "1234567812345670"); // false (Luhn ok but no real IIN)
maskValue("card", "4111 1111 1111 1111"); // "XXXX XXXX XXXX 1111"
```

### 11. gstin — checksum (mod-36 + state code)
```js
detect("GSTIN 27AAPFU0939F1ZV");
// [{ type: 'gstin', value: '27AAPFU0939F1ZV', index: 6, valid: true, confidence: 0.99 }]
validate("gstin", "27AAPFU0939F1ZV"); // true
validate("gstin", "27AAPFU0939F1ZX"); // false (bad check digit)
maskValue("gstin", "27AAPFU0939F1ZV"); // "27XXXXXXXXXXXXV"
```

### 12. tan — structure
```js
detect("TAN MUMA12345B");
// [{ type: 'tan', value: 'MUMA12345B', index: 4, valid: true, confidence: 0.8 }]
validate("tan", "MUMA12345B"); // true
validate("tan", "MUM12345B");  // false
maskValue("tan", "MUMA12345B"); // "MUMAXXXXXB"
```

### 13. cin — structure (all 6 segments)
```js
detect("CIN U72200KA2011PTC123456");
// [{ type: 'cin', value: 'U72200KA2011PTC123456', index: 4, valid: true, confidence: 0.8 }]
validate("cin", "U72200KA2011PTC123456"); // true
validate("cin", "U72200ZZ2011PTC123456"); // false (bad state code)
maskValue("cin", "U72200KA2011PTC123456"); // "UXXXXXXXXXXXXXX123456"
```

### 14. din — structure (context-gated)
```js
detect("DIN 01234567");
// [{ type: 'din', value: '01234567', index: 4, valid: true, confidence: 0.9 }]
detect("ref 01234567 here"); // [] — no "DIN"/"director" keyword nearby
validate("din", "01234567"); // true
maskValue("din", "01234567"); // "XXXXXX67"
```

### 15. uan — structure (context-gated)
```js
detect("UAN 100123456789");
// [{ type: 'uan', value: '100123456789', index: 4, valid: true, confidence: 0.9 }]
detect("number 100123456789 here"); // [] — no "UAN"/"PF" keyword nearby
validate("uan", "100123456789"); // true
maskValue("uan", "100123456789"); // "XXXXXXXX6789"
```

### 16. abha — checksum (Verhoeff)
```js
detect("ABHA 12-3456-7890-1230");
// [{ type: 'abha', value: '12-3456-7890-1230', index: 5, valid: true, confidence: 0.99 }]
validate("abha", "12-3456-7890-1230"); // true
validate("abha", "12-3456-7890-1234"); // false (bad checksum)
maskValue("abha", "12-3456-7890-1230"); // "XX-XXXX-XXXX-1230"
```

### 17. mobile_in — structure (context-gated; `+91` self-identifies)
```js
detect("Call +91 98765 43210");
// [{ type: 'mobile_in', value: '+91 98765 43210', index: 5, valid: true, confidence: 0.9 }]
detect("id 9876543210 here"); // [] — no +91 and no phone keyword nearby
validate("mobile_in", "9876543210"); // true
maskValue("mobile_in", "+91 98765 43210"); // "+XX XXXXX X3210"
```

### 18. pincode — structure (context-gated)
```js
detect("PIN code 560001");
// [{ type: 'pincode', value: '560001', index: 9, valid: true, confidence: 0.9 }]
detect("order 560001 shipped"); // [] — no PIN/postal/address keyword nearby
validate("pincode", "560001"); // true
maskValue("pincode", "560001"); // "5XXXXX"
```

## Usage in Node and the browser

The package ships ESM, CommonJS, and TypeScript declarations.

**Node (ESM) / bundlers / browsers:**
```js
import { detect, validate, mask } from "indian-pii";
```

**Node (CommonJS):**
```js
const { detect, validate, mask } = require("indian-pii");
```

**Browser via a CDN (no build step):**
```html
<script type="module">
  import { mask } from "https://esm.sh/indian-pii";
  console.log(mask("PAN ABCPK1234Z")); // "PAN AXXXXXXXXZ"
</script>
```

## Try it yourself

Paste this into a file and run it with Node (`node try.mjs`) after installing:

```js
import { detect, validate, mask } from "indian-pii";

const input = process.argv[2] ?? "PAN ABCPK1234Z, GSTIN 27AAPFU0939F1ZV";
console.log("detected:", detect(input));
console.log("masked:  ", mask(input));
console.log("valid PAN?", validate("pan", "ABCPK1234Z"));
```

```bash
node try.mjs "Aadhaar 2345 6789 0124 and card 4111 1111 1111 1111"
```

The repo also ships runnable demos in [`examples/`](./examples) — after
`npm run build`, run:

```bash
node examples/detect-demo.js
node examples/validate-demo.js
node examples/mask-demo.js
```

## Testing

The suite (run with [Vitest](https://vitest.dev)) covers, for every one of the 18
detectors, at least three valid samples and three invalid ones (wrong checksum,
wrong structure, value embedded in a longer string, and empty/`null` input). It
also covers the engine itself: context gating (loose patterns are not bare-matched
in free text), UPI-vs-email separation, boundary safety, overlap de-duplication
(checksum-validated wins), the `requireValid` and `types` options, masking output,
and input safety.

```bash
npm test
```

Reading the output: Vitest prints one line per test file with a ✓ (all passing)
or ✗ (a failure), then a summary like `Tests  55 passed (55)`. A green summary
with zero failures means every detector and engine behaviour is verified.

## Honest limitations

- **Format-valid ≠ real.** Detection and validation verify *format and checksums
  only*. A value that validates is well-formed — it is **not** proof that the
  identifier was issued, is active, or belongs to anyone. Use this for redaction,
  privacy hygiene, and input sanity checks; never as proof of identity or as a
  substitute for an authoritative verification service.
- **Context-gated detectors trade recall for precision.** Loose patterns (MICR,
  DIN, UAN, mobile, pincode, and the bare CDSL demat form) only fire in free text
  when a related keyword is nearby. To check such a value directly, call
  `validate(type, value)` — it never requires context.
- **Structure-only detectors can over-match in free text.** Identifiers without a
  checksum (e.g. passport, voter ID) are validated by shape; a coincidental
  matching token may be flagged. Use `requireValid` and the `valid` flag to
  decide how strict your pipeline should be.

## Robustness

- **Zero runtime dependencies** — nothing to audit downstream.
- **Browser + Node**, ESM + CJS, tree-shakeable (`"sideEffects": false`).
- **Input-safe** — `null`/`undefined`/non-string never throw.
- **Boundary-safe** — values glued inside a longer alphanumeric run are ignored.
- **ReDoS-safe** — all patterns are linear with bounded quantifiers.
- **Normalization** — spaces/hyphens stripped and case folded where formats allow.

## Roadmap

- More identifiers (ration card, ESIC, NPS/PRAN, FASTag, bank-account heuristics).
- Locale-aware name & address heuristics.
- Optional OCR / document-parsing modules (Aadhaar/PAN card images, PDFs).
- Configurable redaction policies and streaming/large-text scanning.

## Contributing

Issues and pull requests are welcome. Please add or update tests for any detector
change (valid **and** invalid cases) and keep the library dependency-free. Run
`npm test` and `npm run typecheck` before opening a PR.

## License

[MIT](./LICENSE) © 2026 Chandrabhan Shekhawat / Gigai Kripa Services

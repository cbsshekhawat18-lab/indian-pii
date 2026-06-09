/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

// Run from the repo root after `npm run build`:  node examples/validate-demo.js
import { validate } from "../dist/index.js";

// All sample values below are fabricated for demonstration only.
const checks = [
  ["aadhaar", "2345 6789 0124"], // Verhoeff valid
  ["aadhaar", "2345 6789 0123"], // bad checksum
  ["gstin", "27AAPFU0939F1ZV"], // mod-36 valid
  ["gstin", "27AAPFU0939F1ZX"], // bad check digit
  ["card", "4111111111111111"], // Luhn + Visa IIN
  ["card", "1234567812345670"], // Luhn ok but no real IIN
  ["upi_vpa", "ramesh@oksbi"], // known handle
  ["upi_vpa", "ramesh@gmail.com"], // email, not a VPA
];

for (const [type, value] of checks) {
  console.log(`${type.padEnd(10)} ${String(value).padEnd(20)} => ${validate(type, value)}`);
}

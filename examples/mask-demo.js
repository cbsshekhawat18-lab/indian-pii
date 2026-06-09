/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

// Run from the repo root after `npm run build`:  node examples/mask-demo.js
import { mask, maskValue } from "../dist/index.js";

const log = "User ABCPK1234Z paid via 4111 1111 1111 1111; UPI ramesh@oksbi.";
console.log("Before:", log);
console.log("After: ", mask(log));
console.log("After (custom char):", mask(log, { maskChar: "•" }));

console.log("\nSingle-value masking:");
console.log("  aadhaar:", maskValue("aadhaar", "2345 6789 0124"));
console.log("  pan:    ", maskValue("pan", "ABCPK1234Z"));
console.log("  card:   ", maskValue("card", "4111111111111111"));

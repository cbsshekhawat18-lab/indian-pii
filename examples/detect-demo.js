/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

// Run from the repo root after `npm run build`:  node examples/detect-demo.js
// (If you installed the package, change the import to:  from "indian-pii")
import { detect } from "../dist/index.js";

const text = [
  "Hi, my PAN is ABCPK1234Z and GSTIN 27AAPFU0939F1ZV.",
  "Call me at 9876543210 or pay to ramesh@oksbi.",
  "Office PIN code: 560001. Card on file 4111 1111 1111 1111.",
].join(" ");

console.log("Input:\n" + text + "\n");
console.log("Detected PII:");
for (const hit of detect(text)) {
  console.log(
    `  ${hit.type.padEnd(12)} "${hit.value}"  valid=${hit.valid}  confidence=${hit.confidence}`
  );
}

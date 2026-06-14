/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

// Runtime smoke test of the BUILT package. Run after `npm run build`:
//   npm run smoke
// It imports the compiled ESM entrypoints and exercises the core + image layers
// end to end, printing the results. All values below are fabricated.
import { detect, mask } from "../dist/index.js";
import { fromTesseract, detectInImage, redactBoxes } from "../dist/image.js";

console.log("== core: detect() + mask() ==");
const text = "PAN ABCPK1234Z, GSTIN 27AAPFU0939F1ZV, card 4111 1111 1111 1111";
console.log("detect:", JSON.stringify(detect(text)));
console.log("mask:  ", mask(text));

console.log("\n== image: fromTesseract -> detectInImage -> redactBoxes ==");
const tess = {
  width: 400,
  height: 60,
  words: [
    { text: "Aadhaar", bbox: { x0: 0, y0: 0, x1: 70, y1: 20 }, confidence: 99 },
    { text: "2345", bbox: { x0: 80, y0: 0, x1: 120, y1: 20 }, confidence: 90 },
    { text: "6789", bbox: { x0: 130, y0: 0, x1: 170, y1: 20 }, confidence: 80 },
    { text: "0124", bbox: { x0: 180, y0: 0, x1: 220, y1: 20 }, confidence: 70 },
  ],
};
const ocr = fromTesseract(tess);
const results = detectInImage(ocr);
console.log("detectInImage:", JSON.stringify(results));

const rects = [];
const ctx = { fillStyle: null, fillRect: (x, y, w, h) => rects.push([x, y, w, h]) };
const drawn = redactBoxes(ctx, results);
console.log(`redactBoxes drew ${drawn} box(es) [fillStyle=${ctx.fillStyle}]:`, JSON.stringify(rects));

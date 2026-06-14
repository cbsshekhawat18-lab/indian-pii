/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

// Run from the repo root after `npm run build`:  node examples/image-demo.js
// (If you installed the package, change the import to:  from "indian-pii/image")
//
// This demo uses a HARD-CODED fake OCR result, so it runs with no network,
// no Tesseract, and no model. In real use you would run OCR yourself and pass
// its output through fromTesseract().
import { fromTesseract, detectInImage, redactBoxes } from "../dist/image.js";

// Pretend this came back from Tesseract.js `worker.recognize(image)`.
// All values are fabricated. The Aadhaar (2345 6789 0124) is split across words.
const tesseractData = {
  width: 400,
  height: 60,
  words: [
    { text: "Aadhaar", bbox: { x0: 0, y0: 0, x1: 70, y1: 20 }, confidence: 99 },
    { text: "2345", bbox: { x0: 80, y0: 0, x1: 120, y1: 20 }, confidence: 90 },
    { text: "6789", bbox: { x0: 130, y0: 0, x1: 170, y1: 20 }, confidence: 80 },
    { text: "0124", bbox: { x0: 180, y0: 0, x1: 220, y1: 20 }, confidence: 70 },
  ],
};

const ocr = fromTesseract(tesseractData);
console.log("Normalised OCR words:", ocr.words.length);

const results = detectInImage(ocr);
console.log("\nDetected PII in image:");
for (const r of results) {
  console.log(
    `  ${r.type}  "${r.value}"  valid=${r.valid}  ocrConfidence=${r.ocrConfidence?.toFixed(2)}`
  );
  console.log(`    union bbox:`, r.bbox);
  console.log(`    word boxes:`, r.boxes.length);
}

// Minimal stand-in for a canvas 2D context (browser canvas or node-canvas work too).
const drawnRects = [];
const ctx = {
  fillStyle: null,
  fillRect: (x, y, w, h) => drawnRects.push({ x, y, w, h }),
};

const drawn = redactBoxes(ctx, results); // default: union box, black, 2px padding
console.log(`\nredactBoxes drew ${drawn} box(es) with fillStyle="${ctx.fillStyle}":`);
console.log(" ", drawnRects);

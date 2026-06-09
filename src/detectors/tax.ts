/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

import type { Detector } from "../types.js";
import { gstinCheckChar } from "../utils/checksums.js";
import { asString, stripSeparators, maskChars } from "../utils/text.js";
import { CIN_STATE_CODES, CIN_OWNERSHIP } from "../utils/constants.js";

/**
 * 11. GSTIN — 15 chars: state(01–37) + 10-char PAN + entity + 'Z' + check char.
 * Validates structure, state-code range, and the GSTN mod-36 check digit.
 */
export const gstin: Detector = {
  id: "gstin",
  label: "GSTIN (GST number)",
  category: "tax",
  severity: "high",
  regex:
    /(?<![0-9A-Za-z])[0-9]{2}[A-Za-z]{5}[0-9]{4}[A-Za-z][1-9A-Za-z]Z[0-9A-Za-z](?![0-9A-Za-z])/g,
  checksum: true,
  contextGated: false,
  contextHints: ["gst", "gstin"],
  validate(value) {
    const g = asString(value).toUpperCase();
    if (!/^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$/.test(g)) return false;
    const state = +g.slice(0, 2);
    if (state < 1 || state > 37) return false;
    return gstinCheckChar(g.slice(0, 14)) === g[14];
  },
  mask(value) {
    return maskChars(asString(value), { first: 2, last: 1 });
  },
};

/** 12. TAN — ^[A-Z]{4}[0-9]{5}[A-Z]$. Structure only. */
export const tan: Detector = {
  id: "tan",
  label: "TAN (tax deduction account number)",
  category: "tax",
  severity: "medium",
  regex: /(?<![0-9A-Za-z])[A-Za-z]{4}[0-9]{5}[A-Za-z](?![0-9A-Za-z])/g,
  checksum: false,
  contextGated: false,
  contextHints: ["tan", "tds", "tax deduction"],
  validate(value) {
    return /^[A-Z]{4}[0-9]{5}[A-Z]$/.test(asString(value).toUpperCase());
  },
  mask(value) {
    return maskChars(asString(value), { first: 4, last: 1 });
  },
};

/**
 * 13. CIN — 21 chars: listing status + industry + state + year + ownership +
 * registration number. Validates each segment.
 */
export const cin: Detector = {
  id: "cin",
  label: "CIN (company identification number)",
  category: "tax",
  severity: "medium",
  regex:
    /(?<![0-9A-Za-z])[LUlu][0-9]{5}[A-Za-z]{2}[0-9]{4}[A-Za-z]{3}[0-9]{6}(?![0-9A-Za-z])/g,
  checksum: false,
  contextGated: false,
  contextHints: ["cin", "company", "mca", "incorporation"],
  validate(value) {
    const v = asString(value).toUpperCase();
    const m =
      /^([LU])([0-9]{5})([A-Z]{2})([0-9]{4})([A-Z]{3})([0-9]{6})$/.exec(v);
    if (!m) return false;
    if (!CIN_STATE_CODES.has(m[3]!)) return false;
    const year = +m[4]!;
    if (year < 1850 || year > 2100) return false;
    if (!CIN_OWNERSHIP.has(m[5]!)) return false;
    return true;
  },
  mask(value) {
    return maskChars(asString(value), { first: 1, last: 6 });
  },
};

/** 14. DIN — 8 digits, context-gated to the keyword "DIN". */
export const din: Detector = {
  id: "din",
  label: "DIN (director identification number)",
  category: "tax",
  severity: "medium",
  regex: /(?<![0-9A-Za-z])[0-9]{8}(?![0-9A-Za-z])/g,
  checksum: false,
  contextGated: true,
  contextHints: ["din", "director"],
  validate(value) {
    return /^[0-9]{8}$/.test(stripSeparators(asString(value)));
  },
  mask(value) {
    return maskChars(asString(value), { last: 2 });
  },
};

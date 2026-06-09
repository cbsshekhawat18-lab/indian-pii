/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

import type { Detector } from "../types.js";
import { luhnValid } from "../utils/checksums.js";
import { asString, stripSeparators, maskChars } from "../utils/text.js";
import { UPI_HANDLES } from "../utils/constants.js";

/** Card validation = Luhn + a real network IIN prefix + that network's length. */
function cardValid(d: string): boolean {
  if (!/^[0-9]+$/.test(d)) return false;
  const len = d.length;
  if (len < 13 || len > 19) return false;
  if (!luhnValid(d)) return false;
  const i2 = +d.slice(0, 2);
  const i3 = +d.slice(0, 3);
  const i4 = +d.slice(0, 4);
  if (d[0] === "4") return len === 13 || len === 16 || len === 19; // Visa
  if ((i2 >= 51 && i2 <= 55) || (i4 >= 2221 && i4 <= 2720)) return len === 16; // Mastercard
  if (i2 === 34 || i2 === 37) return len === 15; // Amex
  if (i4 === 6011 || i2 === 65 || (i3 >= 644 && i3 <= 649) || i3 === 622)
    return len === 16 || len === 19; // Discover
  if (i2 === 36 || i2 === 38 || (i3 >= 300 && i3 <= 305)) return len === 14; // Diners
  if (i4 >= 3528 && i4 <= 3589) return len === 16 || len === 19; // JCB
  if (i2 === 60 || i2 === 81 || i2 === 82 || i3 === 508 || i3 === 353 || i3 === 356)
    return len === 16; // RuPay
  return false;
}

/**
 * 6. UPI VPA — `local@psp`; the psp segment has NO dot (that is what separates
 * a VPA from an email). Matches when the psp is a known handle or UPI/VPA
 * wording is nearby; never matches `name@gmail.com`.
 */
export const upiVpa: Detector = {
  id: "upi_vpa",
  label: "UPI ID (VPA)",
  category: "financial",
  severity: "high",
  // local part allows letters/digits/.-_ ; psp is letters/digits with NO dot.
  // The trailing guard rejects only a dot that STARTS a domain (e.g. ".com"),
  // so emails are excluded but a VPA ending a sentence ("...@oksbi.") still
  // matches.
  regex: /(?<![\w.])[a-zA-Z0-9][a-zA-Z0-9.\-_]{1,}@[a-zA-Z][a-zA-Z0-9]{1,}(?!\w|\.\w)/g,
  checksum: false,
  contextGated: true,
  contextHints: ["upi", "vpa", "collect", "payee", "payment"],
  selfIdentifies(value) {
    const at = asString(value).indexOf("@");
    if (at < 0) return false;
    return UPI_HANDLES.has(asString(value).slice(at + 1).toLowerCase());
  },
  validate(value) {
    const v = asString(value);
    const at = v.indexOf("@");
    if (at < 1) return false;
    const psp = v.slice(at + 1).toLowerCase();
    // psp must be present, dot-free and alphanumeric.
    if (!/^[a-z0-9]+$/.test(psp)) return false;
    // Known handle = a real VPA. Unknown handles are accepted structurally but
    // the engine still requires nearby context for them to surface.
    return UPI_HANDLES.has(psp) || /^[a-z0-9.\-_]+$/.test(v.slice(0, at));
  },
  mask(value) {
    const v = asString(value);
    const at = v.indexOf("@");
    if (at < 0) return maskChars(v);
    return maskChars(v.slice(0, at), { first: 1 }) + v.slice(at);
  },
};

/** 7. IFSC — ^[A-Z]{4}0[A-Z0-9]{6}$ (5th char always 0). Structure only. */
export const ifsc: Detector = {
  id: "ifsc",
  label: "IFSC (bank branch code)",
  category: "financial",
  severity: "medium",
  regex: /(?<![0-9A-Za-z])[A-Za-z]{4}0[A-Za-z0-9]{6}(?![0-9A-Za-z])/g,
  checksum: false,
  contextGated: false,
  contextHints: ["ifsc", "branch", "neft", "rtgs", "imps"],
  validate(value) {
    return /^[A-Z]{4}0[A-Z0-9]{6}$/.test(asString(value).toUpperCase());
  },
  mask(value) {
    return maskChars(asString(value), { first: 4 });
  },
};

/** 8. MICR — 9 digits, context-gated to the keyword "MICR". */
export const micr: Detector = {
  id: "micr",
  label: "MICR code",
  category: "financial",
  severity: "low",
  regex: /(?<![0-9A-Za-z])[0-9]{9}(?![0-9A-Za-z])/g,
  checksum: false,
  contextGated: true,
  contextHints: ["micr"],
  validate(value) {
    return /^[0-9]{9}$/.test(stripSeparators(asString(value)));
  },
  mask(value) {
    return maskChars(asString(value), { last: 3 });
  },
};

/** 9. Demat — NSDL `IN`+14 digits, or CDSL 16 digits. */
export const demat: Detector = {
  id: "demat",
  label: "Demat account number",
  category: "financial",
  severity: "high",
  regex: /(?<![0-9A-Za-z])(?:IN[0-9]{14}|[0-9]{16})(?![0-9A-Za-z])/gi,
  checksum: false,
  // The bare 16-digit CDSL form is context-gated; the IN-prefixed NSDL form
  // self-identifies and may surface without context.
  contextGated: true,
  contextHints: ["demat", "dp id", "bo id", "nsdl", "cdsl", "depository"],
  selfIdentifies(value) {
    return /^IN[0-9]{14}$/.test(asString(value).toUpperCase());
  },
  validate(value) {
    const v = asString(value).toUpperCase();
    return /^IN[0-9]{14}$/.test(v) || /^[0-9]{16}$/.test(v);
  },
  mask(value) {
    return maskChars(asString(value), { first: 2, last: 4 });
  },
};

/** 10. Card — 13–19 digits, Luhn + valid IIN prefix + network length. */
export const card: Detector = {
  id: "card",
  label: "Payment card number",
  category: "financial",
  severity: "critical",
  // 13–19 digit run, optionally space/dash grouped; boundary-guarded so a
  // card-length slice inside a longer digit string is not matched.
  regex: /(?<![0-9A-Za-z])(?:[0-9][\s-]?){13,19}(?<![\s-])(?![0-9A-Za-z])/g,
  checksum: true,
  contextGated: false,
  contextHints: ["card", "credit", "debit", "visa", "mastercard", "rupay", "cvv"],
  validate(value) {
    return cardValid(stripSeparators(asString(value)));
  },
  mask(value) {
    return maskChars(asString(value), { last: 4 });
  },
};

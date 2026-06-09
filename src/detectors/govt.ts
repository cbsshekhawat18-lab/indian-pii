/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

import type { Detector } from "../types.js";
import { verhoeffValid } from "../utils/checksums.js";
import { asString, stripSeparators, maskChars } from "../utils/text.js";

/** 15. UAN — 12 digits, context-gated to "UAN" / "PF". */
export const uan: Detector = {
  id: "uan",
  label: "UAN (universal account number)",
  category: "govt",
  severity: "high",
  regex: /(?<![0-9A-Za-z])[0-9]{12}(?![0-9A-Za-z])/g,
  checksum: false,
  contextGated: true,
  contextHints: ["uan", "pf", "provident", "epf", "epfo"],
  validate(value) {
    return /^[0-9]{12}$/.test(stripSeparators(asString(value)));
  },
  mask(value) {
    return maskChars(asString(value), { last: 4 });
  },
};

/** 16. ABHA — 14 digits (XX-XXXX-XXXX-XXXX), Verhoeff check digit. */
export const abha: Detector = {
  id: "abha",
  label: "ABHA number (health ID)",
  category: "health",
  severity: "high",
  regex:
    /(?<![0-9A-Za-z])[0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}(?![0-9A-Za-z])/g,
  checksum: true,
  contextGated: false,
  contextHints: ["abha", "health id", "ayushman", "abdm", "ndhm"],
  validate(value) {
    const d = stripSeparators(asString(value));
    if (d.length !== 14) return false;
    return verhoeffValid(d);
  },
  mask(value) {
    return maskChars(asString(value), { last: 4 });
  },
};

/**
 * 17. Mobile (India) — optional +91, then [6-9] and 9 more digits. Context-gated
 * to avoid matching arbitrary 10-digit numbers; a `+91` prefix self-identifies.
 */
export const mobileIn: Detector = {
  id: "mobile_in",
  label: "Indian mobile number",
  category: "contact",
  severity: "medium",
  // Optional +91 country code, then a [6-9]-leading 10-digit number that may be
  // split by single spaces/hyphens (e.g. "98765 43210").
  regex: /(?<![0-9A-Za-z])(?:\+?91[-\s]?)?[6-9][0-9](?:[-\s]?[0-9]){8}(?![0-9A-Za-z])/g,
  checksum: false,
  contextGated: true,
  contextHints: ["mobile", "phone", "call", "whatsapp", "contact", "tel", "+91"],
  selfIdentifies(value) {
    return /^\+?91[6-9][0-9]{9}$/.test(stripSeparators(asString(value)));
  },
  validate(value) {
    let d = stripSeparators(asString(value)).replace(/^\+/, "");
    if (d.startsWith("91") && d.length === 12) d = d.slice(2);
    return /^[6-9][0-9]{9}$/.test(d);
  },
  mask(value) {
    return maskChars(asString(value), { last: 4 });
  },
};

/** 18. Pincode — ^[1-9][0-9]{5}$, context-gated to PIN / postal / address. */
export const pincode: Detector = {
  id: "pincode",
  label: "Postal PIN code",
  category: "contact",
  severity: "low",
  regex: /(?<![0-9A-Za-z])[1-9][0-9]{5}(?![0-9A-Za-z])/g,
  checksum: false,
  contextGated: true,
  contextHints: ["pin", "pincode", "pin code", "postal", "zip", "address", "post"],
  validate(value) {
    return /^[1-9][0-9]{5}$/.test(stripSeparators(asString(value)));
  },
  mask(value) {
    return maskChars(asString(value), { first: 1 });
  },
};

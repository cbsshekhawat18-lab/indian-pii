/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

import { describe, it, expect } from "vitest";
import { maskValue } from "../src/index.js";

// One masked output per detector, using fabricated sample values. Masking keeps
// format separators and reveals only the documented portion of each identifier.
const MASKS: Array<[type: string, value: string, masked: string]> = [
  ["aadhaar", "2345 6789 0124", "XXXX XXXX 0124"],
  ["pan", "ABCPK1234Z", "AXXXXXXXXZ"],
  ["voter_id", "ABC1234567", "ABCXXXXXXX"],
  ["passport", "P1234567", "PXXXXX67"],
  ["driving_licence", "MH1220110012345", "MH12XXXXXXXXX45"],
  ["upi_vpa", "ramesh@oksbi", "rXXXXX@oksbi"],
  ["ifsc", "SBIN0001234", "SBINXXXXXXX"],
  ["micr", "400002007", "XXXXXX007"],
  ["demat", "IN30001012345678", "INXXXXXXXXXX5678"],
  ["card", "4111 1111 1111 1111", "XXXX XXXX XXXX 1111"],
  ["gstin", "27AAPFU0939F1ZV", "27XXXXXXXXXXXXV"],
  ["tan", "MUMA12345B", "MUMAXXXXXB"],
  ["cin", "U72200KA2011PTC123456", "UXXXXXXXXXXXXXX123456"],
  ["din", "01234567", "XXXXXX67"],
  ["uan", "100123456789", "XXXXXXXX6789"],
  ["abha", "12-3456-7890-1230", "XX-XXXX-XXXX-1230"],
  ["mobile_in", "+91 98765 43210", "+XX XXXXX X3210"],
  ["pincode", "560001", "5XXXXX"],
];

describe("maskValue — every detector", () => {
  it.each(MASKS)("%s masks %s -> %s", (type, value, masked) => {
    expect(maskValue(type, value)).toBe(masked);
  });

  it("covers all 18 detectors", () => {
    expect(new Set(MASKS.map(([t]) => t)).size).toBe(18);
  });
});

/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

import { describe, it, expect } from "vitest";
import { detect, mask, maskValue, detectors } from "../src/index.js";

describe("detect — context gating", () => {
  it("does NOT bare-match loose patterns in free text", () => {
    expect(detect("the code 560001 is here")).toHaveLength(0); // pincode needs ctx
    expect(detect("number 9876543210 logged")).toHaveLength(0); // mobile needs ctx
    expect(detect("ref 100123456789 ok")).toHaveLength(0); // uan needs ctx
    expect(detect("value 400002007 seen")).toHaveLength(0); // micr needs ctx
    expect(detect("id 01234567 done")).toHaveLength(0); // din needs ctx
  });

  it("matches loose patterns WITH a nearby keyword", () => {
    expect(detect("PIN code: 560001").map((r) => r.type)).toContain("pincode");
    expect(detect("call me at 9876543210").map((r) => r.type)).toContain("mobile_in");
    expect(detect("UAN 100123456789").map((r) => r.type)).toContain("uan");
    expect(detect("MICR 400002007").map((r) => r.type)).toContain("micr");
    expect(detect("DIN 01234567 of director").map((r) => r.type)).toContain("din");
  });

  it("self-identifying tokens fire without a keyword", () => {
    expect(detect("reach +919876543210 anytime").map((r) => r.type)).toContain("mobile_in");
    expect(detect("reach +91 98765 43210 anytime").map((r) => r.type)).toContain("mobile_in");
    expect(detect("send to ramesh@oksbi please").map((r) => r.type)).toContain("upi_vpa");
    expect(detect("acct IN30001012345678 here").map((r) => r.type)).toContain("demat");
  });
});

describe("detect — UPI vs email", () => {
  it("flags known-handle VPA but never a plain email", () => {
    expect(detect("pay ramesh@oksbi").map((r) => r.type)).toContain("upi_vpa");
    expect(detect("pay to ramesh@oksbi.").map((r) => r.type)).toContain("upi_vpa"); // trailing period
    expect(detect("mail me at user@gmail.com").map((r) => r.type)).not.toContain("upi_vpa");
    expect(detect("contact user@gmail.com")).toHaveLength(0);
  });
  it("unknown handle needs UPI/VPA context", () => {
    expect(detect("token alice@randomxyz here")).toHaveLength(0);
    expect(detect("upi id alice@randomxyz").map((r) => r.type)).toContain("upi_vpa");
  });
});

describe("detect — boundary & dedup/overlap", () => {
  it("does not match a value embedded in a longer run", () => {
    expect(detect("xx4111111111111111xx")).toHaveLength(0); // alnum-glued
    expect(detect("PAN inABCPK1234Zoo")).toHaveLength(0);
  });

  it("keeps GSTIN, not the PAN embedded inside it", () => {
    const r = detect("GSTIN 27AAPFU0939F1ZV");
    expect(r).toHaveLength(1);
    expect(r[0]!.type).toBe("gstin");
    expect(r[0]!.valid).toBe(true);
  });

  it("prefers checksum-validated card over structure-only overlap", () => {
    const r = detect("card 4111 1111 1111 1111 on file");
    const card = r.find((x) => x.type === "card");
    expect(card).toBeTruthy();
    expect(card!.valid).toBe(true);
    expect(card!.confidence).toBeGreaterThan(0.9);
    // no overlapping second hit on the same span
    expect(r.filter((x) => x.index === card!.index)).toHaveLength(1);
  });
});

describe("detect — requireValid & shape", () => {
  it("includes shape-only invalid hits by default, excludes with requireValid", () => {
    const text = "PAN ABCDK1234Z"; // 4th char D → invalid holder type
    const loose = detect(text);
    expect(loose.find((r) => r.type === "pan")?.valid).toBe(false);
    const strict = detect(text, { requireValid: true });
    expect(strict.find((r) => r.type === "pan")).toBeUndefined();
  });

  it("honours the types allowlist", () => {
    const text = "PAN ABCPK1234Z and IFSC SBIN0001234";
    const only = detect(text, { types: ["pan"] });
    expect(only.every((r) => r.type === "pan")).toBe(true);
    expect(only).toHaveLength(1);
  });

  it("result objects have the documented shape", () => {
    const [r] = detect("ABCPK1234Z");
    expect(r).toMatchObject({
      type: "pan",
      value: "ABCPK1234Z",
      index: 0,
      valid: true,
    });
    expect(typeof r!.confidence).toBe("number");
  });
});

describe("mask", () => {
  it("masks all detected PII in text", () => {
    expect(mask("PAN: ABCPK1234Z")).toBe("PAN: AXXXXXXXXZ");
    expect(mask("My Aadhaar is 2345 6789 0124.")).toBe("My Aadhaar is XXXX XXXX 0124.");
    expect(mask("card 4111 1111 1111 1111")).toBe("card XXXX XXXX XXXX 1111");
  });

  it("supports a custom mask character", () => {
    expect(mask("PAN: ABCPK1234Z", { maskChar: "•" })).toBe("PAN: A••••••••Z");
  });

  it("leaves text without PII unchanged", () => {
    expect(mask("hello world")).toBe("hello world");
  });
});

describe("maskValue", () => {
  it("masks a single value by type", () => {
    expect(maskValue("card", "4111111111111111")).toBe("XXXXXXXXXXXX1111");
    expect(maskValue("aadhaar", "2345 6789 0124")).toBe("XXXX XXXX 0124");
    expect(maskValue("pan", "ABCPK1234Z")).toBe("AXXXXXXXXZ");
  });
  it("returns input for unknown type, empty for non-string", () => {
    expect(maskValue("nope", "secret")).toBe("secret");
    expect(maskValue("pan", 123 as unknown)).toBe("");
  });
});

describe("input safety", () => {
  it("never throws on null/undefined/non-string", () => {
    expect(detect(null)).toEqual([]);
    expect(detect(undefined)).toEqual([]);
    expect(detect(12345 as unknown)).toEqual([]);
    expect(detect("")).toEqual([]);
    expect(mask(null)).toBe("");
    expect(mask(12345 as unknown)).toBe("");
    expect(mask("")).toBe("");
  });
});

describe("registry", () => {
  it("exposes exactly the 18 detectors with required metadata", () => {
    expect(detectors).toHaveLength(18);
    for (const d of detectors) {
      expect(typeof d.id).toBe("string");
      expect(typeof d.label).toBe("string");
      expect(typeof d.validate).toBe("function");
      expect(typeof d.mask).toBe("function");
      expect(Array.isArray(d.contextHints)).toBe(true);
      expect(d.regex).toBeInstanceOf(RegExp);
    }
  });
});

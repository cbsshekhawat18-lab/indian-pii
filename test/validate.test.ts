/* ============================================================================
 *  indian-pii — Detect, validate & mask Indian PII for JavaScript
 *  Author   : Chandrabhan Shekhawat
 *  Company  : Gigai Kripa Services
 *  Website  : https://gigaikripaservices.com/
 *  © 2026 Chandrabhan Shekhawat / Gigai Kripa Services.
 *  Released under the MIT License. See LICENSE.
 * ========================================================================== */

import { describe, it, expect } from "vitest";
import { validate } from "../src/index.js";

describe("aadhaar", () => {
  it("accepts Verhoeff-valid numbers (with/without separators)", () => {
    expect(validate("aadhaar", "234567890124")).toBe(true);
    expect(validate("aadhaar", "4567 8901 2341")).toBe(true);
    expect(validate("aadhaar", "9876-5432-1096")).toBe(true);
  });
  it("rejects bad checksum / leading 0-1 / wrong length / junk", () => {
    expect(validate("aadhaar", "234567890123")).toBe(false); // wrong checksum
    expect(validate("aadhaar", "012345678905")).toBe(false); // starts 0
    expect(validate("aadhaar", "112345678901")).toBe(false); // starts 1
    expect(validate("aadhaar", "23456789012")).toBe(false); // 11 digits
    expect(validate("aadhaar", "")).toBe(false);
    expect(validate("aadhaar", null)).toBe(false);
  });
});

describe("pan", () => {
  it("accepts valid PAN", () => {
    expect(validate("pan", "ABCPK1234Z")).toBe(true);
    expect(validate("pan", "aaaca1234a")).toBe(true); // case-insensitive, C company
    expect(validate("pan", "ZZZHZ9999Z")).toBe(true); // H HUF
  });
  it("rejects bad 4th char / structure / embedded", () => {
    expect(validate("pan", "ABCDK1234Z")).toBe(false); // 4th char D invalid
    expect(validate("pan", "ABCP12345Z")).toBe(false); // structure
    expect(validate("pan", "ABCPK1234ZZ")).toBe(false);
    expect(validate("pan", "")).toBe(false);
  });
});

describe("voter_id", () => {
  it("accepts EPIC structure", () => {
    expect(validate("voter_id", "ABC1234567")).toBe(true);
    expect(validate("voter_id", "xyz7654321")).toBe(true);
    expect(validate("voter_id", "WBA0001112")).toBe(true);
  });
  it("rejects malformed", () => {
    expect(validate("voter_id", "AB1234567")).toBe(false);
    expect(validate("voter_id", "ABCD234567")).toBe(false);
    expect(validate("voter_id", "ABC123456")).toBe(false);
    expect(validate("voter_id", undefined)).toBe(false);
  });
});

describe("passport", () => {
  it("accepts valid Indian passport", () => {
    expect(validate("passport", "A1234567")).toBe(true);
    expect(validate("passport", "P7654321")).toBe(true);
    expect(validate("passport", "w1112223")).toBe(true);
  });
  it("rejects Q/X/Z first letter and bad length", () => {
    expect(validate("passport", "Q1234567")).toBe(false);
    expect(validate("passport", "X1234567")).toBe(false);
    expect(validate("passport", "A123456")).toBe(false);
    expect(validate("passport", "")).toBe(false);
  });
});

describe("driving_licence", () => {
  it("accepts valid state code + digit variants", () => {
    expect(validate("driving_licence", "MH1220110012345")).toBe(true);
    expect(validate("driving_licence", "DL0420110149646")).toBe(true);
    expect(validate("driving_licence", "KA01 2019 0012345")).toBe(true);
  });
  it("rejects bad state code / too few digits / junk", () => {
    expect(validate("driving_licence", "ZZ1220110012345")).toBe(false); // bad state
    expect(validate("driving_licence", "MH12200001")).toBe(false); // too short
    expect(validate("driving_licence", "")).toBe(false);
    expect(validate("driving_licence", 12345 as unknown)).toBe(false);
  });
});

describe("upi_vpa", () => {
  it("accepts known handles, never plain emails", () => {
    expect(validate("upi_vpa", "ramesh@oksbi")).toBe(true);
    expect(validate("upi_vpa", "9876543210@ybl")).toBe(true);
    expect(validate("upi_vpa", "priya.k@okhdfcbank")).toBe(true);
  });
  it("rejects emails / missing psp / junk", () => {
    expect(validate("upi_vpa", "user@gmail.com")).toBe(false);
    expect(validate("upi_vpa", "user@")).toBe(false);
    expect(validate("upi_vpa", "nothandle")).toBe(false);
    expect(validate("upi_vpa", "")).toBe(false);
  });
});

describe("ifsc", () => {
  it("accepts valid IFSC (5th char 0)", () => {
    expect(validate("ifsc", "SBIN0001234")).toBe(true);
    expect(validate("ifsc", "hdfc0000123")).toBe(true);
    expect(validate("ifsc", "ICIC0ABCD12")).toBe(true);
  });
  it("rejects 5th-char-not-0 / structure / junk", () => {
    expect(validate("ifsc", "SBIN1001234")).toBe(false);
    expect(validate("ifsc", "SB1N0001234")).toBe(false);
    expect(validate("ifsc", "SBIN000123")).toBe(false);
    expect(validate("ifsc", null)).toBe(false);
  });
});

describe("micr", () => {
  it("accepts 9 digits", () => {
    expect(validate("micr", "400002007")).toBe(true);
    expect(validate("micr", "110002001")).toBe(true);
    expect(validate("micr", "560002002")).toBe(true);
  });
  it("rejects wrong length / junk", () => {
    expect(validate("micr", "40000200")).toBe(false);
    expect(validate("micr", "4000020077")).toBe(false);
    expect(validate("micr", "abc002007")).toBe(false);
    expect(validate("micr", "")).toBe(false);
  });
});

describe("demat", () => {
  it("accepts NSDL IN+14 and CDSL 16 digits", () => {
    expect(validate("demat", "IN30001012345678")).toBe(true);
    expect(validate("demat", "1234567890123456")).toBe(true);
    expect(validate("demat", "in30123412341234")).toBe(true);
  });
  it("rejects wrong length / junk", () => {
    expect(validate("demat", "IN3000101234567")).toBe(false); // 13 after IN
    expect(validate("demat", "123456789012345")).toBe(false); // 15 digits
    expect(validate("demat", "ABCD567890123456")).toBe(false);
    expect(validate("demat", null)).toBe(false);
  });
});

describe("card", () => {
  it("accepts Luhn + valid IIN + length", () => {
    expect(validate("card", "4111111111111111")).toBe(true); // Visa
    expect(validate("card", "5105 1051 0510 5100")).toBe(true); // MC
    expect(validate("card", "371449635398431")).toBe(true); // Amex
    expect(validate("card", "6075640000000000")).toBe(true); // RuPay
  });
  it("rejects non-Luhn / bad prefix / wrong length", () => {
    expect(validate("card", "4111111111111112")).toBe(false); // non-Luhn
    expect(validate("card", "1234567812345670")).toBe(false); // bad IIN (Luhn ok)
    expect(validate("card", "411111111111")).toBe(false); // too short
    expect(validate("card", "")).toBe(false);
  });
});

describe("gstin", () => {
  it("accepts valid check digit + state code", () => {
    expect(validate("gstin", "27AAPFU0939F1ZV")).toBe(true);
    expect(validate("gstin", "29AAGCB7383J1Z4")).toBe(true);
    expect(validate("gstin", "07aaach1925q1zc")).toBe(true);
  });
  it("rejects bad check digit / bad state / structure", () => {
    expect(validate("gstin", "27AAPFU0939F1ZX")).toBe(false); // wrong check
    expect(validate("gstin", "99AAPFU0939F1ZV")).toBe(false); // bad state code
    expect(validate("gstin", "27AAPFU0939F1Z")).toBe(false); // short
    expect(validate("gstin", "")).toBe(false);
  });
});

describe("tan", () => {
  it("accepts valid TAN", () => {
    expect(validate("tan", "MUMA12345B")).toBe(true);
    expect(validate("tan", "delh99999z")).toBe(true);
    expect(validate("tan", "BLRT00001A")).toBe(true);
  });
  it("rejects malformed", () => {
    expect(validate("tan", "MUM12345B")).toBe(false);
    expect(validate("tan", "MUMA1234B")).toBe(false);
    expect(validate("tan", "MUMA12345")).toBe(false);
    expect(validate("tan", undefined)).toBe(false);
  });
});

describe("cin", () => {
  it("accepts valid 21-char CIN segments", () => {
    expect(validate("cin", "L17110MH1973PLC019786")).toBe(true);
    expect(validate("cin", "U72200KA2011PTC123456")).toBe(true);
    expect(validate("cin", "l01631tn2004plc053469")).toBe(true);
  });
  it("rejects bad state / year / ownership / structure", () => {
    expect(validate("cin", "L17110ZZ1973PLC019786")).toBe(false); // bad state
    expect(validate("cin", "L17110MH1700PLC019786")).toBe(false); // bad year
    expect(validate("cin", "L17110MH1973XYZ019786")).toBe(false); // bad ownership
    expect(validate("cin", "L17110MH1973PLC01978")).toBe(false); // structure
  });
});

describe("din", () => {
  it("accepts 8 digits", () => {
    expect(validate("din", "01234567")).toBe(true);
    expect(validate("din", "08765432")).toBe(true);
    expect(validate("din", "00000001")).toBe(true);
  });
  it("rejects wrong length / junk", () => {
    expect(validate("din", "1234567")).toBe(false);
    expect(validate("din", "123456789")).toBe(false);
    expect(validate("din", "0123456a")).toBe(false);
    expect(validate("din", "")).toBe(false);
  });
});

describe("uan", () => {
  it("accepts 12 digits", () => {
    expect(validate("uan", "100123456789")).toBe(true);
    expect(validate("uan", "101010101010")).toBe(true);
    expect(validate("uan", "123456789012")).toBe(true);
  });
  it("rejects wrong length / junk", () => {
    expect(validate("uan", "10012345678")).toBe(false);
    expect(validate("uan", "1001234567890")).toBe(false);
    expect(validate("uan", "10012345678a")).toBe(false);
    expect(validate("uan", null)).toBe(false);
  });
});

describe("abha", () => {
  it("accepts 14-digit Verhoeff-valid (with/without separators)", () => {
    expect(validate("abha", "12345678901230")).toBe(true);
    expect(validate("abha", "98-7654-3210-9873")).toBe(true);
    expect(validate("abha", "55 5544 4433 3326")).toBe(true);
  });
  it("rejects bad checksum / wrong length / junk", () => {
    expect(validate("abha", "12345678901234")).toBe(false); // bad checksum
    expect(validate("abha", "1234567890123")).toBe(false); // 13 digits
    expect(validate("abha", "abcd5678901230")).toBe(false);
    expect(validate("abha", "")).toBe(false);
  });
});

describe("mobile_in", () => {
  it("accepts 10-digit 6-9 start, optional +91", () => {
    expect(validate("mobile_in", "9876543210")).toBe(true);
    expect(validate("mobile_in", "+91 98765 43210")).toBe(true);
    expect(validate("mobile_in", "919876543210")).toBe(true);
  });
  it("rejects 0-5 start / wrong length / junk", () => {
    expect(validate("mobile_in", "5876543210")).toBe(false);
    expect(validate("mobile_in", "987654321")).toBe(false);
    expect(validate("mobile_in", "98765432100")).toBe(false);
    expect(validate("mobile_in", "")).toBe(false);
  });
});

describe("pincode", () => {
  it("accepts 6-digit non-zero start", () => {
    expect(validate("pincode", "560001")).toBe(true);
    expect(validate("pincode", "110001")).toBe(true);
    expect(validate("pincode", "400072")).toBe(true);
  });
  it("rejects leading 0 / wrong length / junk", () => {
    expect(validate("pincode", "012345")).toBe(false);
    expect(validate("pincode", "56001")).toBe(false);
    expect(validate("pincode", "5600011")).toBe(false);
    expect(validate("pincode", "abc001")).toBe(false);
  });
});

describe("validate guards", () => {
  it("unknown type and non-string input return false", () => {
    expect(validate("nope", "ABCPK1234Z")).toBe(false);
    expect(validate("pan", 42 as unknown)).toBe(false);
    expect(validate("pan", {} as unknown)).toBe(false);
  });
});

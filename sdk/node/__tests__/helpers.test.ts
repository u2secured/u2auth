import {
  generateSecret,
  generateQRCodeURI,
  generateRecoveryCodes,
} from "../src/helpers.js";

const BASE32_RE = /^[A-Z2-7]+$/;
const ALNUM_RE = /^[A-Z0-9]+$/;

describe("generateSecret", () => {
  it("returns a non-empty string", () => {
    const secret = generateSecret();
    expect(typeof secret).toBe("string");
    expect(secret.length).toBeGreaterThan(0);
  });

  it("is valid base32 (RFC 4648 alphabet)", () => {
    const secret = generateSecret(20);
    expect(BASE32_RE.test(secret)).toBe(true);
  });

  it("generates unique secrets", () => {
    const secrets = Array.from({ length: 20 }, () => generateSecret());
    const unique = new Set(secrets);
    expect(unique.size).toBe(20);
  });

  it("respects custom byte length", () => {
    const short = generateSecret(10);
    const long = generateSecret(40);
    expect(long.length).toBeGreaterThan(short.length);
  });
});

describe("generateQRCodeURI", () => {
  it("starts with otpauth://totp/", () => {
    const uri = generateQRCodeURI("MyApp", "user@example.com", "SECRET");
    expect(uri.startsWith("otpauth://totp/")).toBe(true);
  });

  it("contains secret, issuer, algorithm, digits, period in query string", () => {
    const uri = generateQRCodeURI("MyApp", "alice@example.com", "MYSECRET");
    expect(uri).toContain("secret=MYSECRET");
    expect(uri).toContain("issuer=MyApp");
    expect(uri).toContain("algorithm=SHA1");
    expect(uri).toContain("digits=6");
    expect(uri).toContain("period=30");
  });

  it("uses custom options when provided", () => {
    const uri = generateQRCodeURI("Acme", "bob@example.com", "SECRET", {
      algorithm: "SHA256",
      digits: 8,
      period: 60,
    });
    expect(uri).toContain("algorithm=SHA256");
    expect(uri).toContain("digits=8");
    expect(uri).toContain("period=60");
  });

  it("encodes issuer and account in the label", () => {
    const uri = generateQRCodeURI(
      "My App",
      "user+tag@example.com",
      "SECRET"
    );
    expect(uri).toContain("My%20App");
  });
});

describe("generateRecoveryCodes", () => {
  it("returns exactly count codes", () => {
    const codes = generateRecoveryCodes(10);
    expect(codes.length).toBe(10);
  });

  it("each code is 8 characters long", () => {
    const codes = generateRecoveryCodes(5);
    for (const code of codes) {
      expect(code.length).toBe(8);
    }
  });

  it("codes are alphanumeric (uppercase)", () => {
    const codes = generateRecoveryCodes(10);
    for (const code of codes) {
      expect(ALNUM_RE.test(code)).toBe(true);
    }
  });

  it("codes are unique", () => {
    const codes = generateRecoveryCodes(20);
    const unique = new Set(codes);
    expect(unique.size).toBe(20);
  });

  it("uses default count of 10", () => {
    const codes = generateRecoveryCodes();
    expect(codes.length).toBe(10);
  });
});

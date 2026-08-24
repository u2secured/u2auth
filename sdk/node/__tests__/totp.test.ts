import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { generateSecret, generateTOTP, validateTOTP } from "../src/helpers.js";

// The vectors are generated from, and guarded against, the backend's own
// implementation (see backend/internal/totp/shared_vectors_test.go). Running
// them here is what stops local validation drifting from the server's answer.
const vectors = JSON.parse(
  readFileSync(resolve(process.cwd(), "../testvectors/totp.json"), "utf8"),
);

describe("validateTOTP agrees with the backend", () => {
  for (const c of vectors.cases as { name: string; secret: string; time: number; code: string; valid: boolean }[]) {
    test(c.name, () => {
      expect(validateTOTP(c.secret, c.code, c.time * 1000, vectors.digits, vectors.period_sec)).toBe(c.valid);
    });
  }
});

test("a freshly generated secret validates its own current code", () => {
  const secret = generateSecret();
  const now = Date.now();
  expect(validateTOTP(secret, generateTOTP(secret, now), now)).toBe(true);
});

test("a code of the wrong length is rejected rather than throwing", () => {
  const secret = generateSecret();
  expect(validateTOTP(secret, "12345", Date.now())).toBe(false);
  expect(validateTOTP(secret, "", Date.now())).toBe(false);
});

test("surrounding whitespace in the typed code is tolerated", () => {
  const secret = generateSecret();
  const now = Date.now();
  expect(validateTOTP(secret, `  ${generateTOTP(secret, now)} `, now)).toBe(true);
});

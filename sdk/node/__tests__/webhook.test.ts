import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { verifyWebhook } from "../src/webhook.js";

const vector = JSON.parse(
  readFileSync(resolve(process.cwd(), "../testvectors/webhook.json"), "utf8"),
);
const BIG = 10 ** 12; // huge tolerance so the 2023 vector timestamp doesn't trip the check

test("verifyWebhook returns the event for a valid signature", () => {
  const ev = verifyWebhook(vector.body, vector.signature_header, vector.secret, { toleranceSec: BIG });
  expect(ev).toMatchObject({ approval_id: "ap_test123", status: "approved", reason: "user_approved" });
});

test("verifyWebhook throws on a tampered body", () => {
  expect(() => verifyWebhook(vector.body + " ", vector.signature_header, vector.secret, { toleranceSec: BIG }))
    .toThrow(/signature/i);
});

test("verifyWebhook throws on the wrong secret", () => {
  expect(() => verifyWebhook(vector.body, vector.signature_header, "wrong", { toleranceSec: BIG }))
    .toThrow(/signature/i);
});

test("verifyWebhook throws on an expired timestamp", () => {
  expect(() => verifyWebhook(vector.body, vector.signature_header, vector.secret))
    .toThrow(/timestamp/i);
});

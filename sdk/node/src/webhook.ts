import { createHmac, timingSafeEqual } from "node:crypto";
import { U2AuthError } from "./client.js";

export interface WebhookEvent {
  approval_id: string;
  status: string;
  reason?: string;
  resolved_at?: string;
}

/** Verify the X-U2Auth-Signature over the RAW payload. Returns the parsed event or throws U2AuthError. */
export function verifyWebhook(
  payload: string | Buffer,
  sigHeader: string,
  secret: string,
  opts?: { toleranceSec?: number }
): WebhookEvent {
  const toleranceSec = opts?.toleranceSec ?? 300;
  const { t, v1 } = parseSigHeader(sigHeader);
  const body = typeof payload === "string" ? payload : payload.toString("utf8");
  const expected = createHmac("sha256", secret)
    .update(`${t}.${body}`)
    .digest("hex");
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(v1, "utf8");
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    throw new U2AuthError(0, "INVALID_SIGNATURE", "invalid webhook signature");
  }
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - t) > toleranceSec) {
    throw new U2AuthError(
      0,
      "TIMESTAMP_OUT_OF_TOLERANCE",
      "webhook timestamp out of tolerance"
    );
  }
  return JSON.parse(body) as WebhookEvent;
}

function parseSigHeader(h: string): { t: number; v1: string } {
  let t: number | undefined;
  let v1: string | undefined;
  for (const part of h.split(",")) {
    const [k, val] = part.trim().split("=");
    if (k === "t") t = parseInt(val, 10);
    else if (k === "v1") v1 = val;
  }
  if (t === undefined || Number.isNaN(t) || !v1) {
    throw new U2AuthError(0, "INVALID_SIGNATURE", "malformed signature header");
  }
  return { t, v1 };
}

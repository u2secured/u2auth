import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { U2Auth, U2AuthError } from "../src/client.js";

function startMockServer(
  handler: (req: IncomingMessage, res: ServerResponse) => void
): Promise<{ url: string; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as { port: number };
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        close: () =>
          new Promise((res, rej) =>
            server.close((err) => (err ? rej(err) : res()))
          ),
      });
    });
  });
}

function jsonResponse(
  res: ServerResponse,
  status: number,
  body: unknown
): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

describe("U2Auth.verifyTOTP", () => {
  it("returns valid=true on success", async () => {
    const { url, close } = await startMockServer((req, res) => {
      expect(req.method).toBe("POST");
      expect(req.url).toBe("/api/v1/sdk/totp/verify");
      expect(req.headers["authorization"]).toBe("Bearer rka_test");
      jsonResponse(res, 200, { valid: true });
    });

    const client = new U2Auth("rka_test", { baseURL: url });
    const result = await client.verifyTOTP("MYSECRET", "123456");
    expect(result.valid).toBe(true);
    await close();
  });

  it("returns valid=false when code is wrong", async () => {
    const { url, close } = await startMockServer((req, res) => {
      jsonResponse(res, 200, { valid: false });
    });

    const client = new U2Auth("rka_test", { baseURL: url });
    const result = await client.verifyTOTP("MYSECRET", "000000");
    expect(result.valid).toBe(false);
    await close();
  });

  it("throws U2AuthError on 4xx", async () => {
    const { url, close } = await startMockServer((req, res) => {
      jsonResponse(res, 401, {
        error: { code: "UNAUTHORIZED", message: "bad key" },
      });
    });

    const client = new U2Auth("rka_bad", { baseURL: url });
    await expect(client.verifyTOTP("SECRET", "123")).rejects.toBeInstanceOf(
      U2AuthError
    );
    await close();
  });

  it("U2AuthError has correct statusCode and code", async () => {
    const { url, close } = await startMockServer((req, res) => {
      jsonResponse(res, 401, {
        error: { code: "UNAUTHORIZED", message: "bad key" },
      });
    });

    const client = new U2Auth("rka_bad", { baseURL: url });
    try {
      await client.verifyTOTP("SECRET", "123");
      fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(U2AuthError);
      const err = e as U2AuthError;
      expect(err.statusCode).toBe(401);
      expect(err.code).toBe("UNAUTHORIZED");
    }
    await close();
  });
});

describe("U2Auth.requestPush", () => {
  it("returns push result on success", async () => {
    let body = "";
    const { url, close } = await startMockServer((req, res) => {
      expect(req.url).toBe("/api/v1/sdk/push/request");
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        jsonResponse(res, 200, {
          approval_id: "apr_abc",
          status: "pending",
          expires_at: "2026-06-01T12:00:00Z",
        });
      });
    });

    const client = new U2Auth("rka_test", { baseURL: url });
    const result = await client.requestPush(
      "user@example.com",
      "Login from Chrome"
    );
    expect(result.approval_id).toBe("apr_abc");
    expect(result.status).toBe("pending");
    const parsed = JSON.parse(body);
    expect(parsed.user_identifier).toBe("user@example.com");
    await close();
  });

  it("forwards webhook_url and ttl options", async () => {
    let body = "";
    const { url, close } = await startMockServer((req, res) => {
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        jsonResponse(res, 200, {
          approval_id: "apr_xyz",
          status: "pending",
          expires_at: "2026-06-01T12:00:00Z",
        });
      });
    });

    const client = new U2Auth("rka_test", { baseURL: url });
    await client.requestPush("user@example.com", "Test", {
      webhook_url: "https://example.com/hook",
      ttl: 300,
    });
    const parsed = JSON.parse(body);
    expect(parsed.webhook_url).toBe("https://example.com/hook");
    expect(parsed.ttl).toBe(300);
    await close();
  });
});

describe("U2Auth.getPushStatus", () => {
  it("returns push status on success", async () => {
    const { url, close } = await startMockServer((req, res) => {
      expect(req.method).toBe("GET");
      expect(req.url).toBe("/api/v1/sdk/push/apr_abc123/status");
      jsonResponse(res, 200, {
        approval_id: "apr_abc123",
        status: "approved",
      });
    });

    const client = new U2Auth("rka_test", { baseURL: url });
    const status = await client.getPushStatus("apr_abc123");
    expect(status.status).toBe("approved");
    expect(status.approval_id).toBe("apr_abc123");
    await close();
  });

  it("throws U2AuthError on 404", async () => {
    const { url, close } = await startMockServer((req, res) => {
      jsonResponse(res, 404, {
        error: { code: "NOT_FOUND", message: "approval not found" },
      });
    });

    const client = new U2Auth("rka_test", { baseURL: url });
    try {
      await client.getPushStatus("nonexistent");
      fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(U2AuthError);
      const err = e as U2AuthError;
      expect(err.statusCode).toBe(404);
      expect(err.code).toBe("NOT_FOUND");
    }
    await close();
  });

  it("parses reason and resolved_at", async () => {
    const { url, close } = await startMockServer((req, res) => {
      jsonResponse(res, 200, {
        approval_id: "ap1",
        status: "denied",
        reason: "wrong_number",
        resolved_at: "2026-01-01T00:00:00Z",
      });
    });

    const client = new U2Auth("rka_test", { baseURL: url });
    const st = await client.getPushStatus("ap1");
    expect(st.reason).toBe("wrong_number");
    expect(st.resolved_at).toBe("2026-01-01T00:00:00Z");
    await close();
  });
});

describe("U2Auth.requestPush match_number", () => {
  it("parses match_number", async () => {
    const { url, close } = await startMockServer((req, res) => {
      req.on("data", () => {});
      req.on("end", () => {
        jsonResponse(res, 201, {
          approval_id: "ap1",
          match_number: 42,
          status: "pending",
          expires_at: "2026-01-01T00:00:00Z",
        });
      });
    });

    const client = new U2Auth("rka_test", { baseURL: url });
    const res = await client.requestPush("user@x", "ctx");
    expect(res.match_number).toBe(42);
    await close();
  });
});

describe("U2Auth.waitForApproval", () => {
  it("polls until approved", async () => {
    let calls = 0;
    const { url, close } = await startMockServer((_req, res) => {
      calls += 1;
      jsonResponse(res, 200, {
        approval_id: "ap1",
        status: calls < 3 ? "pending" : "approved",
      });
    });

    const client = new U2Auth("rka_test", { baseURL: url });
    const st = await client.waitForApproval("ap1", {
      intervalMs: 5,
      timeoutMs: 1000,
    });
    expect(st.status).toBe("approved");
    await close();
  });

  it("rejects on timeout", async () => {
    const { url, close } = await startMockServer((_req, res) => {
      jsonResponse(res, 200, { approval_id: "ap1", status: "pending" });
    });

    const client = new U2Auth("rka_test", { baseURL: url });
    await expect(
      client.waitForApproval("ap1", { intervalMs: 5, timeoutMs: 40 })
    ).rejects.toMatchObject({ code: "WAIT_TIMEOUT" });
    await close();
  });
});

describe("U2Auth.createPairingCode", () => {
  it("posts the identifier and returns the code", async () => {
    let gotBody = "";
    const { url, close } = await startMockServer((req, res) => {
      expect(req.method).toBe("POST");
      expect(req.url).toBe("/api/v1/sdk/pairing-codes");
      const chunks: Buffer[] = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        gotBody = Buffer.concat(chunks).toString();
        jsonResponse(res, 201, {
          code: "3f9a-c210",
          expires_at: "2026-07-31T10:20:00Z",
        });
      });
    });

    try {
      const client = new U2Auth("rka_test", { baseURL: url });
      const result = await client.createPairingCode("alice@acme.com");
      expect(JSON.parse(gotBody)).toEqual({ user_identifier: "alice@acme.com" });
      expect(result.code).toBe("3f9a-c210");
      expect(result.expires_at).toBe("2026-07-31T10:20:00Z");
    } finally {
      await close();
    }
  });
});

describe("U2Auth.listEnrolments", () => {
  it("sends limit/sort/order, never an app_id, and omits cursor when unset", async () => {
    let gotUrl = "";
    const { url, close } = await startMockServer((req, res) => {
      gotUrl = req.url ?? "";
      jsonResponse(res, 200, {
        items: [
          {
            id: "e1",
            user_identifier: "ellis@acme.test",
            created_at: "2026-08-01T10:00:00Z",
            last_auth_at: null,
            last_auth_outcome: null,
          },
        ],
        next_cursor: "abc",
      });
    });

    try {
      const client = new U2Auth("rka_test", { baseURL: url });
      const page = await client.listEnrolments({
        limit: 2,
        sort: "last_auth_at",
        order: "asc",
      });

      const [path, qs] = gotUrl.split("?");
      expect(path).toBe("/api/v1/sdk/enrolments");
      const query = new URLSearchParams(qs);
      expect(query.get("limit")).toBe("2");
      expect(query.get("sort")).toBe("last_auth_at");
      expect(query.get("order")).toBe("asc");
      // The app is resolved from the API key — an app id must never be sent.
      expect(query.has("app_id")).toBe(false);
      // Cursor was left unset — it must be genuinely absent from the query,
      // not sent as an empty value, so the request carries only what the
      // caller asked for.
      expect(query.has("cursor")).toBe(false);

      expect(page.items).toHaveLength(1);
      expect(page.items[0].user_identifier).toBe("ellis@acme.test");
      // A never-authenticated enrolment must decode as null, not a blank
      // string / zero time — callers need to tell "never" from "blank".
      expect(page.items[0].last_auth_at).toBeNull();
      expect(page.items[0].last_auth_outcome).toBeNull();
      expect(page.next_cursor).toBe("abc");
    } finally {
      await close();
    }
  });

  it("omits sort, order and cursor entirely when no options are given", async () => {
    let gotUrl = "";
    const { url, close } = await startMockServer((req, res) => {
      gotUrl = req.url ?? "";
      jsonResponse(res, 200, { items: [], next_cursor: "" });
    });

    try {
      const client = new U2Auth("rka_test", { baseURL: url });
      await client.listEnrolments();

      const [, qs] = gotUrl.split("?");
      const query = new URLSearchParams(qs ?? "");
      for (const key of ["sort", "order", "cursor", "limit"]) {
        expect(query.has(key)).toBe(false);
      }
    } finally {
      await close();
    }
  });

  it("throws U2AuthError on an invalid sort", async () => {
    const { url, close } = await startMockServer((_req, res) => {
      jsonResponse(res, 400, {
        error: { code: "INVALID_SORT", message: "unrecognised sort" },
      });
    });

    try {
      const client = new U2Auth("rka_test", { baseURL: url });
      await expect(
        client.listEnrolments({ sort: "user_identifier" as never })
      ).rejects.toMatchObject({ code: "INVALID_SORT", statusCode: 400 });
    } finally {
      await close();
    }
  });

  it("omits a negative limit from the query, same as zero", async () => {
    let gotUrl = "";
    const { url, close } = await startMockServer((req, res) => {
      gotUrl = req.url ?? "";
      jsonResponse(res, 200, { items: [], next_cursor: "" });
    });

    try {
      const client = new U2Auth("rka_test", { baseURL: url });
      await client.listEnrolments({ limit: -1 });

      const [, qs] = gotUrl.split("?");
      const query = new URLSearchParams(qs ?? "");
      expect(query.has("limit")).toBe(false);
    } finally {
      await close();
    }
  });
});

describe("U2Auth.listEnrolmentEvents", () => {
  it("sends limit against the per-enrolment path and distinguishes a null place from an empty region", async () => {
    let gotUrl = "";
    const { url, close } = await startMockServer((req, res) => {
      gotUrl = req.url ?? "";
      jsonResponse(res, 200, {
        items: [
          {
            id: "a1",
            kind: "push",
            outcome: "approved",
            created_at: "2026-08-01T10:00:00Z",
            place: { city: "Manchester", region: "", country: "GB" },
            new_country: false,
          },
          {
            id: "a2",
            kind: "totp",
            outcome: "verified",
            created_at: "2026-08-01T09:00:00Z",
            place: null,
            new_country: false,
          },
        ],
        next_cursor: "",
      });
    });

    try {
      const client = new U2Auth("rka_test", { baseURL: url });
      const page = await client.listEnrolmentEvents("e1", { limit: 10 });

      const [path, qs] = gotUrl.split("?");
      expect(path).toBe("/api/v1/sdk/enrolments/e1/events");
      const query = new URLSearchParams(qs);
      expect(query.get("limit")).toBe("10");
      expect(query.has("cursor")).toBe(false);

      // region "" is a legitimate value, distinct from a null place entirely.
      expect(page.items[0].place).toEqual({
        city: "Manchester",
        region: "",
        country: "GB",
      });
      // An event with no location fix must be a null place, not an empty
      // object — callers need to tell "unknown" from "blank".
      expect(page.items[1].place).toBeNull();
    } finally {
      await close();
    }
  });

  it("omits cursor entirely when no options are given", async () => {
    let gotUrl = "";
    const { url, close } = await startMockServer((req, res) => {
      gotUrl = req.url ?? "";
      jsonResponse(res, 200, { items: [], next_cursor: "" });
    });

    try {
      const client = new U2Auth("rka_test", { baseURL: url });
      await client.listEnrolmentEvents("e1");

      const [path, qs] = gotUrl.split("?");
      expect(path).toBe("/api/v1/sdk/enrolments/e1/events");
      const query = new URLSearchParams(qs ?? "");
      expect(query.has("cursor")).toBe(false);
      expect(query.has("limit")).toBe(false);
    } finally {
      await close();
    }
  });

  it("omits a negative limit from the query, same as zero", async () => {
    let gotUrl = "";
    const { url, close } = await startMockServer((req, res) => {
      gotUrl = req.url ?? "";
      jsonResponse(res, 200, { items: [], next_cursor: "" });
    });

    try {
      const client = new U2Auth("rka_test", { baseURL: url });
      await client.listEnrolmentEvents("e1", { limit: -5 });

      const [, qs] = gotUrl.split("?");
      const query = new URLSearchParams(qs ?? "");
      expect(query.has("limit")).toBe(false);
    } finally {
      await close();
    }
  });

  it("throws U2AuthError with ENROLMENT_NOT_FOUND for an unknown enrolment", async () => {
    const { url, close } = await startMockServer((_req, res) => {
      jsonResponse(res, 404, {
        error: { code: "ENROLMENT_NOT_FOUND", message: "no such enrolment" },
      });
    });

    try {
      const client = new U2Auth("rka_test", { baseURL: url });
      await expect(
        client.listEnrolmentEvents("ghost")
      ).rejects.toMatchObject({ code: "ENROLMENT_NOT_FOUND", statusCode: 404 });
    } finally {
      await close();
    }
  });
});

describe("U2Auth.deleteEnrolment", () => {
  it("sends DELETE with the identifier percent-encoded, and accepts an empty 204", async () => {
    let gotUrl = "";
    let gotMethod = "";
    const { url, close } = await startMockServer((req, res) => {
      gotUrl = req.url ?? "";
      gotMethod = req.method ?? "";
      res.writeHead(204);
      res.end();
    });

    try {
      const client = new U2Auth("rka_test", { baseURL: url });
      await client.deleteEnrolment("alice+tag@acme.com");
      expect(gotMethod).toBe("DELETE");
      // "+" must survive as %2B rather than decoding to a space.
      expect(gotUrl).toBe(
        "/api/v1/sdk/enrolments?user_identifier=alice%2Btag%40acme.com"
      );
    } finally {
      await close();
    }
  });

  it("throws ENROLMENT_NOT_FOUND when there is no such enrolment", async () => {
    const { url, close } = await startMockServer((_req, res) => {
      jsonResponse(res, 404, {
        error: { code: "ENROLMENT_NOT_FOUND", message: "no enrolment" },
      });
    });

    try {
      const client = new U2Auth("rka_test", { baseURL: url });
      await expect(client.deleteEnrolment("ghost@acme.com")).rejects.toThrow(
        U2AuthError
      );
      await expect(
        client.deleteEnrolment("ghost@acme.com")
      ).rejects.toMatchObject({ code: "ENROLMENT_NOT_FOUND", statusCode: 404 });
    } finally {
      await close();
    }
  });
});

describe("U2Auth.requestPush idempotency", () => {
  // The Idempotency-Key is an HTTP HEADER, not a body field. A key that leaks
  // into the JSON body is silently ignored by the server — the retry it was
  // meant to collapse sends the user a second push, and nothing fails loudly.
  it("sends the key as a header and keeps it out of the body", async () => {
    let body = "";
    let header: string | undefined;
    const { url, close } = await startMockServer((req, res) => {
      header = req.headers["idempotency-key"] as string | undefined;
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        jsonResponse(res, 200, { approval_id: "apr_abc", status: "pending" });
      });
    });

    const client = new U2Auth("rka_test", { baseURL: url });
    await client.requestPush("user@example.com", "Login", {
      idempotency_key: "nonce-123",
    });

    expect(header).toBe("nonce-123");
    expect(JSON.parse(body).idempotency_key).toBeUndefined();
    await close();
  });

  // A present-but-blank header is not the same as an absent one to the server.
  it("sends no header when no key is supplied", async () => {
    let present = true;
    const { url, close } = await startMockServer((req, res) => {
      present = "idempotency-key" in req.headers;
      req.on("end", () => {
        jsonResponse(res, 200, { approval_id: "apr_abc", status: "pending" });
      });
      req.resume();
    });

    const client = new U2Auth("rka_test", { baseURL: url });
    await client.requestPush("user@example.com", "Login", { ttl: 60 });

    expect(present).toBe(false);
    await close();
  });
});

describe("U2Auth.getEnrolment", () => {
  it("returns null when the user is not linked", async () => {
    const { url, close } = await startMockServer((req, res) => {
      expect(req.url).toContain("user_identifier=ada%40example.com");
      jsonResponse(res, 200, { items: [], next_cursor: "" });
    });

    const client = new U2Auth("rka_test", { baseURL: url });
    // Not an error: "not linked" is the normal answer at login, and forcing
    // callers into try/catch on the common path is how integrations end up
    // swallowing real errors too.
    expect(await client.getEnrolment("ada@example.com")).toBeNull();
    await close();
  });

  it("returns the single match with push_ready", async () => {
    const { url, close } = await startMockServer((req, res) => {
      jsonResponse(res, 200, {
        items: [
          {
            id: "en_1",
            user_identifier: "ada@example.com",
            created_at: "2026-09-15T09:00:00Z",
            last_auth_at: null,
            last_auth_outcome: null,
            push_ready: true,
          },
        ],
        next_cursor: "",
      });
    });

    const client = new U2Auth("rka_test", { baseURL: url });
    const e = await client.getEnrolment("ada@example.com");
    expect(e?.id).toBe("en_1");
    expect(e?.push_ready).toBe(true);
    await close();
  });
});

describe("U2Auth.waitForLink", () => {
  it("polls until the code is redeemed and returns the enrolment", async () => {
    let call = 0;
    const { url, close } = await startMockServer((req, res) => {
      call += 1;
      if (req.url?.startsWith("/api/v1/sdk/pairing-codes/")) {
        jsonResponse(res, 200, call === 1 ? { status: "pending" } : { status: "redeemed", enrolment_id: "en_1" });
        return;
      }
      jsonResponse(res, 200, {
        items: [
          {
            id: "en_1",
            user_identifier: "ada@example.com",
            created_at: "2026-09-15T09:00:00Z",
            last_auth_at: null,
            last_auth_outcome: null,
            push_ready: false,
          },
        ],
        next_cursor: "",
      });
    });

    const client = new U2Auth("rka_test", { baseURL: url });
    const e = await client.waitForLink("af17-b500", {
      userIdentifier: "ada@example.com",
      intervalMs: 1,
    });
    expect(e.id).toBe("en_1");
    await close();
  });

  it("rejects with PAIRING_CODE_EXPIRED when the code lapses", async () => {
    const { url, close } = await startMockServer((req, res) => {
      jsonResponse(res, 200, { status: "expired" });
    });

    const client = new U2Auth("rka_test", { baseURL: url });
    await expect(
      client.waitForLink("af17-b500", { userIdentifier: "ada@example.com", intervalMs: 1 })
    ).rejects.toMatchObject({ code: "PAIRING_CODE_EXPIRED" });
    await close();
  });

  it("rejects with LINK_TIMEOUT once the deadline passes", async () => {
    const { url, close } = await startMockServer((req, res) => {
      jsonResponse(res, 200, { status: "pending" });
    });

    const client = new U2Auth("rka_test", { baseURL: url });
    await expect(
      client.waitForLink("af17-b500", {
        userIdentifier: "ada@example.com",
        intervalMs: 1,
        timeoutMs: 3,
      })
    ).rejects.toMatchObject({ code: "LINK_TIMEOUT" });
    await close();
  });

  // The TypeScript type says userIdentifier is required, but the type is
  // erased at runtime and this package ships to npm — a plain-JS caller, a TS
  // caller with strictNullChecks off, or anyone passing an `any`-typed or
  // JSON-sourced options object gets here with it undefined. Without the
  // guard, undefined flows into listEnrolments, the user_identifier filter is
  // dropped from the query, and waitForLink resolves with the app's FIRST
  // enrolment — belonging to someone else entirely — with no error at all.
  //
  // The stub below answers "redeemed" immediately and serves exactly that
  // other-user enrolment, so an unguarded build fails this test in
  // milliseconds rather than hanging; timeoutMs is a 3ms backstop.
  it.each([
    ["missing", {}],
    ["empty", { userIdentifier: "" }],
  ])(
    "rejects with MISSING_USER_IDENTIFIER, before any request, when userIdentifier is %s",
    async (_label, badOpts) => {
      const requests: string[] = [];
      const { url, close } = await startMockServer((req, res) => {
        requests.push(req.url ?? "");
        if (req.url?.startsWith("/api/v1/sdk/pairing-codes/")) {
          jsonResponse(res, 200, { status: "redeemed", enrolment_id: "en_other" });
          return;
        }
        jsonResponse(res, 200, {
          items: [
            {
              id: "en_other",
              user_identifier: "SOMEONE-ELSE-ENTIRELY",
              created_at: "2026-09-15T09:00:00Z",
              last_auth_at: null,
              last_auth_outcome: null,
              push_ready: true,
            },
          ],
          next_cursor: "",
        });
      });

      try {
        const client = new U2Auth("rka_test", { baseURL: url });
        await expect(
          client.waitForLink("af17-b500", {
            ...(badOpts as Record<string, unknown>),
            intervalMs: 1,
            timeoutMs: 3,
          } as unknown as Parameters<U2Auth["waitForLink"]>[1])
        ).rejects.toMatchObject({ code: "MISSING_USER_IDENTIFIER" });

        // Guarded before the network, exactly as the other five SDKs are.
        expect(requests).toEqual([]);
      } finally {
        await close();
      }
    }
  );
});


/**
 * The default base URL is a security boundary, not a convenience.
 *
 * A client built without `baseURL` sends the caller's rka_ key to whatever it
 * names. It named https://app.u2secured.io through 0.2.0 -- a domain nobody
 * had registered, so any stranger could have bought it and collected keys
 * from every integration that took the default. Nothing caught it: every
 * other test in this file points the client at a local mock server, so the
 * default was exercised by no test at all.
 *
 * This mocks fetch rather than starting a server, because the whole point is
 * to observe the host the client chooses when nobody tells it one. The
 * literal host is asserted, never the constant against itself.
 */
describe("default base URL", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  it("sends requests to the production host when no baseURL is given", async () => {
    const calls: string[] = [];
    globalThis.fetch = (async (url: unknown) => {
      calls.push(String(url));
      return new Response(JSON.stringify({ valid: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;

    await new U2Auth("rka_test").verifyTOTP("S3CR3T", "123456");

    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatch(/^https:\/\/auth\.u2secured\.com\//);
  });
});

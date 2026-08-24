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

export interface ClientOptions {
  baseURL?: string;
}

export interface VerifyResult {
  valid: boolean;
}

export interface PushResult {
  approval_id: string;
  match_number: number;
  status: string;
  expires_at: string;
}

export interface PushStatus {
  approval_id: string;
  status: string;
  reason?: string;
  resolved_at?: string;
}

/**
 * A short-lived code an end user redeems in the U2 Secured app to bind a user
 * identifier to their account.
 */
export interface PairingCode {
  code: string;
  expires_at: string;
}

export interface PushOptions {
  webhook_url?: string;
  ttl?: number;
  /**
   * Collapses a repeated requestPush into the ORIGINAL approval instead of
   * sending the user a second notification. Travels as the Idempotency-Key
   * HTTP header, never in the body.
   *
   * The key must be stable across the retry, so the SDK cannot invent one for
   * you: derive it from whatever identifies the attempt in your system. A nonce
   * rendered into the login form works well, because a double-click and a
   * back-then-resubmit both carry the same one while a fresh page load mints a
   * new one.
   *
   * This is not Stripe-style idempotency: there is no fixed replay window. The
   * server frees the key once the approval is approved, denied or expired, so a
   * genuine retry after that mints a new request rather than replaying the old
   * one. A key held by a live approval for a DIFFERENT request throws
   * U2AuthError with code "IDEMPOTENCY_KEY_REUSED"; one longer than 255
   * characters throws code "INVALID_IDEMPOTENCY_KEY".
   */
  idempotency_key?: string;
}

/**
 * A coarse, city-level location for an authentication event. Derived from IP
 * geolocation — never a precise coordinate.
 */
export interface Place {
  city: string;
  region: string;
  country: string;
}

/**
 * The link between this app and one end user, identified by the
 * user_identifier passed to createPairingCode / requestPush.
 * last_auth_at and last_auth_outcome are both null when the enrolment has
 * never authenticated — distinct from a zero time or an empty string.
 */
export interface Enrolment {
  id: string;
  user_identifier: string;
  created_at: string;
  last_auth_at: string | null;
  last_auth_outcome: string | null;
}

/**
 * A single authentication attempt recorded against an enrolment. place is a
 * coarse, city-level location — never a coordinate — or null when no
 * location fix was captured for this event.
 */
export interface EnrolmentEvent {
  id: string;
  kind: string;
  outcome: string;
  created_at: string;
  place: Place | null;
  new_country: boolean;
}

/**
 * One page of results from listEnrolments / listEnrolmentEvents.
 * next_cursor is opaque; pass it back verbatim to fetch the next page.
 */
export interface Page<T> {
  items: T[];
  next_cursor: string;
}

/**
 * Optional parameters for listEnrolments. cursor is opaque and bound to the
 * sort/order that minted it — pass it back verbatim on the next call;
 * replaying it under a different sort/order is rejected.
 */
export interface ListEnrolmentsOptions {
  limit?: number;
  cursor?: string;
  sort?: "created_at" | "user_identifier" | "last_auth_at";
  order?: "asc" | "desc";
}

/**
 * Optional parameters for listEnrolmentEvents. cursor is opaque; pass it
 * back verbatim on the next call to page.
 */
export interface ListEnrolmentEventsOptions {
  limit?: number;
  cursor?: string;
}

export class U2AuthError extends Error {
  public readonly statusCode: number;
  public readonly code: string;

  constructor(statusCode: number, code: string, message: string) {
    super(`U2Auth API error ${statusCode} ${code}: ${message}`);
    this.name = "U2AuthError";
    this.statusCode = statusCode;
    this.code = code;
  }
}

const DEFAULT_BASE_URL = "https://app.u2secured.io";

export class U2Auth {
  private readonly apiKey: string;
  private readonly baseURL: string;

  constructor(apiKey: string, opts?: ClientOptions) {
    this.apiKey = apiKey;
    this.baseURL = opts?.baseURL ?? DEFAULT_BASE_URL;
  }

  /**
   * Verify a TOTP code against a shared secret.
   */
  async verifyTOTP(secret: string, code: string): Promise<VerifyResult> {
    return this.post<VerifyResult>("/api/v1/sdk/totp/verify", {
      secret,
      code,
    });
  }

  /**
   * Create a push approval request.
   */
  async requestPush(
    userIdentifier: string,
    context: string,
    opts?: PushOptions
  ): Promise<PushResult> {
    return this.post<PushResult>(
      "/api/v1/sdk/push/request",
      {
        user_identifier: userIdentifier,
        context,
        ...(opts?.webhook_url ? { webhook_url: opts.webhook_url } : {}),
        ...(opts?.ttl ? { ttl: opts.ttl } : {}),
      },
      opts?.idempotency_key
        ? { "Idempotency-Key": opts.idempotency_key }
        : undefined
    );
  }

  /**
   * Get the status of a push approval request.
   */
  async getPushStatus(approvalId: string): Promise<PushStatus> {
    return this.get<PushStatus>(`/api/v1/sdk/push/${approvalId}/status`);
  }

  /**
   * Poll a push approval until it leaves the "pending" state, returning the
   * terminal status. Rejects with an U2AuthError ("WAIT_TIMEOUT") if the
   * approval is still pending after timeoutMs, or ("ABORTED") if the supplied
   * signal is aborted.
   */
  async waitForApproval(
    approvalId: string,
    opts?: { intervalMs?: number; timeoutMs?: number; signal?: AbortSignal }
  ): Promise<PushStatus> {
    const intervalMs = opts?.intervalMs ?? 2000;
    const timeoutMs = opts?.timeoutMs ?? 120000;
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const status = await this.getPushStatus(approvalId);
      if (status.status !== "pending") return status;
      if (opts?.signal?.aborted) {
        throw new U2AuthError(0, "ABORTED", "wait aborted");
      }
      if (Date.now() >= deadline) {
        throw new U2AuthError(
          0,
          "WAIT_TIMEOUT",
          "timed out waiting for approval"
        );
      }
      await new Promise((r) => setTimeout(r, intervalMs));
    }
  }

  /**
   * Mint a pairing code binding userIdentifier — your own opaque id for the
   * user — to whichever account redeems it in the U2 Secured app. Pass the
   * same string to requestPush afterwards.
   */
  async createPairingCode(userIdentifier: string): Promise<PairingCode> {
    return this.post<PairingCode>("/api/v1/sdk/pairing-codes", {
      user_identifier: userIdentifier,
    });
  }

  /**
   * Remove the link between this app and userIdentifier. Rejects with a
   * U2AuthError ("ENROLMENT_NOT_FOUND") if there was no such enrolment.
   */
  async deleteEnrolment(userIdentifier: string): Promise<void> {
    const query = new URLSearchParams({ user_identifier: userIdentifier });
    await this.del(`/api/v1/sdk/enrolments?${query}`);
  }

  /**
   * List the enrolments for this app. The app is resolved from the API
   * key — there is no app_id parameter. limit <= 0 is treated as unset and
   * omitted from the query, same as an empty cursor/sort/order.
   *
   * Rejects with a U2AuthError ("INVALID_LIMIT") if limit is outside
   * 1..100, ("INVALID_SORT") for an unrecognised sort, or
   * ("INVALID_CURSOR") if cursor was minted under a different sort/order.
   */
  async listEnrolments(opts?: ListEnrolmentsOptions): Promise<Page<Enrolment>> {
    const query = new URLSearchParams();
    if (opts?.limit && opts.limit > 0) query.set("limit", String(opts.limit));
    if (opts?.cursor) query.set("cursor", opts.cursor);
    if (opts?.sort) query.set("sort", opts.sort);
    if (opts?.order) query.set("order", opts.order);
    const qs = query.toString();
    return this.get<Page<Enrolment>>(
      `/api/v1/sdk/enrolments${qs ? `?${qs}` : ""}`
    );
  }

  /**
   * List the authentication events recorded for one enrolment. limit <= 0
   * is treated as unset and omitted from the query, same as an empty
   * cursor.
   *
   * Rejects with a U2AuthError ("ENROLMENT_NOT_FOUND") if there is no such
   * enrolment, ("INVALID_LIMIT") if limit is outside 1..100, or
   * ("INVALID_CURSOR") if cursor is malformed or was minted for a
   * different enrolment.
   */
  async listEnrolmentEvents(
    enrolmentId: string,
    opts?: ListEnrolmentEventsOptions
  ): Promise<Page<EnrolmentEvent>> {
    const query = new URLSearchParams();
    if (opts?.limit && opts.limit > 0) query.set("limit", String(opts.limit));
    if (opts?.cursor) query.set("cursor", opts.cursor);
    const qs = query.toString();
    return this.get<Page<EnrolmentEvent>>(
      `/api/v1/sdk/enrolments/${encodeURIComponent(enrolmentId)}/events${
        qs ? `?${qs}` : ""
      }`
    );
  }

  /**
   * extraHeaders is spread last but cannot clobber auth: an empty value is
   * dropped by the caller, and the server distinguishes a present-but-blank
   * Idempotency-Key from an absent one.
   */
  private async post<T>(
    path: string,
    body: unknown,
    extraHeaders?: Record<string, string>
  ): Promise<T> {
    const response = await fetch(`${this.baseURL}${path}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
        ...(extraHeaders ?? {}),
      },
      body: JSON.stringify(body),
    });
    return this.handleResponse<T>(response);
  }

  private async get<T>(path: string): Promise<T> {
    const response = await fetch(`${this.baseURL}${path}`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
      },
    });
    return this.handleResponse<T>(response);
  }

  /**
   * DELETE with no response body. Kept separate from handleResponse, which
   * always parses JSON — a 204 carries an empty body and would fail there.
   */
  private async del(path: string): Promise<void> {
    const response = await fetch(`${this.baseURL}${path}`, {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
      },
    });
    if (response.ok) return;

    const text = await response.text();
    let code = "UNKNOWN";
    let message = text || "Unknown error";
    try {
      const parsed = JSON.parse(text) as {
        error?: { code?: string; message?: string };
      };
      code = parsed?.error?.code ?? code;
      message = parsed?.error?.message ?? message;
    } catch {
      /* non-JSON error body — keep the raw text as the message */
    }
    throw new U2AuthError(response.status, code, message);
  }

  private async handleResponse<T>(response: Response): Promise<T> {
    const text = await response.text();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new Error(`U2Auth: invalid JSON response: ${text}`);
    }

    if (!response.ok) {
      const err = parsed as {
        error?: { code?: string; message?: string };
      };
      throw new U2AuthError(
        response.status,
        err?.error?.code ?? "UNKNOWN",
        err?.error?.message ?? "Unknown error"
      );
    }

    return parsed as T;
  }
}

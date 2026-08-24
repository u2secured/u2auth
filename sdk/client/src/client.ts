import type { ClientConfig, PendingApproval, ApprovalAction, RespondOptions } from "./types.js";
import type { Biometric } from "./native.js";

interface ApiError {
  error: {
    code: string;
    message: string;
  };
}

export class U2AuthClient {
  private deviceId: string | undefined;

  constructor(private cfg: ClientConfig, private biometric?: Biometric) {
    this.deviceId = cfg.deviceId;
  }

  /**
   * Register a new device with the authenticator backend.
   * Stashes the returned device_id for subsequent requests.
   */
  async registerDevice(deviceName: string, fcmToken: string): Promise<{ device_id: string }> {
    const result = await this.request<{ device_id: string }>("/api/v1/app/devices", {
      method: "POST",
      body: JSON.stringify({ device_name: deviceName, fcm_token: fcmToken }),
    });
    this.deviceId = result.device_id;
    return result;
  }

  /**
   * List all pending approvals for this device.
   */
  async listPendingApprovals(): Promise<PendingApproval[]> {
    const result = await this.request<{ items: PendingApproval[] }>("/api/v1/app/approvals", {
      method: "GET",
    });
    return result.items;
  }

  /**
   * Respond to a pending approval (approve or deny).
   * If action is "approved" and a biometric was provided, biometric authentication
   * is required before the request is sent.
   */
  async respond(
    approvalId: string,
    action: ApprovalAction,
    opts: RespondOptions = {}
  ): Promise<{ status: string }> {
    if (action === "approved" && this.biometric) {
      const passed = await this.biometric.authenticate("Approve sign-in");
      if (!passed) {
        throw new Error("biometric_failed");
      }
    }

    return this.request<{ status: string }>(`/api/v1/app/approvals/${approvalId}`, {
      method: "POST",
      body: JSON.stringify({
        action,
        selected_number: opts.selectedNumber,
        location: opts.location,
      }),
    });
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private async authHeaders(): Promise<Record<string, string>> {
    const token = await this.cfg.getAccessToken();
    const headers: Record<string, string> = {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
    };
    if (this.deviceId) {
      headers["X-Device-ID"] = this.deviceId;
    }
    return headers;
  }

  private async request<T>(path: string, init: RequestInit): Promise<T> {
    const headers = await this.authHeaders();
    const response = await fetch(`${this.cfg.baseUrl}${path}`, {
      ...init,
      headers: {
        ...headers,
        ...(init.headers as Record<string, string> | undefined),
      },
    });

    if (!response.ok) {
      let code = `HTTP_${response.status}`;
      try {
        const body = await response.json() as ApiError;
        code = body?.error?.code ?? code;
      } catch {
        // ignore JSON parse errors; use the status-derived code
      }
      throw new Error(code);
    }

    return response.json() as Promise<T>;
  }
}

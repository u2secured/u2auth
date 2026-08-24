export type ApprovalAction = "approved" | "denied";

export interface PendingApproval {
  approval_id: string;
  app_name: string;
  context: string;
  candidates: number[];
  new_device: boolean;
  expires_at: string;
  created_at: string;
}

export interface RespondOptions {
  selectedNumber?: number;
  location?: {
    lat: number;
    lng: number;
    accuracy: number;
  };
}

export interface ClientConfig {
  baseUrl: string;
  getAccessToken: () => string | Promise<string>;
  deviceId?: string;
}

/** Thin typed wrapper around the Flask API (mounted under /api). */

import type { AbeKey } from "./crypto";

export interface Attributes { role: string; department: string; clearance: number }
export interface User { username: string; display_name: string; attributes: Attributes; active: boolean; pub_key_pem?: string | null }

export interface Decision { decision: "Permit" | "Deny"; matched: { policy_id: string; rule_id?: string; effect: string }[] }

export interface FileItem {
  file_id: string;
  filename: string;
  owner: string;
  department: string;
  clearance_required: number;
  policy: string;
  policy_display: string;
  size_bytes: number;
  plain_size?: number | null;
  mime_type?: string | null;
  uploaded_at?: string | null;
  stale: boolean;
  rewrap_count: number;
  signed: boolean;
  recipients: string[];
  decision: Decision | null;
}

export interface Policy {
  policy_id: string;
  title?: string;
  description?: string;
  enabled?: boolean;
  target: { action?: string; resource?: Record<string, unknown> };
  rules: { rule_id?: string; effect: string; condition: Condition }[];
}
export type Condition = { [op: string]: Condition[] | Condition | [string, unknown] };

export interface AuditEntry { seq: number; ts: string; actor: string; action: string; resource: string | null; decision: string; detail: string; prev_hash: string; hash: string }

export interface Health { status: string; version: string; abe_mode: string; metadata_backend: string; storage_backend: string; demo_mode: boolean }

export interface LoginResult { token: string; abe_sk: AbeKey; user: User }

export class ApiError extends Error {
  status: number;
  body: Record<string, unknown>;
  constructor(status: number, body: Record<string, unknown>) {
    super(String(body.error ?? `Request failed (${status})`));
    this.status = status;
    this.body = body;
  }
}

let token: string | null = null;
export const setToken = (t: string | null) => { token = t; };

export async function api<T = unknown>(path: string, opts: { method?: string; body?: unknown } = {}): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method: opts.method ?? (opts.body ? "POST" : "GET"),
    headers: {
      ...(opts.body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const text = await res.text();
  let data: unknown = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = { error: text.slice(0, 200) }; }
  if (!res.ok) throw new ApiError(res.status, data as Record<string, unknown>);
  return data as T;
}

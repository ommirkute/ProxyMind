// Thin client for the ProxyMind REST API. Auth is the HttpOnly cookie set
// by the /auth link; state-changing calls add the X-ProxyMind header the
// server requires.

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (method !== "GET") headers["X-ProxyMind"] = "1";
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(`/api/v1${path}`, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) {
    let msg = text;
    try {
      msg = JSON.parse(text).error ?? text;
    } catch {
      /* plain text error */
    }
    throw new ApiError(res.status, msg || res.statusText);
  }
  return (text ? JSON.parse(text) : null) as T;
}

export const api = {
  get: <T>(path: string) => call<T>("GET", path),
  post: <T>(path: string, body?: unknown) => call<T>("POST", path, body ?? {}),
  patch: <T>(path: string, body: unknown) => call<T>("PATCH", path, body),
  put: <T>(path: string, body: unknown) => call<T>("PUT", path, body),
  del: <T>(path: string) => call<T>("DELETE", path),
  /** A GET whose body is text (not JSON), e.g. a rendered report. */
  text: async (path: string): Promise<string> => {
    const res = await fetch(`/api/v1${path}`, { credentials: "same-origin" });
    const text = await res.text();
    if (!res.ok) throw new ApiError(res.status, text || res.statusText);
    return text;
  },
};

/** Saves text as a file in the browser (for downloads that need a POST). */
export function saveText(name: string, text: string, type = "application/json") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

// ---- types (mirroring the Rust structs) ----------------------------------

export interface Counters {
  exchanges: number;
  last_exchange_id: number;
  pending_approvals: number;
  findings: number;
  audit_records: number;
  intercepted: number;
}

export interface Status {
  version: string;
  project: string;
  you_are: string;
  engagement: string | null;
  in_scope: string[];
  counters: Counters;
}

export interface ExchangeSummary {
  id: number;
  ts_ms: number;
  duration_ms: number | null;
  source: string;
  actor_id: string;
  scheme: string;
  host: string;
  port: number;
  method: string;
  path: string;
  status: number | null;
  req_len: number;
  resp_len: number | null;
  error: string | null;
  identity?: string;
  hypothesis_id?: number;
  highlight?: string;
  comment?: string;
}

export interface ExchangePage {
  /** With a query: how many exchanges were looked at. */
  scanned?: number;
  exchanges: ExchangeSummary[];
  next_before_id?: number;
}

export interface BodyView {
  kind: string;
  content_type?: string;
  size: number;
  outline?: string;
  text?: string;
  truncated: boolean;
  notes?: string[];
}

export interface ExchangeDetail {
  summary: ExchangeSummary;
  request: string;
  response: string | null;
  request_b64?: string;
  response_b64?: string | null;
  /** Full length when the text was cut (`?max=`). */
  request_truncated?: number;
  response_truncated?: number;
  view: {
    url: string;
    request: { start_line: string; body?: BodyView };
    response?: { start_line: string; body?: BodyView };
    possible_prompt_injection?: string[];
  };
}

export interface WsMessage {
  id: number;
  ts_ms: number;
  from: "client" | "server";
  kind: string;
  len: number;
  text?: string;
  hex?: string;
  truncated: boolean;
  compressed: boolean;
  possible_prompt_injection?: string[];
}

export interface WsPage {
  exchange_id: number;
  total: number;
  messages: WsMessage[];
  next_after_id?: number;
}

export interface Approval {
  id: string;
  created_ms: number;
  actor: string;
  action: string;
  tier: string;
  target: string | null;
  summary: string;
  params: string;
  status: string;
  decided_by: string | null;
}

export interface IdentityInfo {
  name: string;
  role: string;
  status: string;
  cookies: string[];
  headers: string[];
  has_health_check: boolean;
  has_login: boolean;
  logged_out: boolean;
  login_steps: number;
  created_by: string;
}

export interface LoginRecording {
  name: string;
  steps: { exchange_id: number; method: string; url: string; extracts: string[]; uses: string[] }[];
  cookies: string[];
  headers: string[];
  health_check: number | null;
  notes: string[];
}

export interface LoggedOutLearned {
  name: string;
  logged_out: { statuses: number[]; location_contains: string; body_contains: string };
  health_contains: string | null;
  exchange_ids: number[];
}

export interface AuthzRow {
  id: number;
  exchange_id: number;
  method: string;
  url: string;
  identity: string;
  verdict: string;
  status: number | null;
  similarity: number | null;
  evidence_id: number | null;
  summary: string;
  checked_by: string;
  checked_ms: number;
}

export interface AuthzCandidate {
  operation: string;
  object: string;
  owner: string;
  exchange_id: number;
  try_as: string[];
  reason: string;
}

export interface Operation {
  key: string;
  method: string;
  origin: string;
  template: string;
  kind: string;
  object_type?: string;
  query_params: string[];
  body_params: string[];
  count: number;
  statuses: Record<string, number>;
  identities: string[];
  authenticated: boolean;
  examples: number[];
}

export interface ModelObject {
  object_type: string;
  id: string;
  owner?: string;
  owner_source?: string;
  accessed_by: string[];
}

export interface CoverageCell {
  operation: string;
  vuln_class: string;
  param?: string;
  status: string;
  hypotheses?: number[];
}

export interface Coverage {
  cells: CoverageCell[];
  totals: Record<string, number>;
  percent_tested: number;
}

export interface Proof {
  proof_id: number;
  oracle: string;
  proven: boolean;
  confidence: string;
  reasons: string[];
  exchange_ids: number[];
  created_ms: number;
  actor: string;
}

export interface Finding {
  id: number;
  title: string;
  vuln_class: string;
  severity: string;
  status: string;
  url: string;
  description: string;
  evidence: number[];
  actor: string;
  created_ms: number;
  proofs?: Proof[];
  issue?: IssueType;
  retest?: Retest | null;
  duplicates?: number;
  /** Model-written explanation and fix (Markdown), if someone asked for one. */
  explanation?: string;
}

export interface IssueType {
  id: string;
  name: string;
  severity: string;
  cwe: number[];
  owasp: string;
  owasp_api?: string;
  aliases: string[];
  background: string;
  impact: string;
  remediation: string;
  references: string[];
}

export interface Retest {
  finding_id: number;
  method: string;
  reproduced: boolean | null;
  summary: string;
  exchange_ids: number[];
  ts_ms: number;
  by: string;
}

export interface ReportTemplate {
  name: string;
  description: string;
  format: "html" | "md";
  body: string;
  builtin: boolean;
}

export const cweUrl = (n: number) => `https://cwe.mitre.org/data/definitions/${n}.html`;

export type ProofResult =
  | { status: "completed"; proof_id: number; proven: boolean; confidence: string; reasons: string[]; exchange_ids: number[] }
  | { status: "pending_approval"; approval_id: string; summary: string; reasons: string[] }
  | { status: "denied"; reasons: string[] };

export type ReplayResult =
  | { status: "sent"; exchange_id: number; elapsed_ms: number; notes?: string[] }
  | { status: "failed"; exchange_id: number; error: string }
  | { status: "pending_approval"; approval_id: string; summary: string; reasons: string[] }
  | { status: "denied"; reasons: string[] };

export interface AuditRecord {
  seq: number;
  ts_ms: number;
  actor: string;
  action: string;
  detail: string;
  decision: string;
}

export const fmtTime = (ms: number) => new Date(ms).toLocaleTimeString();
export const fmtDateTime = (ms: number) => new Date(ms).toLocaleString();
export const fmtBytes = (n: number | null | undefined) =>
  n == null ? "–" : n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
export const originOf = (e: ExchangeSummary) => {
  const def = e.scheme === "https" ? 443 : 80;
  const host = e.host.includes(":") ? `[${e.host}]` : e.host;
  return `${e.scheme}://${host}${e.port === def ? "" : `:${e.port}`}`;
};

export interface BrowserOpened {
  url: string;
  proxy: string;
  pid: number | null;
  profile: string;
}

/** Opens ProxyMind's browser window (through the proxy, trusting its CA). */
export const openBrowser = (url?: string) => api.post<BrowserOpened>("/browser/open", url ? { url } : {});

/** Shows a short message in the corner (the app shell listens). */
export function toast(message: string, kind: "ok" | "bad" = "ok") {
  window.dispatchEvent(new CustomEvent("pm-toast", { detail: { message, kind } }));
}

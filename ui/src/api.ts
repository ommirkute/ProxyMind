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

// ---- types ----------------------------------------------------------------
// Types that match the API contract come from api-types.gen.ts (cargo xtask contracts).

import type { IssueLink, IntegrationView, ExchangeSummary, BodyView, WsPage, IdentityInfo, LoginRecording, LoggedOutLearned, AuthzRow, AuthzCandidate, CoverageCell, Coverage, IssueType, Retest, FindingProve, ProofResult, ReplayResult, AuditRecord, BrowserOpened, ApprovalRow as Approval } from "./api-types.gen";
export type { IssueLink, IntegrationView, ExchangeSummary, BodyView, WsPage, IdentityInfo, LoginRecording, LoggedOutLearned, AuthzRow, AuthzCandidate, CoverageCell, Coverage, IssueType, Retest, FindingProve, ProofResult, ReplayResult, AuditRecord, BrowserOpened, Approval };

// Hand-written types: narrower than the contract or shaped for the UI.


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
  /** This installation does not trust the project file (threat model F-2): its settings are held back. */
  safe_mode?: boolean;
}

export interface ExchangePage {
  /** With a query: how many exchanges were looked at. */
  scanned?: number;
  exchanges: ExchangeSummary[];
  next_before_id?: number;
}

export interface DiffLine { op: "same" | "added" | "removed"; text: string }
export interface LineDiff { lines: DiffLine[]; added: number; removed: number; truncated: boolean }

/** One change rules or the intercept editor made to an exchange's traffic. */
export interface TrafficChange {
  phase: "request" | "response";
  by: "rule" | "intercept" | "hook";
  /** The rule (its comment, or part and match) or a label for the editor. */
  name: string;
  note?: string;
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
  /** Body as people read it: de-chunked, decompressed, markup kept (null when absent or binary). For Pretty/Render. */
  request_body?: string | null;
  response_body?: string | null;
  /** gRPC / Protobuf message as editable text (one `@message` per gRPC message); absent for other traffic. */
  request_protobuf?: string;
  response_protobuf?: string;
  /** When rules or the intercept editor changed the traffic: `request` is what went to the server and `response` is
   *  what the server sent. `request_original` is the request as the browser sent it, `response_delivered` the response
   *  as the browser received it. Each is absent when unchanged. */
  request_original?: string;
  response_delivered?: string;
  request_original_truncated?: number;
  response_delivered_truncated?: number;
  request_original_b64?: string;
  response_delivered_b64?: string;
  /** What changed the traffic; empty when nothing did. */
  changes: TrafficChange[];
  /** One line diff per changed message: request from the browser's to the one sent, response from the server's to the
   *  delivered one. */
  diffs: { phase: "request" | "response"; from_label: string; to_label: string; lines: LineDiff }[];
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
  /** Issues created for it in Jira, GitHub or GitLab. */
  issue_links?: IssueLink[];
  /** Model-written explanation and fix (Markdown), if someone asked for one. */
  explanation?: string;
}

export interface ReportTemplate {
  name: string;
  description: string;
  format: "html" | "md";
  body: string;
  builtin: boolean;
}

export const cweUrl = (n: number) => `https://cwe.mitre.org/data/definitions/${n}.html`;

export const fmtTime = (ms: number) => new Date(ms).toLocaleTimeString();
export const fmtDateTime = (ms: number) => new Date(ms).toLocaleString();
export const fmtBytes = (n: number | null | undefined) =>
  n == null ? "–" : n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
export const originOf = (e: ExchangeSummary) => {
  const def = e.scheme === "https" ? 443 : 80;
  const host = e.host.includes(":") ? `[${e.host}]` : e.host;
  return `${e.scheme}://${host}${e.port === def ? "" : `:${e.port}`}`;
};

/** Opens ProxyMind's browser window (through the proxy, trusting its CA). */
export const openBrowser = (url?: string) => api.post<BrowserOpened>("/browser/open", url ? { url } : {});

/** Shows a short message in the corner (the app shell listens). */
export function toast(message: string, kind: "ok" | "bad" = "ok") {
  window.dispatchEvent(new CustomEvent("pm-toast", { detail: { message, kind } }));
}

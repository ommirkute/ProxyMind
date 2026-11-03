/**
 * TypeScript client for the ProxyMind REST API. No dependencies: it uses
 * the platform's `fetch` (Node 18+, Deno, Bun, browsers).
 *
 *     import { Client } from "@proxymind/client";
 *     const pm = await Client.connect();            // http://127.0.0.1:7777, token from PROXYMIND_TOKEN or ~/.proxymind/api-token
 *     for (const ex of await pm.history({ path: "/api/orders" })) console.log(ex.id, ex.method, ex.path, ex.status);
 *
 * The API acts as the human who started `proxymind ui`: what this client
 * does goes through the same policy gate and audit log. For an autonomous
 * agent, use the MCP server with an `agent:` actor instead.
 *
 * Licensed under the Apache License 2.0 (unlike the AGPL core).
 */

export const VERSION = "0.1.0";

type Json = Record<string, unknown>;
type Query = Record<string, string | number | boolean | undefined | null>;

/** The API refused a request (bad input, not found, forbidden…). */
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(`${status}: ${message}`);
    this.name = "ApiError";
  }
}

/** The policy gate refused the action (out of scope, tier not allowed…). */
export class Denied extends ApiError {
  constructor(public readonly reasons: string[]) {
    super(403, reasons.join("; ") || "denied");
    this.name = "Denied";
  }
}

/** The action needs a human's approval first (see `Client.waitForApproval`). */
export class PendingApproval extends Error {
  constructor(
    public readonly approvalId: string,
    public readonly summary: string,
  ) {
    super(`needs approval ${approvalId}: ${summary}`);
    this.name = "PendingApproval";
  }
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

export interface ClientOptions {
  baseUrl?: string;
  token?: string;
  /** Per-request timeout in milliseconds (default 120 000). */
  timeoutMs?: number;
}

/** Reads the token from PROXYMIND_TOKEN or `<PROXYMIND_HOME or ~/.proxymind>/api-token` (Node only). */
export async function defaultToken(): Promise<string | undefined> {
  const env = (globalThis as { process?: { env: Record<string, string | undefined> } }).process?.env;
  if (env?.PROXYMIND_TOKEN) return env.PROXYMIND_TOKEN.trim();
  if (!env) return undefined;
  try {
    const fs = await import("node:fs/promises");
    const os = await import("node:os");
    const path = await import("node:path");
    const home = env.PROXYMIND_HOME ?? path.join(os.homedir(), ".proxymind");
    return (await fs.readFile(path.join(home, "api-token"), "utf8")).trim();
  } catch {
    return undefined;
  }
}

const strip = <T extends Json>(o: T): Json => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined));

export class Client {
  readonly baseUrl: string;
  private readonly token: string;
  private readonly timeoutMs: number;

  constructor(opts: ClientOptions & { token: string }) {
    this.baseUrl = (opts.baseUrl ?? "http://127.0.0.1:7777").replace(/\/+$/, "");
    this.token = opts.token;
    this.timeoutMs = opts.timeoutMs ?? 120_000;
  }

  /** A client with the token found by `defaultToken()` unless one is given. */
  static async connect(opts: ClientOptions = {}): Promise<Client> {
    const token = opts.token ?? (await defaultToken());
    if (!token) throw new Error("no API token: pass token, set PROXYMIND_TOKEN, or run `proxymind ui` once");
    return new Client({ ...opts, token });
  }

  // ---------------------------------------------------------------- plumbing

  async request<T = unknown>(method: string, path: string, body?: unknown, query?: Query, raw = false): Promise<T> {
    let url = `${this.baseUrl}/api/v1${path}`;
    if (query) {
      const q = new URLSearchParams();
      for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== null) q.set(k, String(v));
      if ([...q].length) url += `?${q}`;
    }
    const headers: Record<string, string> = { Authorization: `Bearer ${this.token}`, Accept: "application/json" };
    if (method !== "GET") headers["X-ProxyMind"] = "1";
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const res = await fetch(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const text = await res.text();
    if (!res.ok) {
      let msg = text;
      try {
        msg = (JSON.parse(text) as { error?: string }).error ?? text;
      } catch {
        /* plain text */
      }
      throw new ApiError(res.status, msg || res.statusText);
    }
    if (raw) return text as T;
    return (text ? JSON.parse(text) : null) as T;
  }

  private get<T>(path: string, query?: Query): Promise<T> {
    return this.request<T>("GET", path, undefined, query);
  }

  private post<T>(path: string, body: unknown = {}): Promise<T> {
    return this.request<T>("POST", path, body);
  }

  /** Throws PendingApproval or Denied for results that didn't run. */
  static check<T>(result: T): T {
    const r = result as { status?: string; approval_id?: string; summary?: string; reasons?: string[] } | null;
    if (r?.status === "pending_approval") throw new PendingApproval(r.approval_id ?? "", r.summary ?? "");
    if (r?.status === "denied") throw new Denied(r.reasons ?? []);
    return result;
  }

  private async act<T = Json>(path: string, body: Json): Promise<T> {
    return Client.check(await this.post<T>(path, strip(body)));
  }

  // ----------------------------------------------------------------- reading

  status(): Promise<Json> {
    return this.get("/status");
  }

  /** Recorded exchanges, newest first. Filters: host, path, method, status, source, limit, before_id… */
  async history(filters: Query = {}): Promise<ExchangeSummary[]> {
    return (await this.get<{ exchanges: ExchangeSummary[] }>("/exchanges", filters)).exchanges;
  }

  exchange(id: number): Promise<Json> {
    return this.get(`/exchanges/${id}`);
  }

  /** Sets (or clears) a history row's highlight and comment. */
  annotate(exchange_id: number, opts: { highlight?: string; comment?: string } = {}): Promise<ExchangeSummary> {
    return this.request("PUT", `/exchanges/${exchange_id}/annotation`, strip(opts));
  }

  /** WebSocket messages across connections, newest first. */
  async wsHistory(filters: Query = {}): Promise<Json[]> {
    return (await this.get<{ messages: Json[] }>("/ws/history", filters)).messages;
  }

  model(filters: Query = {}): Promise<Json> {
    return this.get("/model", filters);
  }

  coverage(all = false): Promise<Json> {
    return this.get("/coverage", { all });
  }

  /** Passive scan of recorded traffic (sends nothing). */
  issues(filters: Query = {}): Promise<Json[]> {
    return this.get("/scan/issues", filters);
  }

  findings(): Promise<Json[]> {
    return this.get("/findings");
  }

  finding(id: number): Promise<Json> {
    return this.get(`/findings/${id}`);
  }

  proof(id: number): Promise<Json> {
    return this.get(`/proofs/${id}`);
  }

  /** Approvals, all by default; status: pending, approved, denied, used. */
  approvals(status = "all"): Promise<Json[]> {
    return this.get("/approvals", { status });
  }

  auditVerify(): Promise<{ intact: boolean; records: number }> {
    return this.get("/audit/verify");
  }

  /** The report as text: md, json, sarif or html. */
  report(format: "md" | "json" | "sarif" | "html" = "md"): Promise<string> {
    return this.request<string>("GET", "/report", undefined, { format }, true);
  }

  /** Text (or a regex) in recorded requests and responses, bodies decoded. */
  search(query: string, opts: { regex?: boolean; case_sensitive?: boolean; part?: "request" | "response" | "both" } & Query = {}): Promise<Json> {
    return this.post("/search", strip({ query, ...opts }));
  }

  /** Recorded traffic as a tree per origin. */
  siteMap(host?: string): Promise<Json[]> {
    return this.get("/sitemap", { host });
  }

  /** The rules of engagement in force: { text, summary }. */
  roe(): Promise<{ text: string | null; summary: Json }> {
    return this.get("/roe");
  }

  checkRoe(text: string): Promise<Json> {
    return this.post("/roe/check", { text });
  }

  /** Replaces the rules of engagement (as the human who started the UI); audited. */
  setRoe(text: string): Promise<{ text: string | null; summary: Json }> {
    return this.request("PUT", "/roe", { text });
  }

  /** Live counters (exchanges, findings, approvals…) as they change. */
  async *events(signal?: AbortSignal): AsyncGenerator<Json> {
    const res = await fetch(`${this.baseUrl}/api/v1/events`, { headers: { Authorization: `Bearer ${this.token}` }, signal });
    if (!res.ok || !res.body) throw new ApiError(res.status, "events unavailable");
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return;
      buf += decoder.decode(value, { stream: true });
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (line.startsWith("data:")) yield JSON.parse(line.slice(5).trim()) as Json;
      }
    }
  }

  // ------------------------------------------------------------------ acting

  /** Sends a request through the policy gate. Throws PendingApproval if a human must approve. */
  replay(opts: { raw?: string; url?: string; exchange_id?: number; identity?: string; approval_id?: string } & Json): Promise<Json> {
    return this.act("/replay", opts);
  }

  /** Fuzz positions marked §like this§. payload_sets: [{ list: [...] }, { numbers: "1-10" }, { builtin: "sqli" }]. */
  fuzzer(raw: string, payload_sets: Json[], opts: Json = {}): Promise<Json> {
    return this.act("/fuzzer", { raw, payload_sets, ...opts });
  }

  crawl(url: string, opts: Json = {}): Promise<Json> {
    return this.act("/crawl", { url, ...opts });
  }

  /** Looks for hidden files and folders under url (GET only; built-in list unless words are given). */
  discover(url: string, opts: { words?: string[]; extensions?: string[] } & Json = {}): Promise<Json> {
    return this.act("/discover", { url, ...opts });
  }

  /** Installed plugins (per user) and what the plugin sandbox does here. */
  plugins(): Promise<Json> {
    return this.get("/plugins");
  }

  /** Runs an active-check plugin on a recorded exchange; its requests go through the policy gate. */
  pluginCheck(plugin: string, exchange_id: number, opts: { identity?: string; approval_id?: string } = {}): Promise<Json> {
    return this.act("/plugins/check", { plugin, exchange_id, ...opts });
  }

  scanActive(exchange_id: number, opts: { checks?: string[] } & Json = {}): Promise<Json> {
    return this.act("/scan/active", { exchange_id, ...opts });
  }

  openapiImport(opts: { spec?: string; exchange_id?: number } & Json): Promise<Json> {
    return this.act("/openapi/import", opts);
  }

  /** A GraphQL schema (introspection JSON, a recorded response, or fetch: true) as operations. */
  graphqlImport(opts: { url?: string; schema?: string; exchange_id?: number; fetch?: boolean } & Json): Promise<Json> {
    return this.act("/graphql/import", opts);
  }

  authzCheck(exchange_id: number, identities: string[], include_anonymous = true): Promise<Json> {
    return this.post("/authz/check", { exchange_id, identities, include_anonymous });
  }

  createFinding(f: { title: string; vuln_class: string; severity: string; evidence: number[]; description?: string; url?: string }): Promise<Json> {
    return this.post("/findings", strip(f));
  }

  /** Runs a proof: differential_authz, timing, oast or reflection. */
  prove(oracle: string, inputs: Json = {}): Promise<Json> {
    return this.act("/proofs", { oracle, ...inputs });
  }

  /** Encode/decode locally; no ops means a smart decode. Returns the steps. */
  async decode(text: string, ops: string[] = []): Promise<{ op: string; output: string }[]> {
    return (await this.post<{ steps: { op: string; output: string }[] }>("/tools/decode", { input: text, ops })).steps;
  }

  compare(a: number, b: number): Promise<Json> {
    return this.post("/tools/compare", { a, b });
  }

  tokenAnalyzer(exchange_id: number, locator: string, samples = 100, opts: Json = {}): Promise<Json> {
    return this.act("/tools/token-analyzer", { exchange_id, locator, samples, ...opts });
  }

  /** Adds a HAR file's exchanges to history; sends nothing. */
  importHar(har: string): Promise<{ imported: number; exchange_ids: number[]; skipped: string[] }> {
    return this.post("/import/har", { har });
  }

  /** History as a HAR document: exactly ids, or everything matching history filters. */
  exportHar(opts: { ids?: number[] } & Query = {}): Promise<Json> {
    return this.post("/export/har", strip(opts));
  }

  /** A curl command that sends the same request as a recorded exchange. */
  async curl(exchange_id: number): Promise<string> {
    return (await this.get<{ command: string }>(`/exchanges/${exchange_id}/curl`)).command;
  }

  /** Reads a curl command into { url, method, raw, warnings }, ready for replay(); sends nothing. */
  curlParse(command: string): Promise<{ url: string; method: string; raw: string; warnings: string[] }> {
    return this.post("/tools/curl", { command });
  }

  approve(id: string): Promise<Json> {
    return this.post(`/approvals/${id}/approve`);
  }

  deny(id: string): Promise<Json> {
    return this.post(`/approvals/${id}/deny`);
  }

  /** Waits until a human approves or denies; resolves "approved" or "denied". */
  async waitForApproval(id: string, timeoutMs = 600_000, pollMs = 2000): Promise<"approved" | "denied"> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const a = (await this.approvals()).find((x) => x.id === id);
      if (a && ["approved", "denied", "used"].includes(String(a.status))) return a.status === "denied" ? "denied" : "approved";
      await new Promise((r) => setTimeout(r, pollMs));
    }
    throw new Error(`approval ${id} still pending after ${timeoutMs} ms`);
  }
}

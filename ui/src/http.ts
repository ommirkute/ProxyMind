// Reading and editing raw HTTP requests as text (Repeater, Intruder).
// Lines may end in \n or \r\n; edits keep the request's own line endings.

export interface Param {
  name: string;
  value: string;
}

export interface ParsedRequest {
  method: string;
  target: string;
  version: string;
  headers: Param[];
  body: string;
  eol: string;
}

/** The decoded form of a URL-encoded value (as is when it isn't valid). */
export function decodeComponent(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    return s;
  }
}

export function parseRequest(raw: string): ParsedRequest {
  const eol = raw.includes("\r\n") ? "\r\n" : "\n";
  const split = raw.indexOf(eol + eol);
  const head = split >= 0 ? raw.slice(0, split) : raw;
  const body = split >= 0 ? raw.slice(split + eol.length * 2) : "";
  const [first = "", ...lines] = head.split(eol);
  const parts = first.split(" ");
  const method = parts[0] ?? "";
  const version = parts.length > 2 ? parts[parts.length - 1] : "HTTP/1.1";
  const target = parts.length > 2 ? parts.slice(1, -1).join(" ") : (parts[1] ?? "/");
  const headers = lines
    .filter((l) => l.length > 0)
    .map((l) => {
      const i = l.indexOf(":");
      return i < 0 ? { name: l, value: "" } : { name: l.slice(0, i), value: l.slice(i + 1).trimStart() };
    });
  return { method, target, version, headers, body, eol };
}

export function buildRequest(p: ParsedRequest): string {
  const head = [`${p.method} ${p.target} ${p.version}`, ...p.headers.map((h) => `${h.name}: ${h.value}`)].join(p.eol);
  return head + p.eol + p.eol + p.body;
}

const pairs = (s: string): Param[] =>
  s
    .split("&")
    .filter(Boolean)
    .map((kv) => {
      const i = kv.indexOf("=");
      return i < 0 ? { name: kv, value: "" } : { name: kv.slice(0, i), value: kv.slice(i + 1) };
    });

const joinPairs = (ps: Param[]) => ps.map((p) => `${p.name}=${p.value}`).join("&");

export const header = (p: ParsedRequest, name: string) =>
  p.headers.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value;

/** Query parameters, raw (still URL-encoded). */
export const queryParams = (p: ParsedRequest): Param[] => {
  const i = p.target.indexOf("?");
  return i < 0 ? [] : pairs(p.target.slice(i + 1));
};

export const isForm = (p: ParsedRequest) => (header(p, "content-type") ?? "").toLowerCase().includes("x-www-form-urlencoded");

export const formParams = (p: ParsedRequest): Param[] => (isForm(p) ? pairs(p.body.trim()) : []);

/** Top-level JSON body fields (strings, numbers and booleans). */
export function jsonParams(p: ParsedRequest): Param[] {
  if (!(header(p, "content-type") ?? "").toLowerCase().includes("json")) return [];
  try {
    const v = JSON.parse(p.body);
    if (v && typeof v === "object" && !Array.isArray(v)) {
      return Object.entries(v)
        .filter(([, x]) => ["string", "number", "boolean"].includes(typeof x))
        .map(([name, x]) => ({ name, value: String(x) }));
    }
  } catch {
    /* not JSON */
  }
  return [];
}

export const cookies = (p: ParsedRequest): Param[] =>
  (header(p, "cookie") ?? "")
    .split(";")
    .map((c) => c.trim())
    .filter(Boolean)
    .map((c) => {
      const i = c.indexOf("=");
      return i < 0 ? { name: c, value: "" } : { name: c.slice(0, i), value: c.slice(i + 1) };
    });

export function setQueryParam(raw: string, index: number, value: string): string {
  const p = parseRequest(raw);
  const i = p.target.indexOf("?");
  if (i < 0) return raw;
  const ps = pairs(p.target.slice(i + 1));
  if (!ps[index]) return raw;
  ps[index] = { ...ps[index], value };
  return buildRequest({ ...p, target: `${p.target.slice(0, i)}?${joinPairs(ps)}` });
}

export function setFormParam(raw: string, index: number, value: string): string {
  const p = parseRequest(raw);
  const ps = pairs(p.body.trim());
  if (!ps[index]) return raw;
  ps[index] = { ...ps[index], value };
  return buildRequest({ ...p, body: joinPairs(ps) });
}

export function setJsonParam(raw: string, name: string, value: string): string {
  const p = parseRequest(raw);
  try {
    const v = JSON.parse(p.body);
    const old = v[name];
    v[name] = typeof old === "number" && value.trim() !== "" && !isNaN(Number(value)) ? Number(value)
      : typeof old === "boolean" && (value === "true" || value === "false") ? value === "true"
      : value;
    return buildRequest({ ...p, body: JSON.stringify(v) });
  } catch {
    return raw;
  }
}

export function setCookie(raw: string, name: string, value: string): string {
  const p = parseRequest(raw);
  const cs = cookies(p).map((c) => (c.name === name ? { ...c, value } : c));
  return buildRequest({
    ...p,
    headers: p.headers.map((h) => (h.name.toLowerCase() === "cookie" ? { ...h, value: cs.map((c) => `${c.name}=${c.value}`).join("; ") } : h)),
  });
}

export function setHeader(raw: string, index: number, value: string): string {
  const p = parseRequest(raw);
  if (!p.headers[index]) return raw;
  const headers = p.headers.slice();
  headers[index] = { ...headers[index], value };
  return buildRequest({ ...p, headers });
}

/** The status code and Location of a raw response. */
export function redirectOf(resp: string | null | undefined): string | null {
  if (!resp) return null;
  const m = resp.match(/^HTTP\/[\d.]+ (\d{3})/);
  if (!m || !["301", "302", "303", "307", "308"].includes(m[1])) return null;
  const loc = resp.split(/\r?\n\r?\n/)[0].match(/^location:\s*(.+)$/im);
  return loc ? loc[1].trim() : null;
}

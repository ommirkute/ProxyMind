// Alt-Svc (RFC 7838) advertisements of HTTP/3, read from a recorded response. The same rules as
// `pm_http::h3text::alt_svc_h3` (Rust); the vectors in tests/altsvc.test.mjs mirror its tests.

export interface AltSvc {
  protocol: string;
  /** `:443` (same host) or `alt.example:8443`. */
  authority: string;
  maxAge?: number;
}

/** Splits at `sep` outside double quotes. */
function splitOutsideQuotes(s: string, sep: string): string[] {
  const parts: string[] = [];
  let start = 0;
  let quoted = false;
  let escaped = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (escaped) escaped = false;
    else if (c === "\\" && quoted) escaped = true;
    else if (c === '"') quoted = !quoted;
    else if (c === sep && !quoted) {
      parts.push(s.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(s.slice(start));
  return parts;
}

const isH3 = (id: string) => /^h3(-.*)?$/i.test(id);

/** The alternatives in one Alt-Svc header value (`clear` and entries that do not parse give nothing). */
export function parseAltSvc(value: string): AltSvc[] {
  const out: AltSvc[] = [];
  for (const item of splitOutsideQuotes(value, ",")) {
    const [first, ...params] = splitOutsideQuotes(item, ";");
    const eq = first.indexOf("=");
    if (eq < 0) continue;
    const protocol = first.slice(0, eq).trim();
    const authority = first.slice(eq + 1).trim().replace(/^"+|"+$/g, "");
    if (!protocol || !authority) continue;
    let maxAge: number | undefined;
    for (const p of params) {
      const [k, v] = p.split(/=(.*)/s);
      if (k?.trim().toLowerCase() === "ma" && v !== undefined && /^\d+$/.test(v.trim().replace(/^"|"$/g, ""))) {
        maxAge = Number(v.trim().replace(/^"|"$/g, ""));
        break;
      }
    }
    out.push({ protocol, authority, maxAge });
  }
  return out;
}

/** The HTTP/3 alternatives a response (HTTP/1.x or HTTP/2 or HTTP/3 text) advertises; empty when it offers none. */
export function altSvcH3(response: string | null | undefined): AltSvc[] {
  if (!response) return [];
  const headEnd = response.search(/\r?\n\r?\n/);
  const head = headEnd < 0 ? response : response.slice(0, headEnd);
  const found: AltSvc[] = [];
  for (const line of head.split(/\r?\n/).slice(1)) {
    const m = line.match(/^alt-svc:(.*)$/i);
    if (m) found.push(...parseAltSvc(m[1]).filter((a) => isH3(a.protocol)));
  }
  return found;
}

/**
 * Where an HTTP/3 alternative lives, as a `scheme://host:port` target. `:443` keeps the host; `host:port` moves to
 * that host. `https` always (QUIC is TLS).
 */
export function altTarget(url: string, alt: AltSvc): string {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return url;
  }
  const m = alt.authority.match(/^(\[[^\]]+\]|[^:]*):(\d+)$/);
  if (!m) return url;
  const host = m[1] || u.hostname;
  return `https://${host}:${m[2]}`;
}

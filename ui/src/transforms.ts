// Pure text transforms for the editors' "Transform" menu. No DOM, no React: Node can run this file directly (see
// tests/transforms.test.mjs), so keep it free of imports and of TypeScript-only runtime constructs (enums etc.).
//
// Every operation works on the selected text, treated as UTF-8 where bytes are involved. Decoders fail with a message
// instead of guessing: the menu shows it in the preview and leaves the text alone.

export type TransformResult = { ok: true; value: string } | { ok: false; error: string };

export interface TransformOp {
  id: string;
  label: string;
  group: string;
  /** False for hashes: the digest cannot be turned back into the selection (only Undo restores it). */
  reversible: boolean;
}

export const TRANSFORMS: TransformOp[] = [
  { id: "url_encode", label: "URL encode (component)", group: "URL", reversible: true },
  { id: "url_decode", label: "URL decode (component)", group: "URL", reversible: true },
  { id: "url_encode_full", label: "URL encode (full URL, keeps : / ? # & =)", group: "URL", reversible: true },
  { id: "url_decode_full", label: "URL decode (full URL, keeps %2F %3F %23 …)", group: "URL", reversible: true },
  { id: "base64_encode", label: "Base64 encode", group: "Base64", reversible: true },
  { id: "base64_decode", label: "Base64 decode", group: "Base64", reversible: true },
  { id: "base64url_encode", label: "Base64 encode (URL-safe, no padding)", group: "Base64", reversible: true },
  { id: "base64url_decode", label: "Base64 decode (URL-safe)", group: "Base64", reversible: true },
  { id: "html_encode", label: "HTML entity encode", group: "HTML", reversible: true },
  { id: "html_decode", label: "HTML entity decode", group: "HTML", reversible: true },
  { id: "hex_encode", label: "Hex encode (UTF-8 bytes)", group: "Hex", reversible: true },
  { id: "hex_decode", label: "Hex decode", group: "Hex", reversible: true },
  { id: "unicode_encode", label: "Unicode escape \\uXXXX (non-ASCII only)", group: "Unicode", reversible: true },
  { id: "unicode_encode_all", label: "Unicode escape \\uXXXX (every character)", group: "Unicode", reversible: true },
  { id: "unicode_decode", label: "Unicode unescape (\\uXXXX, \\u{X})", group: "Unicode", reversible: true },
  { id: "json_escape", label: "JSON string escape", group: "JSON", reversible: true },
  { id: "json_unescape", label: "JSON string unescape", group: "JSON", reversible: true },
  { id: "md5", label: "MD5 (hex digest)", group: "Hash", reversible: false },
  { id: "sha1", label: "SHA-1 (hex digest)", group: "Hash", reversible: false },
  { id: "sha256", label: "SHA-256 (hex digest)", group: "Hash", reversible: false },
];

const fail = (error: string): TransformResult => ({ ok: false, error });
const ok = (value: string): TransformResult => ({ ok: true, value });

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const fromUtf8 = (b: Uint8Array): string => new TextDecoder("utf-8", { fatal: true }).decode(b);

const toHex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

// ---------------------------------------------------------------- URL

export function urlEncode(s: string, full = false): TransformResult {
  try {
    return ok(full ? encodeURI(s) : encodeURIComponent(s));
  } catch {
    return fail("The text has an unpaired surrogate and cannot be encoded.");
  }
}

export function urlDecode(s: string, full = false): TransformResult {
  try {
    return ok(full ? decodeURI(s) : decodeURIComponent(s));
  } catch {
    return fail("Invalid percent-encoding (a % is not followed by two hex digits, or the bytes are not valid UTF-8).");
  }
}

// ---------------------------------------------------------------- Base64

export function base64Encode(s: string, urlSafe = false): TransformResult {
  const bytes = utf8(s);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  const std = btoa(bin);
  return ok(urlSafe ? std.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") : std);
}

/** Accepts both alphabets, with or without padding, ignoring whitespace. */
export function base64Decode(s: string): TransformResult {
  const clean = s.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (clean === "") return ok("");
  if (!/^[A-Za-z0-9+/]+$/.test(clean)) return fail("Not Base64: it has characters outside A-Z a-z 0-9 + / - _ =.");
  if (clean.length % 4 === 1) return fail("Not Base64: the length is impossible (one character too many or too few).");
  let bin: string;
  try {
    bin = atob(clean + "=".repeat((4 - (clean.length % 4)) % 4));
  } catch {
    return fail("Not valid Base64.");
  }
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  try {
    return ok(fromUtf8(bytes));
  } catch {
    return fail("The Base64 decodes to bytes that are not valid UTF-8 text (binary data), so it is left alone.");
  }
}

// ---------------------------------------------------------------- HTML

export function htmlEncode(s: string): TransformResult {
  const map: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  return ok(s.replace(/[&<>"']/g, (c) => map[c]));
}

const NAMED: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", copy: "©", reg: "®",
  hellip: "…", ndash: "–", mdash: "—", laquo: "«", raquo: "»",
};

/** Decodes numeric references and a short list of common named ones; other named entities stay as written. */
export function htmlDecode(s: string): TransformResult {
  let bad: string | null = null;
  const re = /&(?:#([0-9]{1,8})|#[xX]([0-9a-fA-F]{1,8})|([A-Za-z][A-Za-z0-9]{1,9}));/g;
  const value = s.replace(re, (m, dec: string | undefined, hex: string | undefined, name: string | undefined) => {
    if (name) return Object.prototype.hasOwnProperty.call(NAMED, name) ? NAMED[name] : m;
    const cp = dec ? parseInt(dec, 10) : parseInt(hex ?? "", 16);
    if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
      bad ??= m;
      return m;
    }
    return String.fromCodePoint(cp);
  });
  return bad ? fail(`${bad} is not a valid character reference.`) : ok(value);
}

// ---------------------------------------------------------------- hex

export const hexEncode = (s: string): TransformResult => ok(toHex(utf8(s)));

/** Accepts plain hex, with spaces, colons, commas or dashes between bytes, and 0x or \x prefixes. */
export function hexDecode(s: string): TransformResult {
  const clean = s.replace(/0x|\\x/gi, "").replace(/[\s:,-]+/g, "");
  if (clean === "") return ok("");
  if (!/^[0-9a-fA-F]+$/.test(clean)) return fail("Not hex: it has characters other than 0-9 a-f.");
  if (clean.length % 2 === 1) return fail("Not whole bytes: an odd number of hex digits.");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  try {
    return ok(fromUtf8(bytes));
  } catch {
    return fail("The hex decodes to bytes that are not valid UTF-8 text (binary data), so it is left alone.");
  }
}

// ---------------------------------------------------------------- Unicode

/** `\uXXXX` per UTF-16 code unit, so characters outside the BMP become a surrogate pair like JavaScript writes them. */
export function unicodeEscape(s: string, all = false): TransformResult {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const u = s.charCodeAt(i);
    out += all || u > 0x7f ? "\\u" + u.toString(16).padStart(4, "0") : s[i];
  }
  return ok(out);
}

export function unicodeUnescape(s: string): TransformResult {
  const malformed = /\\u(?!\{[0-9a-fA-F]{1,6}\}|[0-9a-fA-F]{4})/.exec(s);
  if (malformed) return fail(`Bad escape at position ${malformed.index}: \\u needs four hex digits or {hex}.`);
  let tooBig = false;
  const value = s.replace(/\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})/g, (m, braced?: string, four?: string) => {
    const cp = parseInt(braced ?? four ?? "", 16);
    if (cp > 0x10ffff) {
      tooBig = true;
      return m;
    }
    // A lone surrogate half is fine: the matching second half is joined by the string itself.
    return String.fromCodePoint(cp);
  });
  return tooBig ? fail("A code point is above U+10FFFF.") : ok(value);
}

// ---------------------------------------------------------------- JSON

export const jsonEscape = (s: string): TransformResult => ok(JSON.stringify(s).slice(1, -1));

export function jsonUnescape(s: string): TransformResult {
  try {
    const v: unknown = JSON.parse(`"${s}"`);
    return ok(v as string);
  } catch {
    return fail("Not a valid JSON string body: it has a raw quote, a raw line break or tab, or a bad backslash escape.");
  }
}

// ---------------------------------------------------------------- hashes

const MD5_SHIFT = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
const MD5_K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);

/** MD5 of raw bytes as lowercase hex (RFC 1321). Only for matching values that use it, never for security. */
export function md5(data: Uint8Array): string {
  const blocks = ((data.length + 8) >> 6) + 1;
  const words = new Uint32Array(blocks * 16);
  for (let i = 0; i < data.length; i++) words[i >> 2] |= data[i] << ((i & 3) * 8);
  words[data.length >> 2] |= 0x80 << ((data.length & 3) * 8);
  words[blocks * 16 - 2] = (data.length * 8) >>> 0;
  words[blocks * 16 - 1] = Math.floor(data.length / 2 ** 29);

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;
  for (let blk = 0; blk < blocks; blk++) {
    let a = a0;
    let b = b0;
    let c = c0;
    let d = d0;
    for (let i = 0; i < 64; i++) {
      let f: number;
      let g: number;
      if (i < 16) {
        f = (b & c) | (~b & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | (~d & c);
        g = (5 * i + 1) & 15;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) & 15;
      } else {
        f = c ^ (b | ~d);
        g = (7 * i) & 15;
      }
      const sum = (a + f + MD5_K[i] + words[blk * 16 + g]) >>> 0;
      const s = MD5_SHIFT[(i >> 4) * 4 + (i & 3)];
      a = d;
      d = c;
      c = b;
      b = (b + ((sum << s) | (sum >>> (32 - s)))) >>> 0;
    }
    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }
  const out = new Uint8Array(16);
  [a0, b0, c0, d0].forEach((w, i) => {
    for (let j = 0; j < 4; j++) out[i * 4 + j] = (w >>> (j * 8)) & 0xff;
  });
  return toHex(out);
}

export async function shaDigest(algorithm: "SHA-1" | "SHA-256", s: string): Promise<TransformResult> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) return fail("SHA needs a secure context (open the UI over localhost or HTTPS).");
  return ok(toHex(new Uint8Array(await subtle.digest(algorithm, utf8(s)))));
}

// ---------------------------------------------------------------- dispatch

/** Runs one operation by id (see TRANSFORMS). Never throws: failures come back as `{ ok: false, error }`. */
export async function transform(id: string, input: string): Promise<TransformResult> {
  try {
    switch (id) {
      case "url_encode": return urlEncode(input);
      case "url_encode_full": return urlEncode(input, true);
      case "url_decode": return urlDecode(input);
      case "url_decode_full": return urlDecode(input, true);
      case "base64_encode": return base64Encode(input);
      case "base64url_encode": return base64Encode(input, true);
      case "base64_decode":
      case "base64url_decode": return base64Decode(input);
      case "html_encode": return htmlEncode(input);
      case "html_decode": return htmlDecode(input);
      case "hex_encode": return hexEncode(input);
      case "hex_decode": return hexDecode(input);
      case "unicode_encode": return unicodeEscape(input);
      case "unicode_encode_all": return unicodeEscape(input, true);
      case "unicode_decode": return unicodeUnescape(input);
      case "json_escape": return jsonEscape(input);
      case "json_unescape": return jsonUnescape(input);
      case "md5": return ok(md5(utf8(input)));
      case "sha1": return await shaDigest("SHA-1", input);
      case "sha256": return await shaDigest("SHA-256", input);
      default: return fail(`Unknown operation ${id}.`);
    }
  } catch (e) {
    return fail(e instanceof Error ? e.message : String(e));
  }
}

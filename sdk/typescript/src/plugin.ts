/**
 * Helpers for writing ProxyMind traffic hooks (plugin API 2, ADR-0020) in TypeScript. No dependencies; Node 18+.
 *
 * A hook is a long-lived process: ProxyMind writes one JSON line per message in flight to stdin and expects one
 * JSON line back on stdout.
 *
 *     import { serve, replace, addHeader } from "@proxymind/client/plugin";
 *
 *     serve({
 *       request: (call) => replace(addHeader(call.raw, "X-Sig", "abc"), "signed"), // or undefined (pass), or DROP
 *     });
 *
 * A handler returns `undefined` (pass), `replace(raw, note)` (forwarded exactly as given: no Content-Length
 * fix-ups) or `DROP` (requests only). A thrown error ends the process: ProxyMind counts a failure, forwards the
 * original and, after repeated failures, pauses the hook. Stdout is for answers only.
 */

import { createInterface } from "node:readline";

/** One message ProxyMind hands to a hook. `raw` is the message exactly as it is on the wire. */
export interface HookCall {
  id: number;
  phase: "request" | "response";
  method: string;
  url: string;
  scheme: string;
  host: string;
  port: number;
  path: string;
  /** Responses only. */
  status?: number;
  raw: Buffer;
}

export interface Replace {
  action: "replace";
  raw: Buffer;
  note: string;
}

export type HookResult = undefined | null | "pass" | "drop" | Replace | Buffer | string;
export type HookHandler = (call: HookCall) => HookResult | Promise<HookResult>;

/** Answer for a request hook: stop the request (the client gets ProxyMind's 403). */
export const DROP = "drop" as const;

/** Forward `raw` instead of the message. */
export function replace(raw: Buffer | string, note = ""): Replace {
  return { action: "replace", raw: typeof raw === "string" ? Buffer.from(raw, "latin1") : raw, note };
}

/** The message with a header added at the end of the head; every other byte is untouched. */
export function addHeader(raw: Buffer, name: string, value: string): Buffer {
  const end = raw.indexOf("\r\n\r\n");
  if (end < 0) return raw;
  return Buffer.concat([raw.subarray(0, end), Buffer.from(`\r\n${name}: ${value}`, "latin1"), raw.subarray(end)]);
}

/** The body of a message (everything after the blank line). */
export function bodyOf(raw: Buffer): Buffer {
  const end = raw.indexOf("\r\n\r\n");
  return end < 0 ? Buffer.alloc(0) : raw.subarray(end + 4);
}

/** The first header called `name` (any case), or undefined. */
export function header(raw: Buffer, name: string): string | undefined {
  const end = raw.indexOf("\r\n\r\n");
  const head = raw.subarray(0, end < 0 ? raw.length : end).toString("latin1").split("\r\n").slice(1);
  for (const line of head) {
    const i = line.indexOf(":");
    if (i > 0 && line.slice(0, i).trim().toLowerCase() === name.toLowerCase()) return line.slice(i + 1).trim();
  }
  return undefined;
}

/** Parses one frame from ProxyMind. */
export function parseCall(line: string): HookCall {
  const f = JSON.parse(line);
  const ex = f.exchange ?? {};
  return {
    id: f.id,
    phase: f.phase,
    method: ex.method ?? "",
    url: ex.url ?? "",
    scheme: ex.scheme ?? "",
    host: ex.host ?? "",
    port: ex.port ?? 0,
    path: ex.path ?? "",
    status: ex.status,
    raw: Buffer.from(f.raw ?? "", "base64"),
  };
}

/** The answer line (without the newline) for a handler's result. */
export function answer(call: HookCall, result: HookResult): string {
  if (result === undefined || result === null || result === "pass") return JSON.stringify({ id: call.id, action: "pass" });
  if (result === DROP) return JSON.stringify({ id: call.id, action: "drop" });
  let raw: Buffer;
  let note = "";
  if (typeof result === "string") raw = Buffer.from(result, "latin1");
  else if (Buffer.isBuffer(result)) raw = result;
  else ({ raw, note } = result);
  return JSON.stringify({ id: call.id, action: "replace", raw: raw.toString("base64"), note });
}

/** Answers ProxyMind's frames until it closes stdin. Resolves when stdin ends. */
export async function serve(
  handlers: { request?: HookHandler; response?: HookHandler },
  input: NodeJS.ReadableStream = process.stdin,
  output: { write(s: string): unknown } = process.stdout,
): Promise<void> {
  const rl = createInterface({ input, crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    const call = parseCall(line);
    const handler = handlers[call.phase];
    output.write(answer(call, handler ? await handler(call) : undefined) + "\n");
  }
}

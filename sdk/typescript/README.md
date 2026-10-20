# @proxymind/client (TypeScript)

A small client for the [ProxyMind](https://github.com/ommirkute/proxymind) REST API with no runtime dependencies: it uses the platform's `fetch` (Node 18+, Deno, Bun, browsers). Apache-2.0 (the ProxyMind core is AGPL-3.0; this SDK isn't, so you can use it in any integration).

```bash
cd sdk/typescript && npm ci && npm run build
proxymind ui            # in another terminal: starts the proxy, UI and API
```

```ts
import { Client, PendingApproval } from "@proxymind/client";

const pm = await Client.connect(); // http://127.0.0.1:7777; token from PROXYMIND_TOKEN or ~/.proxymind/api-token

for (const ex of await pm.history({ path: "/api/orders", limit: 20 })) console.log(ex.id, ex.method, ex.path, ex.status);

try {
  await pm.replay({ exchange_id: 42, identity: "bob" });
} catch (e) {
  if (!(e instanceof PendingApproval)) throw e;
  console.log("waiting for a human:", e.summary);
  await pm.waitForApproval(e.approvalId);
}

const leads = (await pm.scanActive(42)).issues;
console.log(await pm.report("sarif"));
for await (const counters of pm.events()) console.log(counters); // live updates
```

Everything goes through ProxyMind's policy gate and audit log. The API acts as the person who started `proxymind ui`; for an autonomous agent, use the MCP server (`proxymind mcp --actor agent:<name>`) so it gets an agent's limits.

Errors: `ApiError` (with `status`), `Denied` (the gate refused; `reasons`) and `PendingApproval` (`approvalId`, `summary`).

Tests start a real `proxymind` and VulnShop: `npm run build && PROXYMIND=../../target/debug/proxymind npm test`.

# ADR-0011: XSS proofs render the recorded response in an offline headless browser

**Status:** Accepted

## Context
"No proof, no finding" needs an oracle for cross-site scripting. Seeing the payload reflected is not proof: the content type, a Content-Security-Policy or the HTML context often stop it from running. Only a browser can say whether script ran. But a browser loading a live target re-sends the request (a second, unapproved send), fetches every subresource, and can follow links and redirects out of scope.

## Decision
- The `reflection` oracle sends one request through the policy gate (active-intrusive) with a payload carrying a fresh, random token. The response is recorded like any other exchange.
- `pm-browser` starts headless Chromium with a throwaway profile and drives it over the DevTools protocol (CDP). It navigates to the request's URL so the page has the right origin, answers that one navigation with the **recorded** status, headers and decoded body (`Fetch.fulfillRequest`), and fails every other request before it leaves the browser. As a second line of defence, the browser runs with a proxy that refuses all connections (loopback included) and a resolver that resolves nothing.
- Script execution is observed with `Runtime.addBinding("pmProof")` and `Page.javascriptDialogOpening`. The verdict (pure, in `pm-proof`) is proven only when a binding call carries exactly the token or a dialog message contains it. The page's own script calling the binding with other values doesn't count.
- CDP is spoken over our own WebSocket frame codec (`pm_http::ws`) instead of a CDP crate: no new dependencies, and the protocol surface we use is small.
- The browser is `PROXYMIND_CHROMIUM` or, failing that, found in Playwright's cache and the usual install locations. It is deliberately not a project setting: project files are handed between people, and one must not choose what executable runs. It runs with its sandbox, falling back to `--no-sandbox` only when the sandbox can't start (e.g. as root in a container).

## Consequences
- No traffic beyond the one approved send; proofs are safe to re-run and work on recordings.
- The response's real headers apply, so a CSP that blocks the payload correctly means "not proven".
- Needs a Chromium-family browser on the machine. Without one, the oracle refuses before sending anything. Tests that need a browser skip with a note when none is found.
- Stored XSS (payload sent to one endpoint, shown on another) and DOM XSS that depends on other resources loading aren't covered yet; they need a "render this other exchange" option and selective subresource serving from history.

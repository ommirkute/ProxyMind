//! MCP tool definitions and dispatch. Names and shapes follow RFC 0001.

use pm_service::pm_ai::View;
use pm_service::pm_policy::{Actor, ActorKind, Tier};
use pm_service::pm_store::HistoryFilter;
use pm_service::{ReplayRequest, Service};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn tool(name: &str, description: &str, properties: Value, required: &[&str]) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": { "type": "object", "properties": properties, "required": required, "additionalProperties": false },
    })
}

const VIEW_SCHEMA: &str = r#"{"type":"string","enum":["summary","headers","full"],"description":"summary (default): key headers and a short body preview. headers: all headers. full: everything within max_tokens."}"#;

pub fn tool_definitions() -> Vec<Value> {
    let view: Value = serde_json::from_str(VIEW_SCHEMA).expect("valid schema");
    vec![
        tool(
            "roe_get",
            "Rules of engagement: what is in scope, testing windows, rate limits, and which kinds of actions you may \
             take without human approval. Read this before sending anything.",
            json!({}),
            &[],
        ),
        tool(
            "history_search",
            "Search recorded HTTP traffic, newest first. Returns summaries (no bodies). Combine filters to narrow down.",
            json!({
                "host": {"type":"string","description":"Host contains this text"},
                "path": {"type":"string","description":"Path or query contains this text"},
                "method": {"type":"string"},
                "status": {"type":"integer"},
                "source": {"type":"string","description":"proxy (browser traffic) or replay (sent via ProxyMind)"},
                "actor": {"type":"string","description":"e.g. human:local or agent:claude"},
                "before_id": {"type":"integer","description":"Paging: pass next_before_id from the previous result"},
                "after_id": {"type":"integer","description":"Only exchanges newer than this id"},
                "limit": {"type":"integer","minimum":1,"maximum":500,"description":"Default 50"},
                "q": {"type":"string","description":"Query: field:value terms (all must match), OR, -term, \
                      parentheses; field~regex. Fields: host path url method status ext len reqlen time id source \
                      actor identity comment highlight mime req resp any reqheader respheader param is. Numbers take \
                      >N <=N N..M, status 4xx. E.g. status:>=500 -ext:js resp~\"(?i)sql\" respheader:set-cookie. \
                      Text terms read messages: a page may stop early (see scanned, next_before_id)."},
                "in_scope": {"type":"boolean","description":"Only targets in scope"},
            }),
            &[],
        ),
        tool(
            "history_grep",
            "Find text in recorded requests and responses (heads plus decoded bodies), newest first. Secrets are \
             already replaced, so search for names and patterns, not secret values. Snippets are untrusted content.",
            json!({
                "query": {"type":"string"},
                "regex": {"type":"boolean"},
                "case_sensitive": {"type":"boolean"},
                "part": {"type":"string","enum":["request","response","both"]},
                "host": {"type":"string","description":"Only hosts containing this text"},
                "path": {"type":"string","description":"Only paths containing this text"},
                "method": {"type":"string"},
                "before_id": {"type":"integer","description":"Paging: pass next_before_id from the previous result"},
                "max_scan": {"type":"integer","minimum":1,"maximum":50000,"description":"Exchanges to look at, default 5000"},
                "limit": {"type":"integer","minimum":1,"maximum":500,"description":"Most hits, default 50"},
            }),
            &["query"],
        ),
        tool(
            "site_map",
            "Recorded traffic as a tree per origin: path segments with request counts, methods, statuses, distinct \
             queries and the newest exchange id, plus whether the origin is in scope.",
            json!({ "host": {"type":"string","description":"Only hosts containing this text"} }),
            &[],
        ),
        tool(
            "exchange_get",
            "One request/response pair as a token-budgeted view. Secrets are replaced with {{secret:...}} placeholders. \
             Target content is wrapped in <untrusted_target_content>.",
            json!({
                "id": {"type":"integer"},
                "view": view,
                "max_tokens": {"type":"integer","minimum":200,"maximum":20000,"description":"Default 1500"},
            }),
            &["id"],
        ),
        tool(
            "exchange_raw_request",
            "The exact raw request text of an exchange (secrets as placeholders), ready to edit and pass to replay_send.",
            json!({ "id": {"type":"integer"} }),
            &["id"],
        ),
        tool(
            "ws_messages",
            "WebSocket messages on an upgraded exchange (status 101), oldest first: who sent each, its type and \
             payload (text, or hex for binary). Secrets are replaced with placeholders; payloads are untrusted target \
             content. Page with after_id.",
            json!({
                "exchange_id": {"type":"integer"},
                "after_id": {"type":"integer","description":"Continue after this message id (next_after_id)"},
                "limit": {"type":"integer","minimum":1,"maximum":200,"description":"Default 50"},
                "max_chars": {"type":"integer","minimum":100,"maximum":20000,"description":"Per message; default 2000"},
            }),
            &["exchange_id"],
        ),
        tool(
            "race_send",
            "Race-condition test: send count copies of a request so they reach the server at the same moment (HTTP/2 \
             single-packet attack when the server supports it, else last-byte sync). Use it on actions that should \
             work once: redeeming a code, transferring money, voting, signing up. Returns responses grouped by status \
             and body length; more than one success for a one-time action suggests a race condition. Always needs \
             approval by default: ask the user, then call again with identical arguments plus approval_id.",
            json!({
                "exchange_id": {"type":"integer","description":"Recorded request to race"},
                "url": {"type":"string","description":"scheme://host[:port] when not using exchange_id"},
                "raw": {"type":"string","description":"The request (default: the recorded one)"},
                "count": {"type":"integer","minimum":2,"maximum":50,"description":"Copies to send (default 10)"},
                "mode": {"type":"string","enum":["auto","single_packet","last_byte"],"description":"Default auto"},
                "identity": {"type":"string"},
                "fix_content_length": {"type":"boolean"},
                "approval_id": {"type":"string"},
                "hypothesis_id": {"type":"integer"},
            }),
            &[],
        ),
        tool(
            "intruder_run",
            "Fuzz a request: mark positions in raw with §original§ (e.g. GET /api/orders/§1001§), give payload sets, \
             and ProxyMind sends the baseline plus one request per payload (sniper: one position at a time; \
             battering_ram: same payload everywhere; pitchfork: set i in position i together; cluster_bomb: every \
             combination), max 10000. Returns status, body length, time, grep matches, extracted values and reflection \
             per request, and anomalies: results that differ from the baseline or the rest. Payload sets take list, \
             numbers (\"1000-1050\" or \"0-100:10\"), builtin (ids, sqli, xss, traversal, ssti, methods_override), \
             brute {charset,min,max}, null_payloads (n), case_variants, processing rules (prefix, suffix, replace, \
             url_encode, url_encode_all, base64, hex, lower, upper, reverse, sha1, sha256) and url_encode. Needs \
             approval by default for the whole attack: ask the user, then call again with identical arguments plus \
             approval_id.",
            json!({
                "exchange_id": {"type":"integer","description":"Recorded request whose target to use"},
                "url": {"type":"string","description":"scheme://host[:port] when not using exchange_id"},
                "raw": {"type":"string","description":"Request with positions marked §like this§"},
                "mode": {"type":"string","enum":["sniper","battering_ram","pitchfork","cluster_bomb"]},
                "payload_sets": {"type":"array","items":{"type":"object","properties":{
                    "list":{"type":"array","items":{"type":"string"}},
                    "numbers":{"type":"string"},
                    "builtin":{"type":"string","enum":["ids","sqli","xss","traversal","ssti","methods_override"]},
                    "brute":{"type":"object","properties":{"charset":{"type":"string"},"min":{"type":"integer"},"max":{"type":"integer"}}},
                    "null_payloads":{"type":"integer"},
                    "case_variants":{"type":"array","items":{"type":"string"}},
                    "processing":{"type":"array","items":{"type":"object","description":"{\"op\":\"prefix\",\"value\":\"x\"}, {\"op\":\"replace\",\"find\":\"a\",\"with\":\"b\"}, {\"op\":\"base64\"}…"}},
                    "url_encode":{"type":"boolean"}}}},
                "grep": {"type":"array","items":{"type":"string"},"description":"Flag responses containing these"},
                "grep_regex": {"type":"boolean","description":"grep terms are regular expressions"},
                "extract": {"type":"array","items":{"type":"object","properties":{
                    "start":{"type":"string"},"end":{"type":"string"},"regex":{"type":"string"}}},
                    "description":"Pull a value out of each response: between start and end, or a regex's first group"},
                "concurrency": {"type":"integer","minimum":1,"maximum":20},
                "throttle_ms": {"type":"integer","minimum":0,"maximum":60000},
                "identity": {"type":"string"},
                "fix_content_length": {"type":"boolean"},
                "hypothesis_id": {"type":"integer"},
                "approval_id": {"type":"string"},
            }),
            &["raw", "payload_sets"],
        ),
        tool(
            "ws_send",
            "Open a new WebSocket like a recorded one (exchange_id of a status-101 upgrade), send messages in order and \
             get every message both ways. ProxyMind listens wait_ms after opening and after each message, answers pings \
             and closes at the end; the session is recorded as a new exchange. Opening only is usually allowed; sending \
             messages may return status=pending_approval: ask the user, then call again with identical arguments plus \
             approval_id. Use {{secret:...}} placeholders as shown to you.",
            json!({
                "exchange_id": {"type":"integer","description":"Recorded WebSocket upgrade (status 101)"},
                "raw": {"type":"string","description":"Edited upgrade request (HTTP/1.1); default: the recorded one"},
                "messages": {"type":"array","maxItems":50,"description":"Sent in order","items":{"type":"object",
                    "properties":{"text":{"type":"string"},"hex":{"type":"string","description":"Binary payload as hex"}},
                    "additionalProperties":false}},
                "wait_ms": {"type":"integer","minimum":0,"maximum":10000,"description":"Listen time after each message (default 1000)"},
                "identity": {"type":"string","description":"Open the socket as this identity"},
                "approval_id": {"type":"string"},
                "hypothesis_id": {"type":"integer"},
                "max_chars": {"type":"integer","minimum":100,"maximum":20000,"description":"Per message shown; default 2000"},
            }),
            &["exchange_id"],
        ),
        tool(
            "replay_send",
            "Send a request to the target and get the response (HTTP/1.1; write HTTP/2 in the request line for HTTP/2, \
             with a host: header for :authority). Give exchange_id to resend or edit a recorded \
             request (its target is used), or url + raw for a new one. Use {{secret:...}} placeholders exactly as shown \
             to you. GET/HEAD/OPTIONS usually run directly; other methods may return status=pending_approval: ask the \
             user to approve, then call again with identical arguments plus approval_id.",
            json!({
                "exchange_id": {"type":"integer","description":"Recorded exchange to resend or base this on"},
                "url": {"type":"string","description":"scheme://host[:port] when not using exchange_id"},
                "identity": {"type":"string","description":"Send with this identity's credentials (see identity_list), or 'anonymous'"},
                "raw": {"type":"string","description":"Full raw request (request line, headers, blank line, body)"},
                "fix_content_length": {"type":"boolean","description":"Set Content-Length to the body length (default true)"},
                "normalize_newlines": {"type":"boolean","description":"Turn \\n into \\r\\n in the head (default true)"},
                "approval_id": {"type":"string","description":"From a previous pending_approval result"},
                "hypothesis_id": {"type":"integer","description":"Hypothesis this send tests (links evidence)"},
                "view": view,
                "max_tokens": {"type":"integer","minimum":200,"maximum":20000},
            }),
            &[],
        ),
        tool(
            "identity_list",
            "Test identities (users/roles) whose credentials ProxyMind holds. Shows names, roles, cookie and header \
             names and session status, never secret values.",
            json!({}),
            &[],
        ),
        tool(
            "identity_capture",
            "Create or update an identity from the cookies and auth headers of a recorded request (e.g. a request the \
             user made while logged in as that user). You never see the values.",
            json!({
                "name": {"type":"string","description":"Short name, e.g. alice or admin"},
                "role": {"type":"string","description":"e.g. user, admin, guest"},
                "exchange_id": {"type":"integer"},
            }),
            &["name", "exchange_id"],
        ),
        tool(
            "identity_check",
            "Check an identity's session with its health check, logging in again automatically if it has a login recipe.",
            json!({ "name": {"type":"string"} }),
            &["name"],
        ),
        tool(
            "identity_learn_logged_out",
            "Learn how the app answers when an identity's session is gone (logs in, sends its health check with and \
             without credentials). Afterwards, expired sessions that still answer 200 are noticed and logged in again.",
            json!({ "name": {"type":"string"} }),
            &["name"],
        ),
        tool(
            "authz_check",
            "Authorization test: re-send a recorded GET (made by the data's owner) as other identities and as an \
             anonymous user, and compare each response with the owner's while ignoring noise such as timestamps. \
             Verdicts: denied, same_as_owner (possible broken access control), allowed_different, inconclusive.",
            json!({
                "exchange_id": {"type":"integer","description":"A GET/HEAD/OPTIONS exchange made by the owner"},
                "identities": {"type":"array","items":{"type":"string"},"description":"Identity names to try"},
                "include_anonymous": {"type":"boolean","description":"Also try without credentials (default true)"},
            }),
            &["exchange_id"],
        ),
        tool(
            "authz_results",
            "Latest authorization-check results, per exchange and identity.",
            json!({ "exchange_id": {"type":"integer","description":"Only this exchange"} }),
            &[],
        ),
        tool(
            "scan_issues",
            "Passive scan of recorded traffic (sends nothing): missing security headers, weak session cookies, \
             permissive CORS, version disclosure, database errors and stack traces, secrets in responses, directory \
             listings, passwords over HTTP. Grouped by origin and path template, most severe first. These are leads \
             to test and prove, not findings.",
            json!({
                "host": {"type":"string","description":"Only hosts containing this"},
                "limit": {"type":"integer","description":"Recent exchanges to scan (default 2000)"},
                "min_severity": {"type":"string","enum":["info","low","medium","high"]},
            }),
            &[],
        ),
        tool(
            "scan_active",
            "Active checks on one recorded request: payloads in each query, form, JSON and numeric/ID path value, \
             cookie and User-Agent/Referer/X-Forwarded-For header. One-shot: sql_error, cmd_injection, \
             reflected_input, open_redirect, path_traversal, ssti. Multi-step with confirmation: sql_boolean \
             (true/false pairs), sql_time and cmd_time (the delay must follow the payload: sleep 0 fast, a longer \
             sleep longer). Out of band, with an OAST listener (the target calls back; each probe has its own \
             token): ssrf_oob, xxe_oob, sql_oob, cmd_oob, ssti_oob, log4shell, code_oob. Also crlf, host_header, \
             cors, nosql_operator ($ne/$regex differential), auth_bypass (path and header tricks on 401/403, \
             checked against a missing path), hidden_params (param mining); sql_error also reports NoSQL, LDAP and \
             XPath errors. Client side: stored_xss (on submissions; looks for the value on HTML pages from history), \
             dom_xss (renders the page in headless Chromium with sink hooks), csrf (the request from a foreign \
             Origin with the session cookie). Step 4: jwt (guessable HMAC secret offline; changed signature, alg none \
             and no signature sent), graphql (introspection, batching, suggestions, GET), cache_poisoning (unkeyed \
             headers, with a cache buster), cache_deception (.css suffixes on private pages), mass_assignment \
             (role/isAdmin added to submissions), proto_pollution (__proto__ in JSON), oauth (redirect_uri to another \
             site, no state), deserialization (corrupted Java/PHP/pickle/.NET/Ruby objects; errors show the server \
             deserializes). request_smuggling (TE.CL/CL.TE timing), file_upload (HTML/SVG/PHP files fetched back) \
             and race_condition (10 copies at once, before the baseline) raise the scan to the destructive tier: \
             a person approves them, and agents are denied unless the ROE allows. Returns leads with \
             evidence and, where an oracle fits, how to prove them (prove_with). \
             Needs approval by default: ask the user, then call again with identical arguments plus approval_id.",
            json!({
                "exchange_id": {"type":"integer"},
                "checks": {"type":"array","items":{"type":"string","enum":["sql_error","cmd_injection","reflected_input","open_redirect","path_traversal","ssti","sql_boolean","sql_time","cmd_time","ssrf_oob","xxe_oob","sql_oob","cmd_oob","ssti_oob","log4shell","code_oob","crlf","host_header","cors","nosql_operator","auth_bypass","hidden_params","stored_xss","dom_xss","csrf","jwt","graphql","cache_poisoning","cache_deception","mass_assignment","proto_pollution","oauth","deserialization","request_smuggling","file_upload","race_condition"]}},
                "oob_wait_seconds": {"type":"integer","minimum":1,"maximum":60,"description":"Wait for callbacks, default 10"},
                "max_requests": {"type":"integer","minimum":1,"maximum":2000},
                "identity": {"type":"string"},
                "hypothesis_id": {"type":"integer"},
                "approval_id": {"type":"string"},
            }),
            &["exchange_id"],
        ),
        tool(
            "openapi_import",
            "Import an OpenAPI 3 / Swagger 2 description (spec text, or exchange_id of a recorded spec response such as \
             /openapi.json): returns every operation with an example request and whether it needs auth. With \
             send_examples, the GET examples are sent once (in scope only) so history and the app model learn them.",
            json!({
                "spec": {"type":"string","description":"JSON or YAML"},
                "exchange_id": {"type":"integer"},
                "base_url": {"type":"string","description":"When the spec's servers aren't absolute"},
                "send_examples": {"type":"boolean"},
                "identity": {"type":"string"},
                "approval_id": {"type":"string"},
            }),
            &[],
        ),
        tool(
            "decode",
            "Encode/decode locally (nothing is sent): give ops in order (base64_decode, url_decode, html_decode, \
             hex_decode, unicode_unescape, gzip_decode, jwt_decode, the *_encode forms, sha1, sha256, …), or no ops \
             for a smart decode that peels JWT, URL, HTML, base64, hex and unicode layers.",
            json!({ "input": {"type":"string"}, "ops": {"type":"array","items":{"type":"string"}} }),
            &["input"],
        ),
        tool(
            "graphql_import",
            "Read a GraphQL schema from an introspection result and list its queries, mutations and subscriptions \
             with example documents, variables and HTTP requests (use them with replay_send). Give url (the \
             endpoint) and one of: schema (introspection JSON text), exchange_id (a recorded introspection \
             response), or fetch: true to send the introspection query (may need approval).",
            json!({
                "url": {"type":"string","description":"e.g. https://app.example.com/graphql"},
                "schema": {"type":"string"},
                "exchange_id": {"type":"integer"},
                "fetch": {"type":"boolean"},
                "identity": {"type":"string"},
                "approval_id": {"type":"string"},
            }),
            &[],
        ),
        tool(
            "import_har",
            "Add the exchanges in a HAR file (browser devtools export) to history, tagged source=import. Sends \
             nothing. Bodies are stored decoded, so imported exchanges are rebuilt, not byte-exact.",
            json!({ "har": {"type":"string","description":"The HAR document as JSON text"} }),
            &["har"],
        ),
        tool(
            "curl_parse",
            "Read a curl command (e.g. from a browser's Copy as cURL) into a raw request and url for replay_send. \
             Sends nothing; options that can't be honoured (files, multipart) come back as warnings.",
            json!({ "command": {"type":"string"} }),
            &["command"],
        ),
        tool(
            "compare_exchanges",
            "Compare two recorded exchanges: semantic response similarity and line diffs of requests and responses.",
            json!({ "a": {"type":"integer"}, "b": {"type":"integer"} }),
            &["a", "b"],
        ),
        tool(
            "sequencer_run",
            "Token randomness: re-send a token-issuing request samples times (default 100) and analyse the tokens at \
             locator (cookie:<name>, header:<name>, json:/pointer, between:<a>|<b>): entropy estimate, constant \
             positions, duplicates, counters. Returns statistics only, never the tokens. May need approval.",
            json!({
                "exchange_id": {"type":"integer"},
                "locator": {"type":"string"},
                "samples": {"type":"integer","minimum":10,"maximum":500},
                "identity": {"type":"string"},
                "approval_id": {"type":"string"},
            }),
            &["exchange_id", "locator"],
        ),
        tool(
            "discover_content",
            "Look for hidden files and folders under url (forced browsing): GET each word once (built-in list of \
             common paths such as .git/config, .env, backup.zip, admin, actuator; or your words, optionally with \
             extensions), in scope only, skipping paths that look like log out or delete. Tells real pages from the \
             server's not-found page (soft 404). One approval covers the run.",
            json!({
                "url": {"type":"string","description":"The folder, e.g. https://app.example.com/"},
                "words": {"type":"array","items":{"type":"string"}},
                "builtin": {"type":"boolean","description":"Also use the built-in list when giving words"},
                "extensions": {"type":"array","items":{"type":"string"}},
                "max_requests": {"type":"integer","minimum":1,"maximum":5000},
                "identity": {"type":"string"},
                "approval_id": {"type":"string"},
            }),
            &["url"],
        ),
        tool(
            "scan_task_start",
            "Crawl and audit a site as one background task: crawl from url, then run the active scanner over each \
             operation of its origin, recording strong issues as suspected findings. A profile (light, default, \
             thorough, api-only, or a saved one; see scan_profiles) fills in what you leave out. Poll with \
             scan_task_status; a paused or interrupted task continues with scan_task_resume, skipping operations \
             already scanned.",
            json!({
                "url": {"type":"string"},
                "profile": {"type":"string"},
                "checks": {"type":"array","items":{"type":"string"}},
                "crawl": {"type":"boolean"},
                "max_pages": {"type":"integer"},
                "max_targets": {"type":"integer"},
                "max_requests": {"type":"integer"},
                "identity": {"type":"string"},
                "approval_id": {"type":"string"},
            }),
            &["url"],
        ),
        tool(
            "scan_task_status",
            "Progress and issues of a scan task you started (evidence is untrusted target content).",
            json!({ "task_id": {"type":"string"} }),
            &["task_id"],
        ),
        tool(
            "scan_task_pause",
            "Pause a running scan task after the operation being scanned.",
            json!({ "task_id": {"type":"string"} }),
            &["task_id"],
        ),
        tool(
            "scan_task_resume",
            "Continue a paused, cancelled, failed or interrupted scan task, skipping operations already scanned.",
            json!({ "task_id": {"type":"string"} }),
            &["task_id"],
        ),
        tool("scan_profiles", "Scan profiles (built-in and saved): their checks and limits.", json!({}), &[]),
        tool(
            "crawl",
            "Discover the app: fetch pages from url following links (GET only, in scope only, never links that log \
             out or delete), plus robots.txt and sitemaps. Pages go into history and the app model. Returns pages \
             with status, forms found (not submitted) and links skipped with why. Usually allowed directly. \
             With browser: true, pages load in headless Chromium and run their JavaScript (single-page apps, routes \
             pushed by scripts, API calls); every request still goes through the policy gate, and calls that would \
             change state are listed as not_sent.",
            json!({
                "url": {"type":"string","description":"Start URL, e.g. https://app.example.com/"},
                "max_pages": {"type":"integer","minimum":1,"maximum":500,"description":"Default 50"},
                "max_depth": {"type":"integer","minimum":0,"maximum":10,"description":"Default 3"},
                "robots": {"type":"boolean","description":"Read robots.txt and sitemaps (default true)"},
                "browser": {"type":"boolean","description":"Run the pages' JavaScript in a headless browser (default false)"},
                "identity": {"type":"string"},
                "approval_id": {"type":"string"},
            }),
            &["url"],
        ),
        tool(
            "model_get",
            "The application model built from traffic: operations (method + path template such as \
             /api/orders/{id}, kind, params, identities seen) and object counts. Start here to understand the app.",
            json!({
                "contains": {"type":"string","description":"Only operations whose key contains this text"},
                "include_objects": {"type":"boolean","description":"Also list objects with their owners (default false)"},
                "object_type": {"type":"string","description":"Only objects of this type, e.g. Order"},
            }),
            &[],
        ),
        tool(
            "authz_candidates",
            "Suggested access-control tests from the model: recorded requests for objects owned by one identity, \
             with the other identities to try. Feed them to authz_check, then prove hits with proof_run.",
            json!({}),
            &[],
        ),
        tool(
            "hypothesis_create",
            "Record what you are about to test, so work is shared and coverage is tracked. Pass the returned id as \
             hypothesis_id to replay_send and proof_run to link evidence.",
            json!({
                "operation": {"type":"string","description":"Operation key from model_get"},
                "param": {"type":"string","description":"Parameter tested, if any"},
                "vuln_class": {"type":"string","description":"idor, bfla, authn, sqli, xss, ssrf, mass_assignment, business_logic, or your own"},
                "rationale": {"type":"string"},
            }),
            &["operation", "vuln_class", "rationale"],
        ),
        tool(
            "hypothesis_update",
            "Update a hypothesis: status open/testing/confirmed/refuted and/or add a note. Mark refuted when a test \
             shows the issue is not there, so nobody repeats it.",
            json!({
                "id": {"type":"integer"},
                "status": {"type":"string","enum":["open","testing","confirmed","refuted"]},
                "note": {"type":"string"},
            }),
            &["id"],
        ),
        tool(
            "hypothesis_list",
            "All hypotheses (optionally by status), with linked evidence exchange ids.",
            json!({ "status": {"type":"string","enum":["open","testing","confirmed","refuted"]} }),
            &[],
        ),
        tool(
            "coverage",
            "What has and hasn't been tested: each operation × relevant vulnerability class, untested first.",
            json!({ "untested_only": {"type":"boolean","description":"Only untested/open cells (default true)"} }),
            &[],
        ),
        tool(
            "proof_run",
            "Have ProxyMind verify a suspected vulnerability itself. Oracles: differential_authz (exchange_id of the \
             owner's GET + attacker identity: proves IDOR/BOLA or missing role checks), timing (exchange_id or url, \
             payload_raw with a delay payload, optional baseline_raw: proves time-based injection statistically), oast \
             (url or exchange_id + raw containing {{oast}} for a callback URL or {{oast_dns}} for a host name to resolve: \
             proves SSRF/blind injection via an out-of-band HTTP request or DNS lookup), \
             reflection (url or exchange_id + raw containing {{xss_url}} in a query/form value, {{xss}} unencoded, or \
             {{token}} inside your own payload that calls pmProof('{{token}}') or alert('{{token}}'): sends it, \
             renders the recorded response offline in headless Chromium and proves XSS only if the script ran). \
             Pass finding_id/hypothesis_id to update them when proven. Payload oracles may need human approval.",
            json!({
                "oracle": {"type":"string","enum":["differential_authz","timing","oast","reflection"]},
                "exchange_id": {"type":"integer"},
                "attacker": {"type":"string"},
                "owner": {"type":"string"},
                "url": {"type":"string"},
                "baseline_raw": {"type":"string"},
                "payload_raw": {"type":"string"},
                "samples": {"type":"integer","minimum":5,"maximum":30},
                "min_effect_ms": {"type":"number"},
                "raw": {"type":"string"},
                "wait_seconds": {"type":"integer","minimum":1,"maximum":60},
                "identity": {"type":"string"},
                "finding_id": {"type":"integer"},
                "hypothesis_id": {"type":"integer"},
                "approval_id": {"type":"string"},
            }),
            &["oracle"],
        ),
        tool(
            "proof_get",
            "A stored proof: verdict, reasons, evidence exchange ids and inputs.",
            json!({ "proof_id": {"type":"integer"} }),
            &["proof_id"],
        ),
        tool(
            "finding_create",
            "Record a suspected vulnerability with evidence exchange ids. It becomes 'proven' only via proof_run; \
             humans confirm it.",
            json!({
                "title": {"type":"string"},
                "vuln_class": {"type":"string"},
                "severity": {"type":"string","enum":["critical","high","medium","low","info"]},
                "description": {"type":"string","description":"What is wrong, impact, and how to reproduce"},
                "url": {"type":"string"},
                "evidence": {"type":"array","items":{"type":"integer"}},
                "hypothesis_id": {"type":"integer"},
            }),
            &["title", "vuln_class", "severity", "description"],
        ),
        tool(
            "finding_update",
            "Update a finding's description, severity or evidence. Agents may only set status to suspected.",
            json!({
                "id": {"type":"integer"},
                "status": {"type":"string"},
                "severity": {"type":"string","enum":["critical","high","medium","low","info"]},
                "description": {"type":"string"},
                "add_evidence": {"type":"array","items":{"type":"integer"}},
            }),
            &["id"],
        ),
        tool(
            "finding_list",
            "Findings, optionally by status (suspected, proven, confirmed, false_positive, reported).",
            json!({ "status": {"type":"string"} }),
            &[],
        ),
        tool(
            "approval_status",
            "Check whether a human has approved or denied an action. Status: pending, approved, denied or used.",
            json!({ "approval_id": {"type":"string"} }),
            &["approval_id"],
        ),
    ]
}

fn args<T: DeserializeOwned>(v: Value) -> Result<T, String> {
    serde_json::from_value(v).map_err(|e| format!("invalid arguments: {e}"))
}

fn tier_name(t: Tier) -> String {
    serde_json::to_value(t).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
}

pub fn roe_summary(service: &Service, actor: &Actor) -> Value {
    let roe = service.policy().roe();
    let tiers: serde_json::Map<String, Value> =
        [Tier::Read, Tier::Passive, Tier::ActiveSafe, Tier::ActiveIntrusive, Tier::Destructive]
            .into_iter()
            .map(|t| (tier_name(t), json!(roe.tier_decision(actor.kind, t).as_str())))
            .collect();
    json!({
        "you_are": actor.id(),
        "engagement": {
            "name": roe.engagement.name,
            "starts": roe.engagement.starts.map(|d| d.to_string()),
            "ends": roe.engagement.ends.map(|d| d.to_string()),
        },
        "in_scope": roe.include.iter().map(|p| &p.text).collect::<Vec<_>>(),
        "excluded": roe.exclude.iter().map(|p| &p.text).collect::<Vec<_>>(),
        "denied_networks": roe.deny_networks.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "max_requests_per_second_per_host": roe.limits.max_rps_per_host,
        "your_permissions": tiers,
        "tiers_explained": {
            "active_safe": "GET/HEAD/OPTIONS requests",
            "active_intrusive": "POST/PUT/PATCH and other state-changing requests",
            "destructive": "DELETE requests",
        },
        "secrets_redacted": service.redacts_for(actor),
        "only_local_models_allowed": !roe.data.allow_cloud_models && actor.kind == ActorKind::Agent,
    })
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GetArgs {
    id: i64,
    view: Option<View>,
    max_tokens: Option<usize>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IdArgs {
    id: i64,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalArgs {
    approval_id: String,
}

pub async fn call(service: &std::sync::Arc<Service>, actor: &Actor, name: &str, a: Value) -> Result<Value, String> {
    match name {
        "roe_get" => Ok(roe_summary(service, actor)),
        "history_search" => {
            let f: HistoryFilter = args(a)?;
            service.history_search(actor, &f).map(to_json).map_err(|e| e.to_string())
        }
        "history_grep" => {
            let r: pm_service::SearchRequest = args(a)?;
            service.history_search_text(actor, &r).map(to_json).map_err(|e| e.to_string())
        }
        "site_map" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                host: Option<String>,
            }
            let g: A = args(a)?;
            service.site_map(actor, g.host.as_deref()).map(to_json).map_err(|e| e.to_string())
        }
        "exchange_get" => {
            let g: GetArgs = args(a)?;
            service
                .exchange_get(actor, g.id, g.view.unwrap_or_default(), g.max_tokens.unwrap_or(1500))
                .map(to_json)
                .map_err(|e| e.to_string())
        }
        "exchange_raw_request" => {
            let g: IdArgs = args(a)?;
            service
                .exchange_raw_request(actor, g.id)
                .map(|raw| json!({ "id": g.id, "raw": raw }))
                .map_err(|e| e.to_string())
        }
        "ws_messages" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                exchange_id: i64,
                after_id: Option<i64>,
                limit: Option<usize>,
                max_chars: Option<usize>,
            }
            let w: A = args(a)?;
            let (limit, max_chars) = (w.limit.unwrap_or(50).min(200), w.max_chars.unwrap_or(2000).clamp(100, 20000));
            service
                .ws_messages(actor, w.exchange_id, w.after_id, limit, max_chars)
                .map(to_json)
                .map_err(|e| e.to_string())
        }
        "race_send" => {
            let r: pm_service::RaceRequest = args(a)?;
            service.race_send(actor, r).await.map(to_json).map_err(|e| e.to_string())
        }
        "scan_active" => {
            let r: pm_service::ActiveScanRequest = args(a)?;
            service.scan_active(actor, r).await.map(to_json).map_err(|e| e.to_string())
        }
        "scan_issues" => {
            let f: pm_service::ScanFilter = args(a)?;
            service.scan_passive(actor, &f).map(to_json).map_err(|e| e.to_string())
        }
        "openapi_import" => {
            let r: pm_service::OpenApiImportRequest = args(a)?;
            service.openapi_import(actor, r).await.map(to_json).map_err(|e| e.to_string())
        }
        "decode" => {
            let r: pm_service::DecodeRequest = args(a)?;
            service.decode(&r).map_err(|e| e.to_string())
        }
        "graphql_import" => {
            let r: pm_service::GraphQlImportRequest = args(a)?;
            service.graphql_import(actor, r).await.map(to_json).map_err(|e| e.to_string())
        }
        "import_har" => {
            let r: pm_service::ImportRequest = args(a)?;
            service.traffic_import_har(actor, &r).map(to_json).map_err(|e| e.to_string())
        }
        "curl_parse" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                command: String,
            }
            let g: A = args(a)?;
            service.curl_parse(&g.command).map(to_json).map_err(|e| e.to_string())
        }
        "compare_exchanges" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                a: i64,
                b: i64,
            }
            let g: A = args(a)?;
            service.compare_exchanges(actor, g.a, g.b).map_err(|e| e.to_string())
        }
        "sequencer_run" => {
            let r: pm_service::SequencerRequest = args(a)?;
            service.sequencer_run(actor, r).await.map(to_json).map_err(|e| e.to_string())
        }
        "discover_content" => {
            let r: pm_service::DiscoverRequest = args(a)?;
            service.discover(actor, r).await.map(to_json).map_err(|e| e.to_string())
        }
        "scan_task_start" => {
            let r: pm_service::ScanTaskRequest = args(a)?;
            service.scan_task_start(actor, r).map(to_json).map_err(|e| e.to_string())
        }
        "scan_task_status" | "scan_task_resume" | "scan_task_pause" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                task_id: String,
            }
            let g: A = args(a)?;
            let r = match name {
                "scan_task_status" => service.scan_task_status(actor, &g.task_id),
                "scan_task_pause" => service.scan_task_pause(actor, &g.task_id),
                _ => service.scan_task_resume(actor, &g.task_id),
            };
            r.map(to_json).map_err(|e| e.to_string())
        }
        "scan_profiles" => service.scan_profiles().map(to_json).map_err(|e| e.to_string()),
        "crawl" => {
            let r: pm_service::CrawlRequest = args(a)?;
            service.crawl(actor, r).await.map(to_json).map_err(|e| e.to_string())
        }
        "intruder_run" => {
            let r: pm_service::IntruderRequest = args(a)?;
            service.intruder_run(actor, r).await.map(to_json).map_err(|e| e.to_string())
        }
        "ws_send" => {
            let r: pm_service::WsReplayRequest = args(a)?;
            service.ws_replay(actor, r).await.map(to_json).map_err(|e| e.to_string())
        }
        "replay_send" => {
            let r: ReplayRequest = args(a)?;
            service.replay_send(actor, r).await.map(to_json).map_err(|e| e.to_string())
        }
        "identity_list" => service.identity_list().map(to_json).map_err(|e| e.to_string()),
        "identity_capture" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                name: String,
                role: Option<String>,
                exchange_id: i64,
            }
            let g: A = args(a)?;
            service
                .identity_capture(actor, &g.name, g.role.as_deref().unwrap_or("user"), g.exchange_id)
                .map(to_json)
                .map_err(|e| e.to_string())
        }
        "identity_check" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                name: String,
            }
            let g: A = args(a)?;
            service.identity_check(actor, &g.name).await.map(to_json).map_err(|e| e.to_string())
        }
        "identity_learn_logged_out" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                name: String,
            }
            let g: A = args(a)?;
            service.identity_learn_logged_out(actor, &g.name).await.map(to_json).map_err(|e| e.to_string())
        }
        "authz_check" => {
            let r: pm_service::AuthzCheckRequest = args(a)?;
            service.authz_check(actor, r).await.map(to_json).map_err(|e| e.to_string())
        }
        "authz_results" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                exchange_id: Option<i64>,
            }
            let g: A = args(a)?;
            service.authz_results(g.exchange_id).map(to_json).map_err(|e| e.to_string())
        }
        "model_get" => {
            let f: pm_service::ModelFilter = args(a)?;
            service.model_get(&f).map_err(|e| e.to_string())
        }
        "authz_candidates" => service.authz_candidates().map(to_json).map_err(|e| e.to_string()),
        "hypothesis_create" => {
            let h: pm_service::NewHypothesis = args(a)?;
            service.hypothesis_create(actor, h).map(to_json).map_err(|e| e.to_string())
        }
        "hypothesis_update" => {
            let u: pm_service::HypothesisUpdate = args(a)?;
            service.hypothesis_update(actor, u).map(to_json).map_err(|e| e.to_string())
        }
        "hypothesis_list" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                status: Option<String>,
            }
            let g: A = args(a)?;
            service.hypothesis_list(g.status.as_deref()).map(to_json).map_err(|e| e.to_string())
        }
        "coverage" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                untested_only: Option<bool>,
            }
            let g: A = args(a)?;
            service.coverage(g.untested_only.unwrap_or(true)).map(to_json).map_err(|e| e.to_string())
        }
        "proof_run" => {
            let r: pm_service::ProofRequest = args(a)?;
            service.proof_run(actor, r).await.map(to_json).map_err(|e| e.to_string())
        }
        "proof_get" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                proof_id: i64,
            }
            let g: A = args(a)?;
            service.proof_get(g.proof_id).map_err(|e| e.to_string())
        }
        "finding_create" => {
            let f: pm_service::NewFinding = args(a)?;
            service.finding_create(actor, f).map_err(|e| e.to_string())
        }
        "finding_update" => {
            let u: pm_service::FindingUpdate = args(a)?;
            service.finding_update(actor, u).map_err(|e| e.to_string())
        }
        "finding_list" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                status: Option<String>,
            }
            let g: A = args(a)?;
            service.finding_list(g.status.as_deref()).map(to_json).map_err(|e| e.to_string())
        }
        "approval_status" => {
            let g: ApprovalArgs = args(a)?;
            match service.approval(&g.approval_id).map_err(|e| e.to_string())? {
                Some(row) if row.actor == actor.id() => Ok(json!({
                    "approval_id": row.id, "status": row.status, "summary": row.summary, "decided_by": row.decided_by,
                })),
                _ => Err(format!("no approval {} for {}", g.approval_id, actor.id())),
            }
        }
        _ => Err(format!("unknown tool {name}")),
    }
}

fn to_json<T: serde::Serialize>(v: T) -> Value {
    serde_json::to_value(v).unwrap_or_else(|e| json!({ "error": e.to_string() }))
}

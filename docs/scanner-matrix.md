# Active scanner: feature matrix

What a professional web scanner covers, what ProxyMind has, and what to
build next. The issue list follows PortSwigger's **public** issue
definitions and scanner documentation (no Burp code was looked at); the
BurpMax column is the author's own MIT-licensed Burp extension
(github.com/ommirkute/BurpMax), whose ideas we reimplement in Rust.

Legend: ✅ have · 🟡 partial · ❌ missing · step = build order (below).

## Injection

| Issue | ProxyMind | BurpMax | Step |
|---|---|---|---|
| SQL injection: error-based | ✅ (quote → DB error) | ✅ | 1 (more payloads, headers, confirmation) |
| SQL injection: boolean-based blind | ✅ step 1 | ✅ (length only) | 1 (content similarity, two formulations) |
| SQL injection: time-based blind | ✅ step 1 (+ `timing` proof oracle) | ✅ | 1 (delay must follow the payload) |
| SQL injection: out-of-band | ✅ step 2 (SQL Server, MySQL, Oracle, PostgreSQL) | ✅ (Interactsh) | 2 |
| SQL injection in headers and cookies | ✅ step 1 | ✅ (headers) | 1 |
| OS command injection: output-based | ✅ step 1 | ✅ | 1 |
| OS command injection: time-based | ✅ step 1 | ✅ | 1 |
| OS command injection: out-of-band | ✅ step 2 (curl, wget, nslookup) | ✅ | 2 |
| Server-side template injection: evaluated | ✅ (3 engines) → step 1 adds more engines | ✅ | 1 |
| Server-side template injection: blind | ✅ step 2 (6 engines, OOB) | ✅ (OOB) | 2 |
| Expression language / code injection (PHP, Python, Node eval) | 🟡 step 2 (OOB) | 🟡 | 2 |
| NoSQL injection (operators, JS) | ✅ step 3 (errors, $ne/$regex differential) | ✅ | 3 |
| LDAP injection | 🟡 step 3 (errors) | ✅ | 3 |
| XPath injection | 🟡 step 3 (errors) | ❌ | 3 |
| XML external entity (in-band and OOB) | 🟡 OOB step 2 (external DTD, entity) | ✅ | 2 (in-band file read: 3) |
| XML injection / SOAP | ❌ | 🟡 | 3 |
| CRLF / HTTP response header injection | ✅ step 3 | ❌ | 3 |
| SMTP / email header injection | ❌ | ❌ | 4 |
| Log4Shell-style lookups (OOB) | ✅ step 2 (needs the DNS zone) | ✅ | 2 |
| Server-side JavaScript / prototype pollution | ❌ | ✅ (client and server, blind) | 4 |
| Java / .NET / PHP deserialization | ❌ | ✅ (Java) | 4 (approval) |
| File path traversal / manipulation | ✅ | ✅ | 3 (more encodings, Windows) |
| File upload (type bypass, web shell) | ❌ | ✅ | 4 (approval) |

## Client-side and reflection

| Issue | ProxyMind | BurpMax | Step |
|---|---|---|---|
| Reflected XSS | ✅ (+ browser `reflection` proof) | ✅ | 3 (context-aware payloads) |
| Stored XSS | ❌ | ✅ | 3 |
| DOM XSS (sources → sinks) | ❌ | ✅ (static) | 3 (headless browser taint) |
| Client-side template injection (Angular) | ❌ | ❌ | 3 |
| Open redirection (reflected, DOM) | ✅ (reflected) | ✅ | 3 (DOM) |
| Link manipulation / input returned in response | 🟡 | ❌ | 3 |
| Cross-site request forgery | ❌ | ✅ | 3 |
| Clickjacking (frameable response) | ✅ passive | ✅ | – |

## Server-side request and routing

| Issue | ProxyMind | BurpMax | Step |
|---|---|---|---|
| SSRF (in-band and OOB) | ✅ OOB step 2 (URL-like parameters, Referer) | ✅ | 2 |
| External service interaction (DNS / HTTP) | ✅ OAST server + scan | ✅ | 2 |
| Host header injection / password-reset poisoning | ✅ step 3 (Host, X-Forwarded-Host) | ✅ | 3 |
| Web cache poisoning (unkeyed inputs) | ❌ | ❌ | 4 |
| Web cache deception | ❌ | ❌ | 4 |
| HTTP request smuggling (CL.TE, TE.CL, H2) | ❌ | ✅ | 4 (approval; can affect others) |
| CORS: arbitrary / null / trusted-subdomain origins | ✅ passive + active (4 origins) | ✅ | 3 |
| HTTP method override / TRACE | ❌ | ✅ (methods) | 3 |

## Access control and logic

| Issue | ProxyMind | BurpMax | Step |
|---|---|---|---|
| IDOR / broken object authorization | ✅ (differential authz, proven) | ✅ | – |
| Authentication bypass (path, header, method tricks) | ✅ step 3 (8 path tricks, rewrite and IP headers, with a control) | ✅ | 3 |
| Mass assignment | ❌ | ✅ | 4 (approval) |
| Race conditions | ✅ (Repeater race, single-packet) | ✅ | 4 (as a scan check) |
| JWT (none alg, weak secret, kid/jku) | ❌ | ✅ | 4 |
| OAuth / OIDC (redirect_uri, state, PKCE) | ❌ | ✅ | 4 |
| GraphQL (introspection, batching, depth) | 🟡 (introspection, passive) | ✅ | 4 |
| Hidden parameters (param mining) | ✅ step 3 (70 names, reflection or difference, bisected) | ✅ | 3 |

## Information disclosure and configuration (mostly passive)

| Issue | ProxyMind | BurpMax | Step |
|---|---|---|---|
| Sensitive files (VCS, env, backups, dumps) | ✅ (content discovery) | ✅ | – |
| Verbose errors / stack traces | ✅ | ✅ | – |
| Secrets in responses | ✅ | ✅ | – |
| Cookie flags (Secure, HttpOnly, SameSite) | ✅ | ✅ | – |
| Security headers (CSP, HSTS, nosniff, framing) | ✅ | ✅ | – |
| Software version disclosure | ✅ | ✅ | – |
| Cleartext credentials | ✅ | ✅ | – |
| Cacheable sensitive responses | ❌ | ✅ | 3 |
| Directory listing | ✅ | ❌ | – |
| Private IPs / cloud metadata in responses | ❌ | ✅ | 3 |
| Rate limiting absent on login | ❌ | ✅ | 4 |

## Scanner engine

| Capability | ProxyMind | BurpMax | Step |
|---|---|---|---|
| Insertion points: query, form, JSON, numeric/ID path segments | ✅ | ✅ | – |
| Insertion points: headers (User-Agent, Referer, X-Forwarded-For) and cookies | ✅ step 1 | ✅ (headers) | 1 |
| Insertion points: parameter names, XML, nested/encoded values (base64, JSON in a param) | ❌ | 🟡 (XML, JSON walk) | 3 |
| Confirmation: re-send, baseline-absent, delay follows payload | ✅ step 1 | ✅ | 1 |
| Proof oracles (differential authz, timing, OAST, browser reflection) | ✅ | ❌ | – |
| Ordering fast → slow, request budget | ✅ step 1 | ✅ | 1 |
| Policy gate, approvals, audit for every probe | ✅ | ❌ | – |
| Session handling during scans | ✅ (rules, macros) | ✅ (health monitor) | – |
| Scan checkpoint / resume | ❌ | ✅ | 4 |
| WAF evasion encodings | ❌ | ✅ | 4 |
| Backslash-powered (payload-free) anomaly detection | ❌ | ❌ | 4 |
| Crawl + audit as one scan task with live progress | 🟡 (crawl and scan separate) | ✅ | 3 |

## Steps

1. **SQL injection** (error, boolean and time based; parameters, headers,
   cookies), **command injection** (output and time based), more template
   engines; confirmation rules and fast-to-slow ordering. *(done)*
2. **Out-of-band** through ProxyMind's own OAST server: blind SSRF, XXE,
   OOB SQL and command injection, blind template injection, Log4Shell,
   code injection. *(done: every probe carries its own token; callbacks are
   collected while the slower checks run)*
3. Stored and DOM XSS, CSRF, Host header, active CORS, NoSQL/LDAP/XPath,
   CRLF, auth bypass, hidden parameters, richer insertion points, one
   crawl-and-audit task. *(3a done: NoSQL/LDAP/XPath, CRLF, Host header,
   CORS, auth bypass, hidden parameters; 3b next: stored and DOM XSS, CSRF,
   insertion points, crawl-and-audit)*
4. JWT, OAuth, GraphQL depth, request smuggling, cache poisoning and
   deception, prototype pollution, deserialization, file upload, mass
   assignment, race checks: the risky ones behind approval.

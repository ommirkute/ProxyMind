//! The issue library: one entry per kind of issue ProxyMind reports, with
//! what it is, why it matters, how to fix it, and its CWE and OWASP Top 10
//! (2021) / API Security Top 10 (2023) categories. Reports and the UI fill
//! findings in from here. The text is ProxyMind's own.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct IssueType {
    /// Stable id, e.g. `sqli`.
    pub id: &'static str,
    pub name: &'static str,
    /// Typical severity: critical, high, medium, low or info.
    pub severity: &'static str,
    pub cwe: &'static [u32],
    /// OWASP Top 10 2021 category, e.g. `A03:2021 Injection`.
    pub owasp: &'static str,
    /// OWASP API Security Top 10 2023 category, when one fits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owasp_api: Option<&'static str>,
    /// Other names: scanner check ids and finding classes that mean this.
    pub aliases: &'static [&'static str],
    pub background: &'static str,
    pub impact: &'static str,
    pub remediation: &'static str,
    pub references: &'static [&'static str],
}

const A01: &str = "A01:2021 Broken Access Control";
const A02: &str = "A02:2021 Cryptographic Failures";
const A03: &str = "A03:2021 Injection";
const A04: &str = "A04:2021 Insecure Design";
const A05: &str = "A05:2021 Security Misconfiguration";
const A07: &str = "A07:2021 Identification and Authentication Failures";
const A08: &str = "A08:2021 Software and Data Integrity Failures";
const A10: &str = "A10:2021 Server-Side Request Forgery";
const API1: Option<&str> = Some("API1:2023 Broken Object Level Authorization");
const API2: Option<&str> = Some("API2:2023 Broken Authentication");
const API3: Option<&str> = Some("API3:2023 Broken Object Property Level Authorization");
const API4: Option<&str> = Some("API4:2023 Unrestricted Resource Consumption");
const API5: Option<&str> = Some("API5:2023 Broken Function Level Authorization");
const API6: Option<&str> = Some("API6:2023 Unrestricted Access to Sensitive Business Flows");
const API7: Option<&str> = Some("API7:2023 Server Side Request Forgery");
const API8: Option<&str> = Some("API8:2023 Security Misconfiguration");

macro_rules! issue {
    ($id:expr, $name:expr, $sev:expr, [$($cwe:expr),*], $owasp:expr, $api:expr, [$($alias:expr),*],
     $bg:expr, $impact:expr, $fix:expr, [$($r:expr),*]) => {
        IssueType {
            id: $id,
            name: $name,
            severity: $sev,
            cwe: &[$($cwe),*],
            owasp: $owasp,
            owasp_api: $api,
            aliases: &[$($alias),*],
            background: $bg,
            impact: $impact,
            remediation: $fix,
            references: &[$($r),*],
        }
    };
}

pub static LIBRARY: &[IssueType] = &[
    // ---- injection -------------------------------------------------------
    issue!(
        "sqli",
        "SQL injection",
        "high",
        [89],
        A03,
        None,
        ["sql_error", "sql_boolean", "sql_time", "sql_oob", "sql_injection"],
        "Input is placed into a SQL statement as code rather than as a value, so characters such as quotes change \
         the statement's meaning.",
        "An attacker can read or change data they shouldn't reach, bypass logins, and on some databases run \
         commands on the server.",
        "Use parameterised queries (prepared statements) for every value, including ones from headers and \
         cookies. Where an identifier must vary, choose it from a fixed list. Give the application's database \
         account only the rights it needs.",
        [
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ]
    ),
    issue!(
        "nosqli",
        "NoSQL injection",
        "high",
        [943],
        A03,
        None,
        ["nosql_error", "nosql_operator", "nosql_injection"],
        "Input reaches a document-database query as structure: objects such as {\"$ne\": null} or operator \
         strings are read as query operators instead of plain values.",
        "Filters can be turned off, letting an attacker log in without a password or read other users' records.",
        "Check the type of every value before it reaches a query (a string must be a string), reject keys \
         starting with $ or containing dots, and use the driver's typed query builders.",
        ["https://cwe.mitre.org/data/definitions/943.html"]
    ),
    issue!(
        "ldap_injection",
        "LDAP injection",
        "high",
        [90],
        A03,
        None,
        ["ldap_error"],
        "Input is placed into an LDAP search filter without escaping, so characters such as *, ( and ) change \
         the filter.",
        "Authentication checks can be bypassed and directory data read.",
        "Escape filter values with the library's LDAP escaping function, or build filters with an API that \
         takes values separately.",
        [
            "https://cwe.mitre.org/data/definitions/90.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html"
        ]
    ),
    issue!(
        "xpath_injection",
        "XPath injection",
        "high",
        [643],
        A03,
        None,
        ["xpath_error"],
        "Input is placed into an XPath expression as code.",
        "An attacker can read parts of the XML document they shouldn't, or bypass checks built on it.",
        "Use parameterised XPath (variables bound by the library) or strictly validate input before use.",
        ["https://cwe.mitre.org/data/definitions/643.html"]
    ),
    issue!(
        "command_injection",
        "OS command injection",
        "critical",
        [78],
        A03,
        None,
        ["cmd_injection", "cmd_time", "cmd_oob", "os_command_injection"],
        "Input becomes part of a shell command, so characters such as ; | $( ) or backticks run further commands.",
        "Full control of the server process: reading files and secrets, changing data, and moving further into \
         the network.",
        "Don't call a shell. Use APIs that take the program and its arguments as a list, validate arguments \
         against an allow-list, and run the process with the fewest rights possible.",
        [
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
        ]
    ),
    issue!(
        "code_injection",
        "Code injection",
        "critical",
        [94],
        A03,
        None,
        ["code_oob", "eval_injection"],
        "Input is evaluated as program code (eval, expression languages, dynamic imports).",
        "An attacker can run their own code inside the application.",
        "Never evaluate input. Replace eval-style features with a parser for the small language you need.",
        ["https://cwe.mitre.org/data/definitions/94.html"]
    ),
    issue!(
        "ssti",
        "Server-side template injection",
        "critical",
        [1336, 94],
        A03,
        None,
        ["ssti_oob", "template_injection"],
        "Input is used as part of a template's source rather than as data passed to it, so template syntax such \
         as {{7*7}} is evaluated.",
        "Most template engines give access to the host language: this usually leads to running code on the server.",
        "Pass input to templates only as variables. If users must write templates, use a sandboxed, logic-less \
         engine.",
        ["https://cwe.mitre.org/data/definitions/1336.html"]
    ),
    issue!(
        "xxe",
        "XML external entity injection",
        "high",
        [611],
        A05,
        None,
        ["xxe_oob"],
        "The XML parser resolves external entities and document type definitions supplied in the request.",
        "Files on the server can be read, internal systems reached, and the parser made to hang.",
        "Turn off DTD processing and external entity resolution in every XML parser the application uses.",
        [
            "https://cwe.mitre.org/data/definitions/611.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"
        ]
    ),
    issue!(
        "ssrf",
        "Server-side request forgery",
        "high",
        [918],
        A10,
        API7,
        ["ssrf_oob"],
        "The server fetches a URL or connects to a host that the request controls.",
        "An attacker can reach internal services and cloud metadata endpoints from the server's network \
         position, often exposing credentials.",
        "Allow only the destinations the feature needs, resolve and check the address before connecting (and on \
         every redirect), and block private, loopback and link-local ranges.",
        [
            "https://cwe.mitre.org/data/definitions/918.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
        ]
    ),
    issue!(
        "rce",
        "Remote code execution through a vulnerable library (Log4Shell)",
        "critical",
        [917, 502],
        A08,
        None,
        ["log4shell"],
        "A logging or expression library evaluates lookup syntax found in logged input, such as ${jndi:…}.",
        "Code can be loaded and run on the server from an attacker's host.",
        "Upgrade the library to a fixed version, remove the lookup feature, and stop outbound connections the \
         server doesn't need.",
        ["https://cwe.mitre.org/data/definitions/917.html"]
    ),
    issue!(
        "path_traversal",
        "Path traversal",
        "high",
        [22],
        A01,
        None,
        ["directory_traversal", "lfi"],
        "Input is used to build a file path, and sequences such as ../ leave the intended folder.",
        "Files outside the folder can be read (configuration, keys, source), and sometimes written.",
        "Map input to files through an index or id, not a path. If paths are unavoidable, resolve them and check \
         the result stays inside the base folder.",
        ["https://cwe.mitre.org/data/definitions/22.html"]
    ),
    issue!(
        "open_redirect",
        "Open redirect",
        "low",
        [601],
        A01,
        None,
        [],
        "The application redirects to a URL taken from the request without checking where it leads.",
        "Phishing links look like they belong to the trusted site, and OAuth flows can leak tokens to another host.",
        "Redirect only to relative paths or to an allow-list of destinations; refuse anything else.",
        [
            "https://cwe.mitre.org/data/definitions/601.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
        ]
    ),
    issue!(
        "crlf",
        "HTTP header injection (CRLF)",
        "medium",
        [93, 113],
        A03,
        None,
        ["header_injection", "response_splitting"],
        "Carriage return and line feed characters in input reach a response header, adding new headers or a body.",
        "Attackers can set cookies, poison caches or inject content into responses.",
        "Reject control characters in any value placed in a header; modern frameworks do this if you use their \
         header APIs.",
        ["https://cwe.mitre.org/data/definitions/113.html"]
    ),
    issue!(
        "host_header",
        "Host header trusted",
        "medium",
        [644],
        A05,
        None,
        ["host_header_injection"],
        "The application uses the Host or X-Forwarded-Host header to build links or decide where to send people.",
        "Password-reset links and cached pages can point to an attacker's host.",
        "Build absolute URLs from configuration, not request headers, and accept only known host names.",
        ["https://cwe.mitre.org/data/definitions/644.html"]
    ),
    // ---- cross-site ------------------------------------------------------
    issue!(
        "xss",
        "Cross-site scripting (reflected)",
        "medium",
        [79],
        A03,
        None,
        ["reflected_input", "reflected_xss"],
        "Input from the request is placed in the page without encoding for where it lands (HTML, attribute, \
         script or URL).",
        "Script runs in a victim's browser as the site: sessions can be hijacked and actions taken as the user.",
        "Encode output for its context (use the template engine's auto-escaping), avoid building HTML by string \
         concatenation, and add a Content-Security-Policy as a second layer.",
        [
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ]
    ),
    issue!(
        "stored_xss",
        "Cross-site scripting (stored)",
        "high",
        [79],
        A03,
        None,
        [],
        "Input saved by one request is later shown, unencoded, on a page other users see.",
        "Every visitor of the page runs the attacker's script, without clicking a crafted link.",
        "Encode on output in every place the stored value is shown; sanitise rich text with a maintained HTML \
         sanitiser.",
        ["https://cwe.mitre.org/data/definitions/79.html"]
    ),
    issue!(
        "dom_xss",
        "Cross-site scripting (DOM-based)",
        "medium",
        [79],
        A03,
        None,
        [],
        "Page scripts take a value from the URL (query, fragment) and pass it to a dangerous sink such as \
         innerHTML, document.write or eval.",
        "Script runs in the victim's browser as the site, often without the server ever seeing the payload.",
        "Use textContent and safe DOM APIs instead of HTML sinks, and consider Trusted Types to block unsafe \
         sinks.",
        ["https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"]
    ),
    issue!(
        "csrf",
        "Cross-site request forgery",
        "medium",
        [352],
        A01,
        None,
        ["xsrf"],
        "A state-changing request authenticated by cookies is accepted when it comes from another site.",
        "A page on any site can make a logged-in victim's browser change their settings, data or money.",
        "Require an anti-CSRF token or a custom header on state-changing requests, check Origin, and set \
         session cookies with SameSite=Lax or Strict.",
        [
            "https://cwe.mitre.org/data/definitions/352.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
        ]
    ),
    issue!(
        "cors",
        "CORS policy too permissive",
        "medium",
        [942],
        A05,
        API8,
        ["cors_reflected_origin", "cors_null_origin", "cors_wildcard_credentials", "cors_misconfiguration"],
        "The server allows other origins (any origin, the null origin, or whichever origin asks) to read \
         responses, sometimes with credentials.",
        "A malicious site can read a logged-in user's data through their browser.",
        "Allow only the exact origins that need access, never reflect the Origin header, and don't combine \
         credentials with broad origins.",
        ["https://cwe.mitre.org/data/definitions/942.html"]
    ),
    // ---- access control and authentication -------------------------------
    issue!(
        "idor",
        "Broken object level authorization (IDOR)",
        "high",
        [639],
        A01,
        API1,
        ["bola", "insecure_direct_object_reference"],
        "The application returns or changes an object chosen by an id in the request without checking that it \
         belongs to the caller.",
        "Any user can read or change other users' records by changing the id.",
        "Check ownership or permission on every object access, server side, ideally in one shared data-access \
         layer; unguessable ids help but are not a fix.",
        [
            "https://cwe.mitre.org/data/definitions/639.html",
            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
        ]
    ),
    issue!(
        "bfla",
        "Broken function level authorization",
        "high",
        [285],
        A01,
        API5,
        ["privilege_escalation", "broken_function_level_authorization", "missing_function_level_access_control"],
        "A function meant for one role (for example administration) is reachable by users with a lower role.",
        "Ordinary users can perform privileged actions.",
        "Deny by default and check the caller's role on the server for every function, not only by hiding it \
         in the interface.",
        ["https://cwe.mitre.org/data/definitions/285.html"]
    ),
    issue!(
        "auth_bypass",
        "Access control bypass",
        "high",
        [288, 863],
        A01,
        API5,
        [],
        "A page that is denied normally answers when the path is written differently or a rewrite header is \
         added (for example /admin/. or X-Original-URL).",
        "Protected functions can be reached without the required rights.",
        "Make access decisions on the normalised path the application actually serves, and ignore rewrite \
         headers unless they come from your own proxy.",
        ["https://cwe.mitre.org/data/definitions/288.html"]
    ),
    issue!(
        "broken_authentication",
        "Broken authentication",
        "high",
        [287],
        A07,
        API2,
        ["authn", "authentication"],
        "Authentication can be skipped, guessed or reused, for example a sensitive function that needs no \
         login or a token that is never checked.",
        "Attackers act as other users.",
        "Require authentication on every sensitive endpoint, check tokens fully, and limit guessing with rate \
         limits and lockouts.",
        [
            "https://cwe.mitre.org/data/definitions/287.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
        ]
    ),
    issue!(
        "jwt",
        "Weak JSON Web Token validation",
        "high",
        [347, 1391],
        A02,
        API2,
        ["json_web_token"],
        "Tokens are accepted with a changed or missing signature, the none algorithm, or a signing secret that \
         is easy to guess.",
        "Anyone can forge tokens for any user or role.",
        "Verify the signature with a fixed algorithm, reject alg none, and use a long random secret or an \
         asymmetric key kept out of the code.",
        [
            "https://cwe.mitre.org/data/definitions/347.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"
        ]
    ),
    issue!(
        "oauth",
        "OAuth flow weakness",
        "medium",
        [601, 352],
        A07,
        API2,
        ["redirect_uri", "oauth_state"],
        "The authorisation endpoint accepts redirect URIs that weren't registered, or the flow works without a \
         state value.",
        "Authorisation codes or tokens can be sent to an attacker, or a victim logged into the attacker's account.",
        "Compare redirect_uri exactly against registered values, require and check state (or PKCE) on every flow.",
        ["https://datatracker.ietf.org/doc/html/rfc9700"]
    ),
    issue!(
        "weak_cookie",
        "Session cookie without protective attributes",
        "low",
        [614, 1004],
        A05,
        None,
        ["cookie_flags"],
        "A session-like cookie is set without Secure, HttpOnly or SameSite.",
        "The cookie can leak over plain HTTP, be read by injected script, or be sent with cross-site requests.",
        "Set Secure, HttpOnly and SameSite (Lax or Strict) on session cookies.",
        ["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"]
    ),
    issue!(
        "password_over_http",
        "Password sent over plain HTTP",
        "medium",
        [319],
        A02,
        None,
        [],
        "A login or password form is served or submitted without TLS.",
        "Anyone on the network path can read the password.",
        "Serve the whole site over HTTPS and redirect HTTP to it; add HSTS.",
        ["https://cwe.mitre.org/data/definitions/319.html"]
    ),
    issue!(
        "mass_assignment",
        "Mass assignment",
        "high",
        [915],
        A01,
        API3,
        ["autobinding"],
        "The server copies every field of the request into an object, including ones the user shouldn't set \
         such as role or isAdmin.",
        "Users can raise their own rights or change protected properties.",
        "Bind only an explicit allow-list of fields for each operation (separate input models), never the \
         whole request.",
        [
            "https://cwe.mitre.org/data/definitions/915.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"
        ]
    ),
    // ---- data exposure and configuration ---------------------------------
    issue!(
        "exposure",
        "Sensitive data exposure",
        "medium",
        [200],
        A01,
        API3,
        ["data_exposure", "information_exposure"],
        "A response contains data the caller has no need for: other users' details, internal fields, metrics \
         or files.",
        "Personal data, secrets or internal details reach people who shouldn't see them.",
        "Return only the fields each caller needs (explicit response models), and keep internal endpoints off \
         the public interface.",
        ["https://cwe.mitre.org/data/definitions/200.html"]
    ),
    issue!(
        "secret_in_response",
        "Secret or key in a response",
        "high",
        [798, 200],
        A02,
        None,
        [],
        "An API key, token or private key appears in a response.",
        "The secret can be used against the service it belongs to.",
        "Remove the secret from responses and client code, rotate it, and keep secrets in a server-side store.",
        ["https://cwe.mitre.org/data/definitions/798.html"]
    ),
    issue!(
        "verbose_error",
        "Verbose error message",
        "low",
        [209],
        A05,
        None,
        ["stack_trace", "sql_error_message"],
        "Errors show stack traces, queries or internal paths.",
        "Attackers learn the technology and code paths, which helps other attacks.",
        "Show a generic error to users and log the detail on the server.",
        ["https://cwe.mitre.org/data/definitions/209.html"]
    ),
    issue!(
        "version_disclosure",
        "Software version disclosed",
        "info",
        [497],
        A05,
        None,
        [],
        "Headers name the server software and its exact version.",
        "Attackers can look up known vulnerabilities for that version.",
        "Remove or shorten version headers (Server, X-Powered-By) and keep the software up to date.",
        ["https://cwe.mitre.org/data/definitions/497.html"]
    ),
    issue!(
        "directory_listing",
        "Directory listing",
        "low",
        [548],
        A05,
        None,
        [],
        "The web server lists the files in a folder.",
        "Files that weren't meant to be linked (backups, configuration) become easy to find.",
        "Turn off directory listing in the server configuration.",
        ["https://cwe.mitre.org/data/definitions/548.html"]
    ),
    issue!(
        "missing_csp",
        "No Content-Security-Policy",
        "info",
        [693],
        A05,
        None,
        ["weak_csp", "content_security_policy"],
        "Pages are served without a Content-Security-Policy, or with one that allows inline or any script.",
        "Cross-site scripting, if present, is easier to exploit.",
        "Add a policy that allows scripts only from your own origin (with nonces or hashes for inline code).",
        ["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"]
    ),
    issue!(
        "clickjacking",
        "Page can be framed (clickjacking)",
        "low",
        [1021],
        A05,
        None,
        ["missing_clickjacking_protection"],
        "Pages can be shown inside a frame on another site.",
        "Users can be tricked into clicking buttons on the framed page.",
        "Send Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: DENY).",
        ["https://cwe.mitre.org/data/definitions/1021.html"]
    ),
    issue!(
        "missing_nosniff",
        "No X-Content-Type-Options",
        "info",
        [693],
        A05,
        None,
        [],
        "Responses don't send X-Content-Type-Options: nosniff.",
        "Browsers may guess a different content type, which can turn uploads into script.",
        "Send X-Content-Type-Options: nosniff on every response.",
        []
    ),
    issue!(
        "missing_hsts",
        "No HTTP Strict Transport Security",
        "low",
        [319],
        A02,
        None,
        ["hsts"],
        "HTTPS responses don't send Strict-Transport-Security.",
        "A network attacker can downgrade a first visit to plain HTTP.",
        "Send Strict-Transport-Security with a long max-age (and includeSubDomains when possible).",
        ["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"]
    ),
    issue!(
        "graphql",
        "GraphQL hardening missing",
        "low",
        [200, 770],
        A05,
        API8,
        ["graphql_introspection", "graphql_batching"],
        "The GraphQL endpoint allows introspection, query batching, field suggestions or queries over GET.",
        "Attackers map the whole schema, and batching lets them get around rate limits (for example for \
         guessing codes).",
        "Turn off introspection and suggestions in production, limit batching, depth and cost, and accept \
         mutations only over POST.",
        ["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"]
    ),
    issue!(
        "hidden_params",
        "Hidden parameter accepted",
        "info",
        [912],
        A04,
        None,
        ["hidden_parameter"],
        "The application reacts to a parameter that isn't used by its own pages (for example debug or admin).",
        "Hidden switches can turn on debugging or skip checks.",
        "Remove unused parameters and debug switches from production code.",
        ["https://cwe.mitre.org/data/definitions/912.html"]
    ),
    // ---- caching, parsing and logic --------------------------------------
    issue!(
        "cache_poisoning",
        "Web cache poisoning",
        "high",
        [349],
        A05,
        None,
        [],
        "A header the cache doesn't key on (such as X-Forwarded-Host) changes the response, and the changed \
         response is cached for everyone.",
        "Every visitor can be served attacker-controlled content or script.",
        "Don't use unkeyed headers to build responses, or add them to the cache key; cache only what is the \
         same for everyone.",
        ["https://cwe.mitre.org/data/definitions/349.html"]
    ),
    issue!(
        "cache_deception",
        "Web cache deception",
        "high",
        [524],
        A05,
        None,
        [],
        "A private page answers on a path that looks static (/account/x.css), so a shared cache stores it.",
        "Another user's private page can be read from the cache.",
        "Cache by content type and Cache-Control from the application, not by file extension; mark private \
         pages Cache-Control: no-store.",
        ["https://cwe.mitre.org/data/definitions/524.html"]
    ),
    issue!(
        "prototype_pollution",
        "Prototype pollution",
        "high",
        [1321],
        A08,
        None,
        ["proto_pollution"],
        "Merging request data into objects lets keys such as __proto__ or constructor.prototype change the \
         prototype every object inherits from.",
        "Properties appear on every object: checks can be bypassed and, in some code, script can run.",
        "Use maps or objects without a prototype for user keys, block __proto__, constructor and prototype \
         keys, and use safe merge functions.",
        ["https://cwe.mitre.org/data/definitions/1321.html"]
    ),
    issue!(
        "deserialization",
        "Insecure deserialization",
        "critical",
        [502],
        A08,
        None,
        ["insecure_deserialization"],
        "The application turns serialised objects from the request (Java, PHP, pickle, .NET, Ruby) back into \
         objects.",
        "Crafted objects can run code on the server or change application state.",
        "Don't deserialise untrusted data into native objects; use plain data formats such as JSON with a fixed \
         schema, or sign the data.",
        [
            "https://cwe.mitre.org/data/definitions/502.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"
        ]
    ),
    issue!(
        "request_smuggling",
        "HTTP request smuggling",
        "high",
        [444],
        A05,
        None,
        ["desync"],
        "The front-end proxy and the back-end server disagree on where a request ends (Content-Length against \
         Transfer-Encoding).",
        "Attackers can prefix other users' requests, bypass front-end controls and poison caches.",
        "Use HTTP/2 end to end where possible, make the front end reject ambiguous requests, and keep proxy and \
         server software current.",
        ["https://cwe.mitre.org/data/definitions/444.html"]
    ),
    issue!(
        "file_upload",
        "Unrestricted file upload",
        "high",
        [434],
        A04,
        None,
        ["unrestricted_upload"],
        "Uploaded files keep a dangerous type (HTML, SVG, server script) and are served from the site's origin.",
        "Uploads can run script for visitors or code on the server.",
        "Check type by content, store uploads outside the web root or on another domain, rename them, and \
         serve them with Content-Disposition: attachment.",
        [
            "https://cwe.mitre.org/data/definitions/434.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
        ]
    ),
    issue!(
        "race_condition",
        "Race condition",
        "medium",
        [362],
        A04,
        API6,
        ["race", "toctou"],
        "A one-time action (redeeming a code, spending a balance) can be done several times by sending the \
         requests at the same moment.",
        "Limits can be exceeded: discounts reused, balances overdrawn.",
        "Make the check and the change one atomic step (a database constraint, a transaction with the right \
         isolation, or a lock).",
        ["https://cwe.mitre.org/data/definitions/362.html"]
    ),
    issue!(
        "rate_limiting",
        "No rate limiting",
        "medium",
        [307, 770],
        A07,
        API4,
        ["brute_force", "rate_limit"],
        "Sensitive endpoints such as login, reset codes or expensive searches accept unlimited requests.",
        "Passwords and codes can be guessed, and the service overloaded.",
        "Limit attempts per account and per client, add backoff, and alert on bursts.",
        ["https://cwe.mitre.org/data/definitions/307.html"]
    ),
    issue!(
        "business_logic",
        "Business logic flaw",
        "medium",
        [840],
        A04,
        API6,
        ["logic"],
        "The application's rules can be broken by using its features in an unexpected order or with unexpected \
         values.",
        "Depends on the flow: free goods, skipped steps, or actions taken for other users.",
        "Enforce each business rule on the server at the step that changes state, and test the flow with abuse \
         cases.",
        ["https://cwe.mitre.org/data/definitions/840.html"]
    ),
];

fn norm(s: &str) -> String {
    s.trim().to_ascii_lowercase().replace([' ', '-', '.'], "_")
}

/// The library entry for a finding class or scanner check id (any of an
/// entry's names, case and separators ignored).
pub fn lookup(class: &str) -> Option<&'static IssueType> {
    let c = norm(class);
    if c.is_empty() {
        return None;
    }
    LIBRARY.iter().find(|i| i.id == c || i.aliases.iter().any(|a| *a == c))
}

/// One CWE id as a link.
pub fn cwe_url(id: u32) -> String {
    format!("https://cwe.mitre.org/data/definitions/{id}.html")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_aliases_are_unique_and_lookups_work() {
        let mut seen = std::collections::HashSet::new();
        for i in LIBRARY {
            assert!(seen.insert(i.id), "duplicate {}", i.id);
            for a in i.aliases {
                assert!(seen.insert(a), "duplicate alias {a}");
            }
            assert!(["critical", "high", "medium", "low", "info"].contains(&i.severity), "{}", i.id);
            assert!(!i.cwe.is_empty() && i.owasp.starts_with('A'), "{}", i.id);
        }
        assert_eq!(lookup("SQL-Error").map(|i| i.id), Some("sqli"));
        assert_eq!(lookup("proto_pollution").map(|i| i.id), Some("prototype_pollution"));
        assert_eq!(lookup("reflected_input").map(|i| i.id), Some("xss"));
        assert!(lookup("something new").is_none());
    }

    #[test]
    fn every_check_has_an_entry() {
        let passive = [
            "graphql_introspection",
            "missing_csp",
            "weak_csp",
            "missing_clickjacking_protection",
            "missing_nosniff",
            "missing_hsts",
            "weak_cookie",
            "cors_null_origin",
            "cors_reflected_origin",
            "cors_wildcard_credentials",
            "version_disclosure",
            "verbose_error",
            "secret_in_response",
            "directory_listing",
            "password_over_http",
        ];
        let active = crate::active::CHECKS.iter().chain(crate::oob::CHECKS).chain(passive.iter());
        for c in active.chain(["nosql_error", "ldap_error", "xpath_error", "exposure", "idor", "bfla"].iter()) {
            assert!(lookup(c).is_some(), "no library entry for {c}");
        }
    }
}

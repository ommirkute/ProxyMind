//! Payload-aware tiers: what a request *does*, not just its method.
//!
//! A `GET /search?q=1;DROP TABLE users` is as dangerous as a DELETE. The
//! classifier normalises the request target and body (percent-decoding,
//! repeatedly; `+` as space; JSON `\uXXXX` escapes; SQL comments and runs of
//! whitespace collapsed; lowercase) and looks for destructive SQL, OS
//! commands, file writes and bulk actions. The gate takes the higher of the
//! method's tier and the payload's.
//!
//! It is deliberately conservative: a false alarm only means a human is
//! asked; a miss could mean damage. It is a safety net, not a WAF, and
//! never lowers a tier.

use crate::Tier;

/// The tier a payload calls for, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadClass {
    pub tier: Tier,
    pub reasons: Vec<String>,
}

impl PayloadClass {
    fn none() -> Self {
        PayloadClass { tier: Tier::Read, reasons: Vec::new() }
    }

    fn raise(&mut self, tier: Tier, reason: String) {
        self.tier = self.tier.max(tier);
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }
}

/// Destructive SQL. Each pattern is matched against normalised text where
/// every separator (space, tab, newline, comment, `+`) is a single space.
const SQL_DESTRUCTIVE: &[(&str, &str)] = &[
    ("drop table", "DROP TABLE"),
    ("drop database", "DROP DATABASE"),
    ("drop schema", "DROP SCHEMA"),
    ("drop user", "DROP USER"),
    ("drop index", "DROP INDEX"),
    ("drop view", "DROP VIEW"),
    ("truncate table", "TRUNCATE TABLE"),
    ("delete from", "DELETE FROM"),
    ("alter table", "ALTER TABLE"),
    ("alter user", "ALTER USER"),
    ("grant all", "GRANT ALL"),
    ("into outfile", "INTO OUTFILE (file write)"),
    ("into dumpfile", "INTO DUMPFILE (file write)"),
    ("xp_cmdshell", "xp_cmdshell (OS command)"),
    ("lo_export", "lo_export (file write)"),
    ("shutdown with nowait", "SHUTDOWN"),
];

/// SQL that changes data but is a common, bounded probe.
const SQL_WRITE: &[(&str, &str)] =
    &[("insert into", "INSERT INTO"), ("update ", "UPDATE … SET"), ("merge into", "MERGE INTO")];

/// OS commands that destroy data or stop the machine.
const OS_DESTRUCTIVE: &[(&str, &str)] = &[
    ("rm -rf", "rm -rf"),
    ("rm -fr", "rm -rf"),
    ("rm -r ", "rm -r"),
    ("rm -f ", "rm -f"),
    ("rmdir /s", "rmdir /s"),
    ("del /f", "del /f"),
    ("del /q", "del /q"),
    ("format c:", "format c:"),
    ("mkfs", "mkfs"),
    ("dd if=", "dd"),
    ("shred ", "shred"),
    ("shutdown -", "shutdown"),
    ("shutdown /", "shutdown"),
    ("reboot", "reboot"),
    ("halt -", "halt"),
    ("poweroff", "poweroff"),
    ("kill -9", "kill -9"),
    ("killall", "killall"),
    (":(){", "fork bomb"),
    ("chmod -r", "recursive chmod"),
    ("chown -r", "recursive chown"),
    ("> /etc/", "write to /etc"),
    (">/etc/", "write to /etc"),
    ("> /var/", "write to /var"),
    ("> /usr/", "write to /usr"),
    ("> c:\\", "write to C:\\"),
    ("crontab ", "crontab"),
    ("drop-database", "drop-database"),
    ("flushall", "Redis FLUSHALL"),
    ("flushdb", "Redis FLUSHDB"),
];

/// Signs of OS-command injection (execution, even if harmless).
const OS_EXEC: &[(&str, &str)] = &[
    ("$(", "$( ) command substitution"),
    (";id", "; id"),
    ("; id", "; id"),
    ("|id", "| id"),
    ("| id", "| id"),
    ("&&id", "&& id"),
    ("&& id", "&& id"),
    ("whoami", "whoami"),
    ("/bin/sh", "/bin/sh"),
    ("/bin/bash", "/bin/bash"),
    ("cmd.exe", "cmd.exe"),
    ("powershell", "powershell"),
    ("nslookup ", "nslookup"),
    ("wget ", "wget"),
    ("curl ", "curl"),
    ("nc -e", "netcat"),
    ("system(", "system()"),
    ("exec(", "exec()"),
    ("passthru(", "passthru()"),
    ("runtime.getruntime", "Runtime.exec"),
];

/// Bulk actions: one request that touches many objects.
const BULK: &[(&str, &str)] = &[
    ("/bulk", "bulk endpoint"),
    ("/batch", "batch endpoint"),
    ("deleteall", "delete-all action"),
    ("delete_all", "delete-all action"),
    ("delete-all", "delete-all action"),
    ("purge", "purge action"),
    ("wipe", "wipe action"),
    ("all=true", "all=true"),
    ("all=1", "all=1"),
    ("\"all\": true", "\"all\": true"),
    ("recursive=true", "recursive=true"),
    ("force=true", "force=true"),
    ("cascade", "CASCADE"),
];

/// Classifies a raw HTTP request (HTTP/1.x or HTTP/2 text). Headers other
/// than the request line are not examined: cookies and tokens are not
/// payloads, and testers put probes in the target or body.
pub fn classify_http(raw: &[u8]) -> PayloadClass {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = match text.find("\r\n\r\n").or_else(|| text.find("\n\n")) {
        Some(i) => (&text[..i], text[i..].trim_start_matches(['\r', '\n'])),
        None => (&text[..], ""),
    };
    let first = head.lines().next().unwrap_or("");
    // The target is everything between the method and the version, so a
    // target with raw spaces in it is read whole.
    let (method, rest) = first.split_once(' ').unwrap_or((first, ""));
    let method = method.to_ascii_uppercase();
    let target = rest.rsplit_once(" HTTP/").map_or(rest, |(t, _)| t);
    let mut c = classify_text(&format!("{target}\n{body}"));
    // Bulk via many ids: ?ids=1,2,3,… or a long JSON array of numbers.
    let ids = longest_id_list(&normalise(&format!("{target}\n{body}")));
    if ids >= 50 {
        c.raise(Tier::ActiveIntrusive, format!("bulk action: {ids} ids in one request"));
    }
    // Frameworks that honour a method override run another method than
    // the request line says: a POST with `X-HTTP-Method-Override: DELETE`
    // or `_method=DELETE` deletes.
    let mut method = method;
    if let Some(m) = method_override(head, &normalise(&format!("{target}&{body}"))) {
        let tier = crate::Tier::for_http_method(&m);
        if tier > crate::Tier::for_http_method(&method) {
            c.raise(tier, format!("method override to {m}"));
        }
        method = m;
    }
    // A bulk action that also deletes is destructive.
    if method == "DELETE" && c.reasons.iter().any(|r| r.starts_with("bulk")) {
        c.raise(Tier::Destructive, "bulk delete".into());
    }
    c
}

/// The method a request asks the server to use instead of its own:
/// `X-HTTP-Method-Override`, `X-HTTP-Method` or `X-Method-Override` headers,
/// or a `_method` parameter (Rails, Laravel). `params` is the normalised
/// target and body.
fn method_override(head: &str, params: &str) -> Option<String> {
    const HEADERS: &[&str] = &["x-http-method-override", "x-http-method", "x-method-override"];
    for line in head.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':')
            && HEADERS.contains(&name.trim().to_ascii_lowercase().as_str())
        {
            let v = value.trim().to_ascii_uppercase();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    let at = params.find("_method=")?;
    let v: String = params[at + "_method=".len()..].chars().take_while(|c| c.is_ascii_alphabetic()).collect();
    (!v.is_empty()).then(|| v.to_ascii_uppercase())
}

/// Classifies free text (a WebSocket message, a body).
pub fn classify_text(text: &str) -> PayloadClass {
    let n = normalise(text);
    let squeezed: String = n.chars().filter(|c| !c.is_whitespace()).collect();
    let mut c = PayloadClass::none();
    // A pattern with spaces also matches with the spaces taken out
    // (`drop/**/table` normalises to `droptable`), but only when it is long
    // enough not to match ordinary words.
    let has =
        |pat: &str| n.contains(pat) || (pat.contains(' ') && pat.len() > 6 && squeezed.contains(&pat.replace(' ', "")));
    for (pat, name) in SQL_DESTRUCTIVE {
        if has(pat) {
            c.raise(Tier::Destructive, format!("destructive SQL: {name}"));
        }
    }
    for (pat, name) in SQL_WRITE {
        if n.contains(pat) && (*pat != "update " || n.contains(" set ")) {
            c.raise(Tier::ActiveIntrusive, format!("SQL write: {name}"));
        }
    }
    for (pat, name) in OS_DESTRUCTIVE {
        if n.contains(pat) {
            c.raise(Tier::Destructive, format!("destructive OS command: {name}"));
        }
    }
    for (pat, name) in OS_EXEC {
        if n.contains(pat) || (!pat.contains(' ') && squeezed.contains(pat)) {
            c.raise(Tier::ActiveIntrusive, format!("OS command injection: {name}"));
        }
    }
    if n.contains('`') && n.matches('`').count() >= 2 {
        c.raise(Tier::ActiveIntrusive, "OS command injection: backticks".into());
    }
    for (pat, name) in BULK {
        if n.contains(pat) {
            c.raise(Tier::ActiveIntrusive, format!("bulk action: {name}"));
        }
    }
    // GraphQL mutations that delete.
    if n.contains("mutation") && (n.contains("delete") || n.contains("remove") || n.contains("destroy")) {
        c.raise(Tier::Destructive, "GraphQL mutation that deletes".into());
    }
    c
}

/// Lowercased text with encodings undone and separators collapsed.
pub fn normalise(text: &str) -> String {
    let mut s = text.to_string();
    // Percent-decoding up to three times defeats double/triple encoding.
    for _ in 0..3 {
        let d = percent_decode(&s);
        if d == s {
            break;
        }
        s = d;
    }
    s = json_unescape(&s);
    let lower = s.to_lowercase();
    // SQL comments (/* … */, -- and #) and '+' become separators.
    let mut out = String::with_capacity(lower.len());
    let mut chars = lower.chars().peekable();
    let mut last_space = false;
    while let Some(ch) = chars.next() {
        let sep = match ch {
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut prev = ' ';
                for c in chars.by_ref() {
                    if prev == '*' && c == '/' {
                        break;
                    }
                    prev = c;
                }
                true
            }
            '+' | '\u{a0}' => true,
            c if c.is_whitespace() || c.is_control() => true,
            _ => false,
        };
        if sep {
            if !last_space {
                out.push(' ');
            }
            last_space = true;
        } else {
            out.push(ch);
            last_space = false;
        }
    }
    out
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if b[i] == b'%'
            && let (Some(h), Some(l)) = (b.get(i + 1).copied().and_then(hex), b.get(i + 2).copied().and_then(hex))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Undoes JSON escapes (`\uXXXX`, `\t`, `\n`, `\/`, …) and `\xNN` escapes.
fn json_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('\\') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let parse =
            |n: usize| tail.get(2..2 + n).and_then(|h| u32::from_str_radix(h, 16).ok()).and_then(char::from_u32);
        if tail.starts_with("\\u")
            && let Some(c) = parse(4)
        {
            out.push(c);
            rest = &tail[6..];
        } else if tail.starts_with("\\x")
            && let Some(c) = parse(2)
        {
            out.push(c);
            rest = &tail[4..];
        } else if let Some(c) = tail.chars().nth(1).and_then(|c| match c {
            't' | 'n' | 'r' | 'f' | 'b' => Some(' '),
            '/' => Some('/'),
            _ => None,
        }) {
            out.push(c);
            rest = &tail[2..];
        } else {
            out.push('\\');
            rest = &tail[1..];
        }
    }
    out.push_str(rest);
    out
}

/// Length of the longest list of numbers separated by commas.
fn longest_id_list(n: &str) -> usize {
    let mut best = 0;
    let mut run = 0;
    for part in n.split(',') {
        let t = part.trim().trim_matches(|c| c == '"' || c == '[' || c == ']');
        let numeric_end = t.rsplit(|c: char| !c.is_ascii_digit()).next().unwrap_or("");
        let numeric_start = t.split(|c: char| !c.is_ascii_digit()).next().unwrap_or("");
        if !numeric_end.is_empty() && (t.chars().all(|c| c.is_ascii_digit()) || run == 0) {
            run += 1;
        } else if !numeric_start.is_empty() && run > 0 {
            run += 1;
            best = best.max(run);
            run = 0;
            continue;
        } else {
            run = 0;
        }
        best = best.max(run);
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tier(raw: &str) -> Tier {
        classify_http(raw.as_bytes()).tier
    }
    fn get(target: &str) -> String {
        format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n")
    }
    fn post(body: &str) -> String {
        format!("POST /api HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{body}")
    }

    #[test]
    fn plain_requests_are_untouched() {
        for r in [
            get("/api/products?q=coffee"),
            get("/search?q=table+tennis+dropdown"),
            get("/api/orders/1001"),
            post(r#"{"name":"alice","note":"update my address"}"#),
            get("/static/app.js"),
            post(r#"{"ids":[1,2,3]}"#),
        ] {
            assert_eq!(tier(&r), Tier::Read, "{r}");
        }
    }

    #[test]
    fn destructive_sql_in_every_disguise() {
        for t in [
            "/s?q=1;DROP TABLE users--",
            "/s?q=1;DrOp%20TaBlE%20users",
            "/s?q=1;drop/**/table/**/users",
            "/s?q=1;drop%09table%0ausers",
            "/s?q=1;drop+table+users",
            "/s?q=1%253Bdrop%2520table%2520users", // double-encoded
            "/s?q=1%25253Bdrop%252520table",       // triple-encoded
            "/s?q=x';TRUNCATE TABLE logs;--",
            "/s?q=x' UNION SELECT 1 INTO OUTFILE '/var/www/x.php'--",
            "/s?q=1;EXEC xp_cmdshell 'dir'",
            "/s?q=1;DELETE%20FROM%20users",
            "/s?q=1;droptable", // squeezed spaces still caught for long patterns
        ] {
            assert_eq!(tier(&get(t)), Tier::Destructive, "{t}");
        }
        assert_eq!(tier(&post(r#"{"q":"x\u0027; DROP\u0020TABLE users"}"#)), Tier::Destructive);
        assert_eq!(tier(&post(r#"{"q":"1; delete\tfrom accounts"}"#)), Tier::Destructive);
    }

    #[test]
    fn os_commands() {
        assert_eq!(tier(&get("/ping?host=127.0.0.1;rm%20-rf%20/")), Tier::Destructive);
        assert_eq!(tier(&get("/ping?host=x%26%26shutdown%20-h%20now")), Tier::Destructive);
        assert_eq!(tier(&post(r#"{"cmd":"echo hi > /etc/passwd"}"#)), Tier::Destructive);
        assert_eq!(tier(&post(r#"{"cmd":"FLUSHALL"}"#)), Tier::Destructive);
        for t in ["/ping?host=x;id", "/ping?host=x|whoami", "/ping?host=$(id)", "/ping?host=`id`", "/x?h=x%7Cid"] {
            assert_eq!(tier(&get(t)), Tier::ActiveIntrusive, "{t}");
        }
    }

    #[test]
    fn writes_and_bulk_actions() {
        assert_eq!(tier(&get("/s?q=1;INSERT INTO users VALUES(1)")), Tier::ActiveIntrusive);
        assert_eq!(tier(&get("/s?q=1;UPDATE users SET role='admin'")), Tier::ActiveIntrusive);
        assert_eq!(tier(&get("/api/users/bulk")), Tier::ActiveIntrusive);
        assert_eq!(tier(&get("/api/items?all=true")), Tier::ActiveIntrusive);
        let many: Vec<String> = (1..=60).map(|i| i.to_string()).collect();
        assert_eq!(tier(&get(&format!("/api/items?ids={}", many.join(",")))), Tier::ActiveIntrusive);
        assert_eq!(tier(&post(&format!("{{\"ids\":[{}]}}", many.join(",")))), Tier::ActiveIntrusive);
        let del = format!("DELETE /api/items/bulk HTTP/1.1\r\nHost: x\r\n\r\n{{\"ids\":[{}]}}", many.join(","));
        assert_eq!(tier(&del), Tier::Destructive);
        assert_eq!(tier(&post(r#"{"query":"mutation { deleteUser(id: 1) { id } }"}"#)), Tier::Destructive);
    }

    #[test]
    fn reasons_name_what_was_found() {
        let c = classify_http(get("/s?q=1;drop%20table%20x").as_bytes());
        assert_eq!(c.reasons, vec!["destructive SQL: DROP TABLE".to_string()]);
    }

    #[test]
    fn normalisation() {
        assert_eq!(normalise("A%2520B"), "a b");
        assert_eq!(normalise("x/*c*/y\t\nz"), "x y z");
        assert_eq!(normalise(r"\u0041\x42"), "ab");
        assert_eq!(normalise("100%"), "100%");
        assert_eq!(normalise("%zz"), "%zz");
    }

    #[test]
    fn method_overrides_count() {
        let t = |raw: &str| classify_http(raw.as_bytes()).tier;
        assert_eq!(t("POST /api/users/7 HTTP/1.1\r\nX-HTTP-Method-Override: DELETE\r\n\r\n"), Tier::Destructive);
        assert_eq!(t("POST /api/users/7 HTTP/1.1\r\nx-method-override: delete\r\n\r\n"), Tier::Destructive);
        assert_eq!(
            t("POST /users/7 HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n_method=delete&x=1"),
            Tier::Destructive
        );
        assert_eq!(t("POST /users/7?_method=DELETE HTTP/1.1\r\n\r\n"), Tier::Destructive);
        assert_eq!(t("GET /x HTTP/1.1\r\nX-HTTP-Method-Override: PUT\r\n\r\n"), Tier::ActiveIntrusive);
        assert_eq!(t("POST /x HTTP/1.1\r\nX-HTTP-Method-Override: GET\r\n\r\n"), Tier::Read, "never lowers");
    }
}

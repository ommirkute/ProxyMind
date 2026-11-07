//! DOM testing on a recorded page (no I/O here; the service renders it
//! offline in a headless browser with every request blocked). Each source a
//! page reads gets its own marker; hooks report the markers that reach a
//! dangerous sink, with the call stack. A second render tries prototype
//! pollution through the URL.

use serde::Serialize;

use crate::active::dom_dangerous;

/// The sources a run seeds, each with its own marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Markers {
    pub base: String,
}

pub const SOURCES: &[(&str, &str)] = &[
    ("q", "URL query"),
    ("h", "URL fragment"),
    ("n", "window.name"),
    ("m", "postMessage"),
    ("s", "web storage"),
    ("p", "URL parameter (read by name)"),
];

impl Markers {
    pub fn new(base: &str) -> Self {
        Self { base: base.to_string() }
    }

    /// The marker for one source (`q`, `h`…), with characters that tell
    /// whether markup survives (`<pmx`).
    pub fn of(&self, source: &str) -> String {
        format!("{}{source}x", self.base)
    }

    /// The URL to render: the page with a marker in the query and the fragment.
    pub fn url(&self, page: &str) -> String {
        let (no_hash, _) = page.split_once('#').unwrap_or((page, ""));
        let sep = if no_hash.contains('?') { '&' } else { '?' };
        format!("{no_hash}{sep}pm={}%3Cpmx%3E#{}<pmx>", self.of("q"), self.of("h"))
    }
}

/// JavaScript run before the page's scripts: seeds the sources and reports
/// `{sink, value, stack}` when a marker reaches a sink.
pub fn hooks(m: &Markers, binding: &str, storage: bool) -> String {
    let base = serde_json::to_string(&m.base).unwrap_or_default();
    let b = serde_json::to_string(binding).unwrap_or_default();
    let name = serde_json::to_string(&format!("{}<pmx>", m.of("n"))).unwrap_or_default();
    let msg = serde_json::to_string(&format!("{}<pmx>", m.of("m"))).unwrap_or_default();
    let param = serde_json::to_string(&m.of("p")).unwrap_or_default();
    let store = serde_json::to_string(&m.of("s")).unwrap_or_default();
    format!(
        r#"(() => {{
  const M = {base}, B = {b};
  const report = (sink, v) => {{
    try {{
      const s = String(v);
      if (!s.includes(M) || typeof window[B] !== 'function') return;
      const stack = String(new Error().stack || '').split('\n').slice(2, 6).map(l => l.trim()).join(' | ');
      window[B](JSON.stringify({{ sink, value: s.slice(0, 300), stack: stack.slice(0, 400) }}));
    }} catch (e) {{}}
  }};
  const setter = (proto, prop, sink) => {{
    try {{
      const d = Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.set) return;
      Object.defineProperty(proto, prop, {{ ...d, set(v) {{ report(sink, v); return d.set.call(this, v); }} }});
    }} catch (e) {{}}
  }};
  const wrap = (obj, name, sink, pick) => {{
    try {{
      const f = obj[name];
      if (typeof f !== 'function') return;
      obj[name] = function (...a) {{ report(sink, pick(a)); return f.apply(this, a); }};
    }} catch (e) {{}}
  }};
  setter(Element.prototype, 'innerHTML', 'innerHTML');
  setter(Element.prototype, 'outerHTML', 'outerHTML');
  setter(HTMLIFrameElement.prototype, 'srcdoc', 'iframe.srcdoc');
  setter(HTMLScriptElement.prototype, 'src', 'script.src');
  setter(HTMLScriptElement.prototype, 'text', 'script.text');
  setter(HTMLAnchorElement.prototype, 'href', 'a.href');
  setter(HTMLFormElement.prototype, 'action', 'form.action');
  wrap(Element.prototype, 'insertAdjacentHTML', 'insertAdjacentHTML', a => a[1]);
  wrap(Element.prototype, 'setAttribute', 'setAttribute', a => /^(on|href$|src$|action$|srcdoc$)/i.test(String(a[0])) ? a[1] : '');
  wrap(document, 'write', 'document.write', a => a.join(''));
  wrap(document, 'writeln', 'document.writeln', a => a.join(''));
  wrap(Range.prototype, 'createContextualFragment', 'createContextualFragment', a => a[0]);
  wrap(window, 'eval', 'eval', a => a[0]);
  wrap(window, 'setTimeout', 'setTimeout', a => typeof a[0] === 'string' ? a[0] : '');
  wrap(window, 'setInterval', 'setInterval', a => typeof a[0] === 'string' ? a[0] : '');
  wrap(window, 'open', 'window.open', a => a[0]);
  wrap(Location.prototype, 'assign', 'location.assign', a => a[0]);
  wrap(Location.prototype, 'replace', 'location.replace', a => a[0]);
  try {{
    const F = window.Function;
    window.Function = function (...a) {{ report('Function', a.join(',')); return F.apply(this, a); }};
  }} catch (e) {{}}
  // Sources.
  try {{ window.name = {name}; }} catch (e) {{}}
  try {{
    const get = URLSearchParams.prototype.get;
    URLSearchParams.prototype.get = function (k) {{
      const v = get.call(this, k);
      return v === null ? {param} + ':' + String(k).slice(0, 40) + '<pmx>' : v;
    }};
  }} catch (e) {{}}
  if ({storage}) {{
    try {{
      const gi = Storage.prototype.getItem;
      Storage.prototype.getItem = function (k) {{
        const v = gi.call(this, k);
        return v === null ? {store} + ':' + String(k).slice(0, 40) + '<pmx>' : v;
      }};
    }} catch (e) {{}}
  }}
  window.addEventListener('load', () => {{
    setTimeout(() => {{
      try {{ window.postMessage({msg}, '*'); }} catch (e) {{}}
      try {{ window.postMessage({{ data: {msg}, message: {msg}, html: {msg}, url: {msg} }}, '*'); }} catch (e) {{}}
      try {{ window.postMessage(JSON.stringify({{ data: {msg} }}), '*'); }} catch (e) {{}}
    }}, 50);
  }});
}})();"#
    )
}

/// A marker that reached a sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Flow {
    pub source: String,
    /// The parameter or storage key, for sources read by name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    pub sink: String,
    /// What reached the sink (from the page: untrusted).
    pub value: String,
    pub stack: String,
    /// Markup survived into an HTML sink, any value reached a code sink, or
    /// a `javascript:` URL reached a navigation sink.
    pub exploitable: bool,
}

/// The flows in the binding calls of a render with [`hooks`].
pub fn flows(calls: &[String], m: &Markers) -> Vec<Flow> {
    let mut out: Vec<Flow> = Vec::new();
    for c in calls {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(c) else { continue };
        let (Some(sink), Some(value)) = (v["sink"].as_str(), v["value"].as_str()) else { continue };
        let stack = v["stack"].as_str().unwrap_or_default().to_string();
        for (code, label) in SOURCES {
            let marker = m.of(code);
            let Some(at) = value.find(&marker) else { continue };
            let key = (["p", "s"].contains(code))
                .then(|| {
                    value[at + marker.len()..]
                        .strip_prefix(':')
                        .map(|r| r.split("<pmx").next().unwrap_or(r).to_string())
                })
                .flatten();
            // Keyed sources carry ":<key>" between the marker and the markup.
            let full = key.as_ref().map_or_else(|| marker.clone(), |k| format!("{marker}:{k}"));
            let exploitable = dom_dangerous(sink, value, &full);
            let f = Flow {
                source: (*label).into(),
                key,
                sink: sink.into(),
                value: value.into(),
                stack: stack.clone(),
                exploitable,
            };
            if !out.iter().any(|x| x.source == f.source && x.key == f.key && x.sink == f.sink) {
                out.push(f);
            }
        }
    }
    out.sort_by_key(|f| !f.exploitable);
    out
}

/// Prototype pollution through the URL: the page with each technique in the
/// query and the fragment, and a check run after load.
pub const POLLUTION: &[(&str, &str)] = &[
    ("query __proto__[x]", "?__proto__[pmpp]=polluted"),
    ("query __proto__.x", "?__proto__.pmpp=polluted"),
    ("query constructor[prototype][x]", "?constructor[prototype][pmpp]=polluted"),
    ("fragment __proto__[x]", "#__proto__[pmpp]=polluted"),
    ("fragment __proto__.x", "#__proto__.pmpp=polluted"),
];

pub fn pollution_url(page: &str, technique: &str) -> String {
    let (no_hash, _) = page.split_once('#').unwrap_or((page, ""));
    match technique.strip_prefix('?') {
        Some(q) => {
            let sep = if no_hash.contains('?') { '&' } else { '?' };
            format!("{no_hash}{sep}{q}")
        }
        None => format!("{no_hash}{technique}"),
    }
}

/// Reports through `binding` whether `Object.prototype.pmpp` was set after load.
pub fn pollution_check(binding: &str) -> String {
    let b = serde_json::to_string(binding).unwrap_or_default();
    format!(
        r#"(() => {{
  const B = {b};
  const check = () => {{ try {{ if (({{}}).pmpp === 'polluted' && typeof window[B] === 'function') window[B]('polluted'); }} catch (e) {{}} }};
  window.addEventListener('load', () => {{ check(); setTimeout(check, 400); }});
}})();"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_and_flows() {
        let m = Markers::new("pmd1");
        assert_eq!(m.url("https://a.test/p?x=1#old"), "https://a.test/p?x=1&pm=pmd1qx%3Cpmx%3E#pmd1hx<pmx>");
        let calls = vec![
            r#"{"sink":"innerHTML","value":"Welcome back, pmd1px:name<pmx>!","stack":"at welcome.js:2"}"#.to_string(),
            r#"{"sink":"a.href","value":"/next?u=pmd1qx","stack":""}"#.to_string(),
            r#"{"sink":"eval","value":"go('pmd1mx<pmx>')","stack":""}"#.to_string(),
            "not json".to_string(),
        ];
        let f = flows(&calls, &m);
        assert_eq!(f.len(), 3);
        assert_eq!(
            (f[0].source.as_str(), f[0].key.as_deref(), f[0].sink.as_str()),
            ("URL parameter (read by name)", Some("name"), "innerHTML")
        );
        assert!(f[0].exploitable && f[1].exploitable, "markup in innerHTML, any value in eval");
        assert!(!f[2].exploitable, "a plain value in a link isn't");
        assert_eq!(
            pollution_url("https://a.test/p?x=1#y", "?__proto__[pmpp]=polluted"),
            "https://a.test/p?x=1&__proto__[pmpp]=polluted"
        );
        assert_eq!(
            pollution_url("https://a.test/p", "#__proto__.pmpp=polluted"),
            "https://a.test/p#__proto__.pmpp=polluted"
        );
        assert!(hooks(&m, "pmProof", true).contains("Storage.prototype.getItem"));
    }
}

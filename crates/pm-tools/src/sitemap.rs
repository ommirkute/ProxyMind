//! A site map: recorded requests as a tree of origins and path segments.

use std::collections::BTreeMap;

use serde::Serialize;

/// One recorded request, as the site map needs it.
pub struct Entry<'a> {
    pub origin: &'a str,
    pub method: &'a str,
    /// Origin-form target; the query is counted, not split into nodes.
    pub path: &'a str,
    pub status: Option<u16>,
    pub id: i64,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Node {
    /// This segment (`/` for an origin's root).
    pub name: String,
    /// Path from the origin's root, e.g. `/api/orders`.
    pub path: String,
    /// Requests to exactly this path (any query).
    pub requests: usize,
    /// Requests here or below.
    pub total: usize,
    pub methods: Vec<String>,
    pub statuses: Vec<u16>,
    /// Distinct query strings seen here.
    pub queries: usize,
    /// Newest exchange for exactly this path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_id: Option<i64>,
    pub children: Vec<Node>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Site {
    pub origin: String,
    pub total: usize,
    pub root: Node,
}

#[derive(Default)]
struct Builder {
    requests: usize,
    total: usize,
    methods: BTreeMap<String, ()>,
    statuses: BTreeMap<u16, ()>,
    queries: BTreeMap<String, ()>,
    latest_id: Option<i64>,
    children: BTreeMap<String, Builder>,
}

impl Builder {
    fn finish(self, name: String, path: String) -> Node {
        let children = self
            .children
            .into_iter()
            .map(|(seg, b)| {
                let child_path = if path == "/" { format!("/{seg}") } else { format!("{path}/{seg}") };
                b.finish(seg, child_path)
            })
            .collect();
        Node {
            name,
            path,
            requests: self.requests,
            total: self.total,
            methods: self.methods.into_keys().collect(),
            statuses: self.statuses.into_keys().collect(),
            queries: self.queries.len(),
            latest_id: self.latest_id,
            children,
        }
    }
}

/// Most distinct children kept per node; the rest are folded into one `…` node.
pub const MAX_CHILDREN: usize = 500;

/// Builds the tree. Entries may come in any order.
pub fn build<'a>(entries: impl IntoIterator<Item = Entry<'a>>) -> Vec<Site> {
    let mut sites: BTreeMap<String, Builder> = BTreeMap::new();
    for e in entries {
        let (path, query) = e.path.split_once('?').unwrap_or((e.path, ""));
        let mut node = sites.entry(e.origin.to_string()).or_default();
        node.total += 1;
        for seg in path.split('/').filter(|s| !s.is_empty()) {
            let key = if node.children.len() >= MAX_CHILDREN && !node.children.contains_key(seg) {
                "…".to_string()
            } else {
                seg.to_string()
            };
            node = node.children.entry(key).or_default();
            node.total += 1;
        }
        node.requests += 1;
        node.methods.insert(e.method.to_ascii_uppercase(), ());
        if let Some(s) = e.status {
            node.statuses.insert(s, ());
        }
        if !query.is_empty() && node.queries.len() < 10_000 {
            node.queries.insert(query.to_string(), ());
        }
        node.latest_id = Some(node.latest_id.map_or(e.id, |l| l.max(e.id)));
    }
    sites
        .into_iter()
        .map(|(origin, b)| Site { total: b.total, root: b.finish("/".into(), "/".into()), origin })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_tree() {
        let rows = [
            ("http://a", "GET", "/api/orders/1?x=1", Some(200), 1),
            ("http://a", "GET", "/api/orders/1?x=2", Some(403), 5),
            ("http://a", "post", "/api/orders", Some(201), 2),
            ("http://a", "GET", "/", Some(200), 3),
            ("https://b:8443", "GET", "/login", None, 4),
        ];
        let sites =
            build(rows.iter().map(|&(origin, method, path, status, id)| Entry { origin, method, path, status, id }));
        assert_eq!(sites.len(), 2);
        let a = &sites[0];
        assert_eq!((a.origin.as_str(), a.total), ("http://a", 4));
        assert_eq!((a.root.requests, a.root.total), (1, 4));
        let api = &a.root.children[0];
        assert_eq!((api.name.as_str(), api.path.as_str(), api.requests, api.total), ("api", "/api", 0, 3));
        let orders = &api.children[0];
        assert_eq!((orders.methods.clone(), orders.requests), (vec!["POST".to_string()], 1));
        let one = &orders.children[0];
        assert_eq!(one.path, "/api/orders/1");
        assert_eq!((one.queries, one.statuses.clone(), one.latest_id), (2, vec![200, 403], Some(5)));
        assert_eq!(sites[1].root.children[0].statuses, Vec::<u16>::new());
    }

    #[test]
    fn caps_wide_nodes() {
        let paths: Vec<String> = (0..MAX_CHILDREN + 50).map(|i| format!("/u/{i}")).collect();
        let sites =
            build(paths.iter().map(|p| Entry { origin: "http://a", method: "GET", path: p, status: None, id: 1 }));
        let u = &sites[0].root.children[0];
        assert_eq!(u.children.len(), MAX_CHILDREN + 1);
        assert_eq!(u.children.iter().find(|c| c.name == "…").unwrap().total, 50);
    }
}

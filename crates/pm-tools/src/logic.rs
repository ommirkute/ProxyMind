//! Business-logic test candidates: parameters whose names suggest money,
//! quantities, discounts, limits, roles or workflow state, with the abuse
//! cases worth trying on each. Scanners can't judge these (the response is
//! a normal 200 either way); a person or an agent compares the outcome with
//! what the business allows.

use serde::Serialize;

use crate::engage::ParamSummary;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogicCandidate {
    pub param: String,
    /// price, quantity, discount, limit, identity, role, state, flow
    pub category: &'static str,
    pub paths: Vec<String>,
    pub examples: Vec<String>,
    /// Abuse cases to try.
    pub tests: Vec<&'static str>,
}

struct Rule {
    category: &'static str,
    /// Matched against the lowercased name with `_`, `-` and `.` removed.
    names: &'static [&'static str],
    tests: &'static [&'static str],
}

const RULES: &[Rule] = &[
    Rule {
        category: "price",
        names: &[
            "price", "amount", "total", "cost", "fee", "subtotal", "balance", "credit", "payment", "tip", "currency",
        ],
        tests: &[
            "send 0, a negative number and a tiny decimal (0.001)",
            "change the currency code while keeping the amount",
            "check whether the server recomputes the total or trusts this value",
        ],
    },
    Rule {
        category: "quantity",
        names: &["qty", "quantity", "count", "items", "units", "seats", "number"],
        tests: &[
            "send a negative quantity (refund-style credit)",
            "send 0, a decimal (1.5) and a very large number (overflow, stock checks)",
            "repeat the same line item in one request",
        ],
    },
    Rule {
        category: "discount",
        names: &["coupon", "voucher", "promo", "discount", "code", "giftcard", "referral", "reward", "points"],
        tests: &[
            "apply the same code twice, or in two parallel requests (race; needs approval)",
            "stack several codes, or reuse one after the order is cancelled",
            "use a code meant for another account or product",
        ],
    },
    Rule {
        category: "limit",
        names: &["limit", "max", "min", "per", "size", "pagesize", "rate", "quota", "maxattempts"],
        tests: &["raise it past the documented maximum", "send 0 or a negative value", "remove it entirely"],
    },
    Rule {
        category: "identity",
        names: &[
            "userid",
            "accountid",
            "ownerid",
            "customerid",
            "email",
            "recipient",
            "to",
            "from",
            "payee",
            "username",
        ],
        tests: &[
            "replace it with another user's value (use authz_check with a second identity)",
            "send the same value as the sender and the recipient (self-transfer)",
        ],
    },
    Rule {
        category: "role",
        names: &["role", "admin", "isadmin", "group", "permission", "plan", "tier", "level", "verified", "premium"],
        tests: &[
            "set it to a higher value (admin, premium, verified) on signup or profile update",
            "add it to a request that doesn't send it (mass assignment)",
        ],
    },
    Rule {
        category: "state",
        names: &["status", "state", "step", "stage", "approved", "paid", "confirmed", "shipped", "completed"],
        tests: &[
            "jump straight to the final state (paid, approved, shipped)",
            "move backwards after a later step (cancel after shipping, edit after payment)",
        ],
    },
];

/// Paths that are usually part of a multi-step flow.
const FLOW_WORDS: &[&str] = &[
    "cart",
    "checkout",
    "order",
    "basket",
    "payment",
    "pay",
    "transfer",
    "withdraw",
    "refund",
    "redeem",
    "invite",
    "vote",
    "subscribe",
    "booking",
    "reserve",
    "wallet",
];

fn normalize(name: &str) -> String {
    name.to_ascii_lowercase().chars().filter(|c| !matches!(c, '_' | '-' | '.' | '[' | ']')).collect()
}

/// The last segment of a bracketed or dotted name (`order[items][0][qty]` → `qty`).
fn leaf(name: &str) -> &str {
    name.rsplit(['[', '.'])
        .find(|s| !s.trim_end_matches(']').is_empty() && s.trim_end_matches(']').parse::<u64>().is_err())
        .map_or(name, |s| s.trim_end_matches(']'))
}

fn matches(rule: &Rule, n: &str) -> bool {
    rule.names.iter().any(|w| n == *w || (w.len() >= 4 && (n.ends_with(w) || n.starts_with(w))))
}

/// Candidates from the parameters traffic has shown, most promising first:
/// money and discounts before limits, and parameters sent to flow-like
/// paths (cart, checkout, transfer…) before the rest.
pub fn candidates(params: &[ParamSummary]) -> Vec<LogicCandidate> {
    let mut out: Vec<(usize, bool, LogicCandidate)> = Vec::new();
    for p in params {
        let n = normalize(leaf(&p.name));
        let Some((rank, rule)) = RULES.iter().enumerate().find(|(_, r)| matches(r, &n)) else { continue };
        let in_flow = p.paths.iter().any(|path| {
            let l = path.to_ascii_lowercase();
            FLOW_WORDS.iter().any(|w| l.contains(w))
        });
        out.push((
            rank,
            !in_flow,
            LogicCandidate {
                param: p.name.clone(),
                category: rule.category,
                paths: p.paths.clone(),
                examples: p.examples.clone(),
                tests: rule.tests.to_vec(),
            },
        ));
    }
    out.sort_by_key(|(rank, not_flow, _)| (*not_flow, *rank));
    out.into_iter().map(|(_, _, c)| c).collect()
}

/// Paths that look like steps of a multi-step flow, for step-skipping and
/// replay tests.
pub fn flow_paths<'a>(paths: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = paths
        .into_iter()
        .filter(|p| {
            let l = p.to_ascii_lowercase();
            l.split(['/', '?', '-', '_', '.', '=', '&']).any(|seg| {
                FLOW_WORDS.iter().any(|w| seg == *w || seg.strip_prefix(w).is_some_and(|r| r == "s" || r == "es"))
            })
        })
        .map(str::to_string)
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(name: &str, path: &str) -> ParamSummary {
        ParamSummary {
            name: name.into(),
            locations: vec![],
            requests: 1,
            distinct_values: 1,
            examples: vec!["1".into()],
            paths: vec![path.into()],
        }
    }

    #[test]
    fn money_in_a_flow_comes_first_and_noise_is_skipped() {
        let c = candidates(&[
            p("page_size", "/api/products"),
            p("q", "/search"),
            p("order[items][0][qty]", "/api/cart"),
            p("unit_price", "/api/cart"),
            p("couponCode", "/api/checkout"),
            p("role", "/api/users/me"),
        ]);
        let got: Vec<(&str, &str)> = c.iter().map(|c| (c.param.as_str(), c.category)).collect();
        assert_eq!(
            got,
            [
                ("unit_price", "price"),
                ("order[items][0][qty]", "quantity"),
                ("couponCode", "discount"),
                ("page_size", "limit"),
                ("role", "role"),
            ]
        );
        assert!(c[0].tests.iter().any(|t| t.contains("negative")));
    }

    #[test]
    fn flow_paths_are_found_by_segment() {
        let f = flow_paths(["/api/cart/add", "/checkout?step=2", "/static/carton.png", "/about", "/api/cart/add"]);
        assert_eq!(f, ["/api/cart/add", "/checkout?step=2"]);
    }
}

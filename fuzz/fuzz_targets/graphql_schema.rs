#![no_main]
//! GraphQL introspection results from hostile servers: never panic, and
//! example documents contain only GraphQL names and punctuation.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(doc) = serde_json::from_slice::<serde_json::Value>(data) else { return };
    if let Ok(s) = pm_graphql::parse_introspection(&doc) {
        for op in s.operations {
            // Only names, punctuation and spaces: nothing from the schema can add syntax.
            let ok = |c: char| c.is_ascii_alphanumeric() || " _${}():,![]".contains(c);
            assert!(op.document.chars().all(ok), "{}", op.document);
            let _ = pm_graphql::request("h", "/graphql", &op.document, &op.variables);
        }
    }
});

//! `cargo xtask contracts [--check]`: regenerates the committed API contracts from the Rust types
//! (ADR-0019). This crate sits above all others; nothing depends on it.
//!
//! Generated: `docs/api/openapi.json`, and the UI and SDK type files made from it (`ui/src/api-types.gen.ts`,
//! `sdk/typescript/src/types.gen.ts`, `sdk/python/proxymind/types.py`). The MCP schemas are written by `pm-mcp`.

mod py;
mod schema;
mod ts;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// One generated file: where it lives (relative to the repository root) and what it should contain.
struct Output {
    path: &'static str,
    content: String,
}

fn outputs() -> Vec<Output> {
    let defs = schema::definitions(&pm_api::contracts::openapi_document());
    let ts = ts::render(&defs);
    vec![
        Output { path: "docs/api/openapi.json", content: pm_api::contracts::openapi_json() },
        Output { path: "ui/src/api-types.gen.ts", content: ts.clone() },
        Output { path: "sdk/typescript/src/types.gen.ts", content: ts },
        Output { path: "sdk/python/proxymind/types.py", content: py::render(&defs) },
    ]
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("xtask lives in the repository root").to_path_buf()
}

fn contracts(check: bool) -> Result<(), String> {
    let root = repo_root();
    for out in outputs() {
        let path = root.join(out.path);
        if check {
            if std::fs::read_to_string(&path).ok().as_deref() != Some(out.content.as_str()) {
                return Err(format!("{} is stale: run `cargo xtask contracts`", out.path));
            }
        } else {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
            }
            std::fs::write(&path, &out.content).map_err(|e| format!("write {}: {e}", out.path))?;
            println!("wrote {}", out.path);
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["contracts"] => contracts(false),
        ["contracts", "--check"] => contracts(true),
        _ => Err("usage: cargo xtask contracts [--check]".to_string()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;

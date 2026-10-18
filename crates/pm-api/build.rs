//! Embeds the built web UI (`ui/dist`) into the binary. If it hasn't been
//! built (no Node.js), a placeholder page explains how to build it, so
//! `cargo build` always works.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, base, out);
        } else if let Ok(rel) = p.strip_prefix(base) {
            out.push((rel.to_string_lossy().replace('\\', "/"), p));
        }
    }
}

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let dist = manifest.join("../../ui/dist");
    println!("cargo:rerun-if-changed={}", dist.display());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("out dir"));
    let mut files = Vec::new();
    if dist.join("index.html").exists() {
        walk(&dist, &dist, &mut files);
        for (_, p) in &files {
            println!("cargo:rerun-if-changed={}", p.display());
        }
    } else {
        let placeholder = out_dir.join("placeholder.html");
        std::fs::write(
            &placeholder,
            "<!doctype html><html><head><meta charset=utf-8><title>ProxyMind</title></head><body \
             style=\"font-family:system-ui;max-width:40rem;margin:4rem auto;line-height:1.5\"><h1>ProxyMind</h1>\
             <p>The web UI was not built into this binary. Build it with:</p><pre>cd ui && npm ci && npm run build\
             \ncargo build --release</pre><p>The API is running: try <code>/api/v1/status</code>.</p></body></html>",
        )
        .expect("write placeholder");
        files.push(("index.html".into(), placeholder));
    }
    files.sort();
    let mut code = String::from("pub static ASSETS: &[(&str, &[u8])] = &[\n");
    for (name, path) in &files {
        let _ = writeln!(code, "    ({name:?}, include_bytes!({:?})),", path.canonicalize().unwrap_or(path.clone()));
    }
    code.push_str("];\n");
    std::fs::write(out_dir.join("assets.rs"), code).expect("write assets.rs");
}

//! ADR-0017 step 1: every use of the store goes through `StoreHandle::read` / `write`, never a raw mutex guard.

use std::path::Path;

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_raw_store_lock_in_pm_service() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(files.len() > 10, "found no sources under {}", src.display());
    let mut bad = Vec::new();
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        // Whitespace removed so that `.store\n    .lock()` is caught too.
        let squashed: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        if squashed.contains(".store.lock()") {
            bad.push(f.display().to_string());
        }
    }
    assert!(bad.is_empty(), "use store.read(|s| ..) / store.write(|s| ..) instead of store.lock(): {bad:?}");
}

#![no_main]
//! The crawler's HTML, robots.txt and sitemap readers on hostile pages.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let base = url::Url::parse("http://app.example.com/a/b").unwrap();
    let e = pm_crawl::extract(&base, &text);
    for l in e.links {
        assert!(matches!(l.scheme(), "http" | "https"));
        assert!(l.fragment().is_none());
    }
    let _ = pm_crawl::robots(&base, &text);
    let _ = pm_crawl::sitemap(&text);
});

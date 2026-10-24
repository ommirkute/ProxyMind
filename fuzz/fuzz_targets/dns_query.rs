#![no_main]
//! The OAST DNS parser and answer builder: any UDP packet from the internet.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(q) = pm_oast::dns::parse_query(data) {
        let a = pm_oast::dns::answer(data, &q, "oast.example.com", std::net::Ipv4Addr::LOCALHOST);
        assert_eq!(&a[..2], &data[..2], "the answer keeps the query id");
        let _ = pm_oast::dns::token_in(&q.name, "oast.example.com");
    }
});

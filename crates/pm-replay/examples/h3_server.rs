//! A small HTTP/3 server for the browser test: `cargo run -p pm-replay --example h3_server [127.0.0.1:0]`.
//! Prints `h3 listening on <addr>` and serves until killed. See `tests/common/h3_server.rs` for what it answers.
#[path = "../tests/common/h3_server.rs"]
mod h3_server;

#[tokio::main]
async fn main() {
    let bind = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:0".into());
    let server = h3_server::start(bind.parse().expect("an address such as 127.0.0.1:0"));
    println!("h3 listening on {}", server.addr);
    std::future::pending::<()>().await;
}

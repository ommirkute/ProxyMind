//! Manual-testing utilities, without I/O:
//!
//! - [`har`] and [`curl`]: HAR files and cURL commands, in and out.
//! - [`search`] and [`sitemap`]: matching text in history, and history as a tree.
//! - [`codec`]: encode, decode and hash, one step or a chain, and a
//!   "smart decode" that peels common layers.
//! - [`linediff`]: a line diff for the Diff tool.
//! - [`token_analyzer`]: how random a sample of tokens looks.
//! - [`reqedit`]: change a request's method or body encoding, keeping its parameters.
//! - [`engage`]: engagement tools (comments, scripts, parameters, CSRF and clickjacking pages).

pub mod codec;
pub mod codegen;
pub mod curl;
pub mod dns;
pub mod engage;
pub mod har;
pub mod hql;
pub mod linediff;
pub mod logic;
pub mod reqedit;
pub mod search;
pub mod sitemap;
pub mod token_analyzer;
pub mod wayback;

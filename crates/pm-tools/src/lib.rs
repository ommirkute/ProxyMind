//! Manual-testing utilities, without I/O:
//!
//! - [`har`] and [`curl`]: HAR files and cURL commands, in and out.
//! - [`search`] and [`sitemap`]: matching text in history, and history as a tree.
//! - [`codec`]: encode, decode and hash, one step or a chain, and a
//!   "smart decode" that peels common layers.
//! - [`linediff`]: a line diff for the comparer.
//! - [`sequencer`]: how random a sample of tokens looks.

pub mod codec;
pub mod curl;
pub mod har;
pub mod hql;
pub mod linediff;
pub mod search;
pub mod sequencer;
pub mod sitemap;

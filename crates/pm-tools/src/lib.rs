//! Manual-testing utilities, without I/O:
//!
//! - [`har`] and [`curl`]: HAR files and cURL commands, in and out.
//! - [`codec`]: encode, decode and hash, one step or a chain, and a
//!   "smart decode" that peels common layers.
//! - [`linediff`]: a line diff for the comparer.
//! - [`sequencer`]: how random a sample of tokens looks.

pub mod codec;
pub mod curl;
pub mod har;
pub mod linediff;
pub mod sequencer;

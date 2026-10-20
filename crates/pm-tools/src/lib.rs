//! Manual-testing utilities, without I/O:
//!
//! - [`codec`]: encode, decode and hash, one step or a chain, and a
//!   "smart decode" that peels common layers.
//! - [`linediff`]: a line diff for the comparer.
//! - [`sequencer`]: how random a sample of tokens looks.

pub mod codec;
pub mod linediff;
pub mod sequencer;

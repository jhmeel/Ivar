//! Consequence invariants and time locks (sections 10, 11.1).
//!
//! Limits on outcomes such as value moved, records read and destructive
//! operations per window. They work whatever technique the attacker used to
//! get in, including ones not yet known. Actions above a set value or scope
//! wait a fixed delay that any one owner can cancel; held actions count
//! against the limit, so many small queued actions cannot slip under it.

mod engine;
mod timelock;

pub use engine::{InvariantCheck, InvariantEngine, Measured};
pub use timelock::{HeldAction, TimeLockQueue, TimeLockState};

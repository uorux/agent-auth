//! End-to-end: the real binaries, the way an operator and agents use them.
//! Each test gets a fresh database (`#[sqlx::test]`, migrated by the broker
//! itself) and its own broker on a free loopback port.

// Test code: failing loudly is the point.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

mod fakes;
mod harness;
mod world;

mod a2a;
mod lifecycle;
mod mcp;
mod operations;

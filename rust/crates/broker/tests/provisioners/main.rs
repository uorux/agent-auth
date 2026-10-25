//! Provisioners against fake upstreams (rust/spec/provisioners.md §14) and
//! the wiki against a fake GitHub (a2a-wiki-desktop spec §11).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::field_reassign_with_default,
    clippy::result_large_err,
    dead_code,
    missing_debug_implementations
)]

mod common;
mod github;
mod google;
mod kubernetes;
mod lldap;
mod mcp;
mod models;
mod setup;
mod wiki;

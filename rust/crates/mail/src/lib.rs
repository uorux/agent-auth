#![forbid(unsafe_code)]
//! Mail for the broker's mail gateway: reading untrusted messages (MIME,
//! headers, HTML) into what the gateway filters on and what an agent is
//! shown, the cheap prompt-injection hints, composing what is sent, and
//! the two protocols the IMAP backend speaks (IMAP and SMTP, over TLS
//! only).
//!
//! Everything here reads text an outsider wrote. Nothing in it panics on
//! hostile input, and every allocation is bounded by the input's size
//! (which the caller caps) or by an explicit limit.

pub mod compose;
pub mod conn;
mod entities;
pub mod html;
pub mod imap;
pub mod message;
pub mod smtp;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
#[cfg(test)]
mod tests;
pub mod text;

//! Paired daemons: the pairing HTTP bodies, the WebSocket handshake, and the
//! signed channel's messages, one tagged enum per direction (daemon spec
//! §3-§5, sandboxd spec §3). The discriminator is `type`, as in the Python.
//!
//! A channel message is the body of a verified envelope minus the
//! envelope's own six keys ([`channel::ENVELOPE_KEYS`]); [`channel::parse`]
//! strips them, tells an unknown `type` (ignored, as the Python did) from a
//! malformed known one, and checks every bound.

pub mod channel;
pub mod handshake;
pub mod host;
pub mod local;
pub mod pairing;
pub mod sandbox;

pub use channel::{CallId, ChannelMessage, Heartbeat, Incoming, PromptId, Reply, parse};

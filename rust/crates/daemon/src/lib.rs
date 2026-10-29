#![forbid(unsafe_code)]
//! What hostd and sandboxd share (daemons-hostd spec §2-§4, §12): the
//! broker channel client, pairing, the broker URL rules, and the local
//! unix-socket server with peer-credential checks.
//!
//! Role-neutral: nothing here knows what a host or a sandbox does with a
//! message. A daemon implements [`channel::Handler`] and runs
//! [`channel::Channel::run`]; it serves its local API with
//! [`localsock::serve`].
//!
//! Trust runs one way: the broker's public key comes from the daemon's own
//! config, never from the network. Pairing and every connection check the
//! broker against it ([`channel::Identity`]).

pub mod channel;
pub mod localsock;
pub mod pair;
mod stream;
pub mod url;

pub use channel::{Channel, Handler, Identity};
pub use url::BrokerUrl;

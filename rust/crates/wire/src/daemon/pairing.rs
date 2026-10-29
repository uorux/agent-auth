//! `POST /v1/daemons/pair` (daemon spec §3.3): unauthenticated, proven by
//! the one-time code's HMAC.

use serde::{Deserialize, Serialize};

use crate::text::{LowerHex, Text};

/// Every refusal of a pairing is this one 403 text.
pub const PAIRING_REFUSED: &str =
    "pairing refused: no pending code for this daemon matches (expired, used, or wrong code)";

/// The daemon's request. Role, name and key are checked by the broker after
/// parsing (400 on a bad one), so here they are only bounded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairBody {
    pub role: Text<0, 16>,
    pub name: Text<0, 128>,
    /// `ed25519:<43 base64url characters>`.
    pub public_key: Text<0, 128>,
    /// `hex(HMAC(pairing key, "agent-auth/v1/pair-selector"))[:32]`.
    pub selector: LowerHex<32>,
    /// The daemon's proof of the code.
    pub proof: LowerHex<64>,
}

/// The broker's answer: its key (which the daemon compares with its pinned
/// one) and its own proof of the code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairResponse {
    pub broker_public_key: String,
    pub proof: LowerHex<64>,
    /// The daemon key's fingerprint, `xxxx:xxxx:...` (8 groups).
    pub fingerprint: String,
}

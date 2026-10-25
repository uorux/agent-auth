//! A human's approval of one request.
//!
//! [`HumanApproval`] is what the store's `Approval::human` requires: the
//! only way a request is approved without an [`crate::AutoClearance`] or an
//! [`crate::LlmClearance`]. It names the request it approves, so it cannot
//! be spent on another one.
//!
//! [`HumanApproval::attest`] may be called **only** from authenticated
//! human surfaces: the broker's auth module (a `DiscordOwner` or an
//! `AdminCaller`), the Discord and web-panel handlers, and the human
//! decision service (`crates/broker/src/{auth,discord,webui}/`,
//! `crates/broker/src/service/decide*.rs`). `scripts/check.sh` fails if it
//! appears anywhere else outside test code.

use crate::ids::RequestId;

/// A human approved `request`. Not `Clone`: one attestation, one approval.
#[derive(Debug, PartialEq, Eq)]
pub struct HumanApproval {
    decided_by: String,
    request: RequestId,
}

impl HumanApproval {
    /// Attest that the human `decided_by` approved `request`. Call only
    /// from an authenticated human surface (see the module docs; enforced
    /// by an audit step in `scripts/check.sh`).
    #[must_use]
    pub fn attest(request: RequestId, decided_by: impl Into<String>) -> HumanApproval {
        HumanApproval {
            decided_by: decided_by.into(),
            request,
        }
    }

    #[must_use]
    pub fn decided_by(&self) -> &str {
        &self.decided_by
    }

    #[must_use]
    pub fn request(&self) -> RequestId {
        self.request
    }
}

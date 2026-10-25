//! Small helpers the provisioners share.

use agent_auth_core::policy::agents::AgentRef;
use agent_auth_store::StoreError;
use agent_auth_store::agents::AgentRow;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::ProvisionError;

pub(crate) use agent_auth_core::pyfmt::repr;

/// The policy view of an agent row.
#[must_use]
pub(crate) fn agent_ref(agent: &AgentRow) -> AgentRef<'_> {
    agent.policy_ref()
}

static NULL: serde_json::Value = serde_json::Value::Null;

/// `v[path[0]][path[1]]...` without indexing: `Null` where anything is
/// missing (upstream answers are untrusted shapes).
#[must_use]
pub(crate) fn at<'a>(v: &'a serde_json::Value, path: &[&str]) -> &'a serde_json::Value {
    path.iter().try_fold(v, |v, k| v.get(k)).unwrap_or(&NULL)
}

/// A database failure inside a provisioner: logged, and reported to the
/// agent without details.
pub(crate) fn store_failed(e: &StoreError) -> ProvisionError {
    tracing::error!(error = %e, "provisioner: database error");
    ProvisionError::failed("database error (see broker logs)")
}

/// Python's `repr()` of a list of strings: `['a', 'b']`.
#[must_use]
pub(crate) fn repr_list<S: AsRef<str>>(items: &[S]) -> String {
    let inner: Vec<String> = items.iter().map(|s| repr(s.as_ref())).collect();
    format!("[{}]", inner.join(", "))
}

/// Python's `datetime.isoformat()` of an aware UTC time:
/// `2026-10-25T12:00:00.123456+00:00`, the fraction left out when zero.
#[must_use]
pub(crate) fn py_isoformat(t: OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    let base = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    if t.microsecond() == 0 {
        format!("{base}+00:00")
    } else {
        format!("{base}.{:06}+00:00", t.microsecond())
    }
}

/// An RFC 3339 timestamp from an upstream (GitHub, Kubernetes), in UTC.
#[must_use]
pub(crate) fn parse_time(text: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(text, &Rfc3339)
        .ok()
        .map(|t| t.to_offset(time::UtcOffset::UTC))
}

/// The first `n` characters of an upstream body, for the broker's log only.
#[must_use]
pub(crate) fn head(body: &[u8], n: usize) -> String {
    String::from_utf8_lossy(body).chars().take(n).collect()
}

/// Whole seconds from `now` until `then` (negative when past).
#[must_use]
pub(crate) fn secs_until(then: OffsetDateTime, now: OffsetDateTime) -> i64 {
    then.unix_timestamp().saturating_sub(now.unix_timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn isoformat_like_python() {
        assert_eq!(
            py_isoformat(datetime!(2026-10-25 12:00:00.123456 UTC)),
            "2026-10-25T12:00:00.123456+00:00"
        );
        assert_eq!(
            py_isoformat(datetime!(2026-10-25 12:00:00 UTC)),
            "2026-10-25T12:00:00+00:00"
        );
    }

    #[test]
    fn list_repr() {
        assert_eq!(repr_list(&["view", "edit"]), "['view', 'edit']");
        assert_eq!(repr_list::<&str>(&[]), "[]");
    }
}

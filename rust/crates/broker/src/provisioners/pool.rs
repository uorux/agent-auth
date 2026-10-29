//! Platform `pool`: scarce things an agent holds alone for a while
//! (accounts, licences, devices), e.g. a pool of Minecraft accounts
//! (upstream `provisioners/pool.py`).
//!
//! Capability `lease`, resource the pool, scope one of: `{}` or
//! `{"match": {...}}` (any free item whose properties match, the one this
//! agent held last first), `{"previous": true}` (the item held last), or
//! `{"item": "<name>"}` (that item).
//!
//! The item is chosen when the grant is provisioned (an approval may come
//! long after the request) and held by a `pool_leases` row whose unique
//! `(pool, item, slot)` and `(pool, agent_id, agent_slot)` keep an item
//! within its capacity and an agent within `max_per_agent` whatever races.
//! Provisions of one pool are serialized by an advisory lock, and a lease
//! is inserted `ON CONFLICT DO NOTHING`, so a lost race moves on to the
//! next slot or item instead of failing the transaction. The grant's
//! resource stays the pool (rules match on it); which item it holds is in
//! its `provisioner_state`.
//!
//! Sensitive items are never picked by "any" or "previous": they are
//! leased by name, and always by a human (`Authority::is_sensitive`).
//!
//! What it does not do: a credential handed out can be kept. Exclusivity
//! is the broker's bookkeeping; an item whose secret must stop working at
//! the end of a lease needs rotating outside the broker.

use std::collections::{BTreeMap, BTreeSet};

use agent_auth_core::canonical_json;
use agent_auth_core::policy::agents::{AgentPattern, AgentRef};
use agent_auth_core::policy::schema::{PoolConfig, PoolItem};
use agent_auth_core::pool::{PoolChoice, PropMatch, PropValue, matches};
use agent_auth_core::{Authority, Platform};
use agent_auth_crypto::Secret;
use agent_auth_store::agents::{self, AgentRow};
use agent_auth_store::grants::{GrantRow, IssuableGrant, ProvisioningGrant};
use agent_auth_store::pool::{self as store_pool, LeaseRow, NewLease};
use agent_auth_store::{StoreError, Tx};
use agent_auth_wire::agent::CREDENTIAL_VALUE_MAX;
use agent_auth_wire::catalog::{PoolEntry, PoolItemEntry};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;

use super::common::{agent_ref, repr, store_failed};
use super::{
    Credential, CredentialKind, ProvisionError, Provisioner, Refused, RequestSpec, Validated,
};

/// How often a provision re-reads the leases after a lost insert.
const TRIES: usize = 8;

fn admitted(patterns: &[AgentPattern], agent: &AgentRef<'_>) -> bool {
    patterns.is_empty() || patterns.iter().any(|p| p.matches(agent))
}

fn match_value(m: &PropMatch) -> Value {
    Value::Object(m.iter().map(|(k, v)| (k.clone(), v.to_json())).collect())
}

fn props_value(props: &BTreeMap<String, PropValue>) -> Map<String, Value> {
    props
        .iter()
        .map(|(k, v)| (k.clone(), v.to_json()))
        .collect()
}

/// Python's `datetime.isoformat(timespec="minutes")` of a UTC time:
/// `2026-10-25T14:30+00:00`.
#[must_use]
pub fn iso_minutes(t: OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}+00:00",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute()
    )
}

/// An `io::Error` as Python's `strerror` (no `(os error N)`).
fn strerror(e: &std::io::Error) -> String {
    let text = e.to_string();
    match text.find(" (os error ") {
        Some(i) => text.get(..i).unwrap_or(&text).to_owned(),
        None => text,
    }
}

/// The largest secret file a pool item may have: what a credential's value
/// may carry, plus the one trailing newline that is dropped.
#[allow(clippy::as_conversions)] // usize to u64 cannot truncate
const MAX_SECRET_FILE: u64 = CREDENTIAL_VALUE_MAX as u64 + 1;

fn too_large(item: &str) -> ProvisionError {
    ProvisionError::failed(format!(
        "the secret of {item} is larger than {CREDENTIAL_VALUE_MAX} bytes, the most a credential carries; ask the operator to shorten it"
    ))
}

/// An item's secret file, without its trailing newline, read with a bound
/// (the Python read any size; a value over the wire cap was a 500 at
/// fetch, and a huge file filled the broker's memory).
async fn read_secret(item: &str, path: &str) -> Result<Secret<String>, ProvisionError> {
    let owned = path.to_owned();
    let read = tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut text = String::new();
        std::fs::File::open(&owned)?
            .take(MAX_SECRET_FILE.saturating_add(1))
            .read_to_string(&mut text)?;
        Ok::<_, std::io::Error>(Secret::new(text))
    })
    .await;
    let text = match read {
        Ok(Ok(text)) => text,
        Ok(Err(e)) => {
            return Err(ProvisionError::failed(format!(
                "cannot read the secret of {item} ({})",
                strerror(&e)
            )));
        }
        Err(e) => {
            tracing::error!(error = %e, item, "reading a pool secret did not finish");
            return Err(ProvisionError::failed(format!(
                "cannot read the secret of {item} (see broker logs)"
            )));
        }
    };
    let whole = text.expose();
    let text = Secret::new(whole.strip_suffix('\n').unwrap_or(whole).to_owned());
    if text.expose().len() > CREDENTIAL_VALUE_MAX {
        return Err(too_large(item));
    }
    Ok(text)
}

/// Refuse, at provisioning, an item whose secret file is already too
/// large to hand out, so the request fails with the reason instead of
/// becoming a grant whose credential never comes. (A missing or
/// unreadable file is left to the fetch, as before: it may appear later.)
async fn check_secret_size(item: &str, path: &str) -> Result<(), ProvisionError> {
    if path.is_empty() {
        return Ok(());
    }
    match tokio::fs::metadata(path).await {
        Ok(m) if m.len() > MAX_SECRET_FILE => Err(too_large(item)),
        _ => Ok(()),
    }
}

#[derive(Debug, Clone)]
pub struct PoolProvisioner {
    pools: BTreeMap<String, PoolConfig>,
}

impl PoolProvisioner {
    #[must_use]
    pub fn new(pools: &BTreeMap<String, PoolConfig>) -> PoolProvisioner {
        PoolProvisioner {
            pools: pools.clone(),
        }
    }

    /// Items "any" may pick for this agent: not sensitive, admitted,
    /// matching (in name order).
    fn eligible(pool: &PoolConfig, agent: &AgentRef<'_>, m: &PropMatch) -> Vec<String> {
        pool.items
            .iter()
            .filter(|(_, item)| {
                !item.sensitive && admitted(&item.agents, agent) && matches(&item.properties, m)
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    fn holders(leases: &[LeaseRow]) -> BTreeMap<&str, Vec<&LeaseRow>> {
        let mut out: BTreeMap<&str, Vec<&LeaseRow>> = BTreeMap::new();
        for l in leases {
            out.entry(l.item.as_str()).or_default().push(l);
        }
        out
    }

    async fn validate_spec(
        &self,
        tx: &Tx<'_>,
        spec: RequestSpec<'_>,
    ) -> Result<Result<Validated, Refused>, StoreError> {
        let refuse = |text: String| Ok(Err(Refused(text)));
        let name = spec.resource.trim().to_lowercase();
        let Some(pool) = self.pools.get(&name) else {
            let known: Vec<&str> = self.pools.keys().map(String::as_str).collect();
            let known = if known.is_empty() {
                "none".to_owned()
            } else {
                known.join(", ")
            };
            return refuse(format!("no pool {} (there is: {known})", repr(&name)));
        };
        let agent = agent_ref(spec.agent);
        if !admitted(&pool.agents, &agent) {
            return refuse(format!(
                "pool {} is not open to {}",
                repr(&name),
                spec.agent.name
            ));
        }
        let Authority::Pool(choice) = &spec.authority else {
            return refuse("pool capability is \"lease\"".to_owned());
        };
        let held_last = store_pool::last_held(tx, spec.agent.id, &name, None).await?;
        let leases = store_pool::leases(tx, &name).await?;
        let holders = Self::holders(&leases);
        let capacity = usize::try_from(pool.capacity).unwrap_or(usize::MAX);
        let free = |n: &str| holders.get(n).map_or(0, Vec::len) < capacity;
        let in_use = |n: &str| if free(n) { "" } else { " (in use now)" };
        let mut notes = Vec::new();
        match choice {
            PoolChoice::Item(item) => {
                let Some(spec_item) = pool.items.get(item) else {
                    let has: Vec<&str> = pool.items.keys().map(String::as_str).collect();
                    return refuse(format!(
                        "pool {name} has no item {} (it has: {})",
                        repr(item),
                        has.join(", ")
                    ));
                };
                if !admitted(&spec_item.agents, &agent) {
                    return refuse(format!(
                        "{item} of pool {name} is not for {}",
                        spec.agent.name
                    ));
                }
                notes.push(format!(
                    "{item} of pool {name}, by name{}{}",
                    in_use(item),
                    if spec_item.sensitive {
                        " — a sensitive item"
                    } else {
                        ""
                    }
                ));
            }
            PoolChoice::Previous => {
                let Some(last) = &held_last else {
                    return refuse(format!(
                        "you have not held an item of pool {name} before: ask for any (no scope, or a \"match\")"
                    ));
                };
                let usable = pool
                    .items
                    .get(last)
                    .is_some_and(|i| !i.sensitive && admitted(&i.agents, &agent));
                if !usable {
                    return refuse(format!(
                        "{last}, the item you held last, can't be leased again this way"
                    ));
                }
                notes.push(format!(
                    "{last} of pool {name} again (held last){}",
                    in_use(last)
                ));
            }
            PoolChoice::Any(m) => {
                let candidates = Self::eligible(pool, &agent, m);
                if candidates.is_empty() {
                    return refuse(if m.is_empty() {
                        format!("pool {name} has no item for you")
                    } else {
                        format!(
                            "no item of pool {name} matches {}",
                            canonical_json::to_python_default_string(&match_value(m))
                        )
                    });
                }
                let free_now = candidates.iter().filter(|c| free(c)).count();
                let mut note = format!("any item of pool {name}");
                if !m.is_empty() {
                    note.push_str(&format!(
                        " matching {}",
                        canonical_json::to_python_default_string(&match_value(m))
                    ));
                }
                note.push_str(&format!(": {free_now} of {} free now", candidates.len()));
                if let Some(last) = &held_last
                    && candidates.contains(last)
                {
                    note.push_str(&format!("; held {last} last"));
                }
                notes.push(note);
            }
        }
        // Not a refusal: the agent may give one back before this is decided.
        let mine = leases
            .iter()
            .filter(|l| l.agent_id == spec.agent.id)
            .count();
        if mine >= usize::try_from(pool.max_per_agent).unwrap_or(usize::MAX) {
            notes.push(format!(
                "{} already holds {mine} of pool {name} (at most {}): this fails unless one is released first",
                spec.agent.name, pool.max_per_agent
            ));
        }
        Ok(Ok(Validated {
            resource: name,
            authority: spec.authority.clone(),
            notes,
        }))
    }

    /// The items to try, best first, after re-checking eligibility (policy
    /// may have changed since the request: a rule, the LLM or a window may
    /// approve long after).
    pub(super) fn candidates(
        pool_name: &str,
        pool: &PoolConfig,
        agent: &AgentRow,
        choice: &PoolChoice,
        held_last: Option<&String>,
    ) -> Result<Vec<String>, ProvisionError> {
        let me = agent_ref(agent);
        Ok(match choice {
            PoolChoice::Item(item) => {
                let Some(spec) = pool.items.get(item) else {
                    return Err(ProvisionError::failed(format!(
                        "pool {pool_name} no longer has {item}"
                    )));
                };
                if !admitted(&spec.agents, &me) {
                    return Err(ProvisionError::failed(format!(
                        "{item} of pool {pool_name} is no longer for {}",
                        agent.name
                    )));
                }
                vec![item.clone()]
            }
            PoolChoice::Previous => match held_last {
                Some(last) if Self::eligible(pool, &me, &PropMatch::new()).contains(last) => {
                    vec![last.clone()]
                }
                _ => {
                    return Err(ProvisionError::failed(
                        "the item you held last can't be leased again",
                    ));
                }
            },
            PoolChoice::Any(m) => {
                let mut c = Self::eligible(pool, &me, m);
                // Continuity: the same account as last time.
                if let Some(last) = held_last
                    && let Some(i) = c.iter().position(|x| x == last)
                {
                    let item = c.remove(i);
                    c.insert(0, item);
                }
                c
            }
        })
    }

    async fn take(
        &self,
        tx: &Tx<'_>,
        grant: &GrantRow,
        now: OffsetDateTime,
    ) -> Result<Value, ProvisionError> {
        let name = grant.resource.as_str();
        let Some(pool) = self.pools.get(name) else {
            return Err(ProvisionError::failed(format!(
                "pool {} is no longer configured",
                repr(name)
            )));
        };
        let store = |e: StoreError| store_failed(&e);
        let agent = agents::get(tx, grant.agent_id)
            .await
            .map_err(store)?
            .ok_or_else(|| ProvisionError::failed("agent not found"))?;
        if !admitted(&pool.agents, &agent_ref(&agent)) {
            return Err(ProvisionError::failed(format!(
                "pool {name} is no longer open to {}",
                agent.name
            )));
        }
        let Authority::Pool(choice) = &grant.authority else {
            return Err(ProvisionError::failed("not a pool grant"));
        };
        store_pool::lock_pool(tx, name).await.map_err(store)?;
        store_pool::clear_ended(tx, name).await.map_err(store)?;
        let held_last = store_pool::last_held(tx, agent.id, name, Some(grant.id))
            .await
            .map_err(store)?;
        let candidates = Self::candidates(name, pool, &agent, choice, held_last.as_ref())?;
        let mut last_leases = Vec::new();
        let mut held_items = BTreeSet::new();
        let mut exhausted = true;
        for _ in 0..TRIES {
            let leases = store_pool::leases(tx, name).await.map_err(store)?;
            let mine: Vec<&LeaseRow> = leases.iter().filter(|l| l.agent_id == agent.id).collect();
            if mine.len() >= usize::try_from(pool.max_per_agent).unwrap_or(usize::MAX) {
                return Err(ProvisionError::failed(format!(
                    "you already hold {} item(s) of pool {name} (at most {}); release one with release_grant first",
                    mine.len(),
                    pool.max_per_agent
                )));
            }
            let used: BTreeSet<u32> = mine.iter().map(|l| l.agent_slot).collect();
            let agent_slot = (0..pool.max_per_agent)
                .find(|s| !used.contains(s))
                .unwrap_or(0);
            // One slot of an item per agent.
            held_items = mine.iter().map(|l| l.item.clone()).collect();
            let taken: BTreeSet<(&str, u32)> =
                leases.iter().map(|l| (l.item.as_str(), l.slot)).collect();
            let choice = candidates
                .iter()
                .filter(|item| !held_items.contains(*item))
                .find_map(|item| {
                    (0..pool.capacity)
                        .find(|slot| !taken.contains(&(item.as_str(), *slot)))
                        .map(|slot| (item, slot))
                });
            let Some((item, slot)) = choice else {
                last_leases = leases;
                exhausted = false;
                break;
            };
            if let Some(it) = pool.items.get(item) {
                check_secret_size(item, &it.secret_file).await?;
            }
            let lease = NewLease {
                pool: name,
                item,
                slot,
                agent_slot,
                grant_id: grant.id,
                agent_id: agent.id,
                now,
            };
            if store_pool::take(tx, &lease).await.map_err(store)? {
                return Ok(json!({"pool": name, "item": item, "slot": slot}));
            }
            // Someone else took it between the read and now: read again.
        }
        if exhausted {
            return Err(ProvisionError::failed(format!(
                "pool {name} is busy; try again"
            )));
        }
        if !candidates.is_empty() && candidates.iter().all(|c| held_items.contains(c)) {
            return Err(ProvisionError::failed(format!(
                "you already hold {} of pool {name}",
                candidates.join(", ")
            )));
        }
        let first_free = last_leases
            .iter()
            .filter(|l| candidates.contains(&l.item))
            .map(|l| l.expires_at)
            .min();
        let when = first_free.map_or_else(String::new, |t| {
            format!("; the first frees at {}", iso_minutes(t))
        });
        Err(ProvisionError::failed(format!(
            "every matching item of pool {name} is in use{when}"
        )))
    }

    fn item_of<'a>(&'a self, grant: &GrantRow) -> Option<(&'a str, &'a PoolItem)> {
        let item = grant.provisioner_state.get("item")?.as_str()?;
        let pool = self.pools.get(&grant.resource)?;
        pool.items.get_key_value(item).map(|(k, v)| (k.as_str(), v))
    }

    /// The pools `agent` may lease from, and each item's availability
    /// (items it may not hold are left out), for the catalog.
    pub async fn status(
        &self,
        tx: &Tx<'_>,
        agent: &AgentRow,
    ) -> Result<Vec<PoolEntry>, StoreError> {
        let me = agent_ref(agent);
        let mut out = Vec::new();
        for (name, pool) in &self.pools {
            if !admitted(&pool.agents, &me) {
                continue;
            }
            let leases = store_pool::leases(tx, name).await?;
            let holders = Self::holders(&leases);
            let capacity = usize::try_from(pool.capacity).unwrap_or(usize::MAX);
            let items = pool
                .items
                .iter()
                .filter(|(_, item)| admitted(&item.agents, &me))
                .map(|(item_name, item)| {
                    let held = holders
                        .get(item_name.as_str())
                        .map_or(&[][..], Vec::as_slice);
                    PoolItemEntry {
                        name: item_name.clone(),
                        description: item.description.clone(),
                        properties: props_value(&item.properties),
                        sensitive: item.sensitive,
                        in_use: u32::try_from(held.len()).unwrap_or(u32::MAX),
                        free: held.len() < capacity,
                        frees_at: held.iter().map(|l| l.expires_at).min(),
                        yours: held.iter().any(|l| l.agent_id == agent.id),
                    }
                })
                .collect();
            out.push(PoolEntry {
                name: name.clone(),
                description: pool.description.clone(),
                capacity: pool.capacity,
                max_per_agent: pool.max_per_agent,
                items,
                you_held_last: store_pool::last_held(tx, agent.id, name, None).await?,
            });
        }
        Ok(out)
    }

    /// The configured pools.
    #[must_use]
    pub fn pools(&self) -> &BTreeMap<String, PoolConfig> {
        &self.pools
    }
}

impl Provisioner for PoolProvisioner {
    fn platform(&self) -> Platform {
        Platform::Pool
    }

    async fn validate(
        &self,
        tx: &Tx<'_>,
        spec: RequestSpec<'_>,
        _now: OffsetDateTime,
    ) -> Result<Result<Validated, Refused>, StoreError> {
        self.validate_spec(tx, spec).await
    }

    async fn provision<'t>(
        &self,
        tx: &'t Tx<'_>,
        grant: &ProvisioningGrant<'t>,
        now: OffsetDateTime,
    ) -> Result<Value, ProvisionError> {
        self.take(tx, grant.grant(), now).await
    }

    async fn revoke(
        &self,
        tx: &Tx<'_>,
        grant: &GrantRow,
        _now: OffsetDateTime,
    ) -> Result<(), ProvisionError> {
        store_pool::release(tx, grant.id)
            .await
            .map_err(|e| store_failed(&e))?;
        Ok(())
    }

    async fn credential<'t>(
        &self,
        _tx: &'t Tx<'_>,
        issuable: &IssuableGrant<'t>,
        _now: OffsetDateTime,
    ) -> Result<Credential, ProvisionError> {
        let grant = issuable.grant();
        let Some((item_name, item)) = self.item_of(grant) else {
            return Err(ProvisionError::failed(
                "this grant's item is no longer configured",
            ));
        };
        let value = if item.secret_file.is_empty() {
            None
        } else {
            Some(read_secret(item_name, &item.secret_file).await?)
        };
        let username = match item.properties.get("username") {
            Some(PropValue::Str(u)) => Some(u.clone()),
            _ => None,
        };
        let props = props_value(&item.properties);
        let mut properties = Map::new();
        properties.insert("item".to_owned(), json!(item_name));
        properties.extend(props.clone());
        Ok(Credential {
            value,
            username,
            expires_at: Some(grant.expires_at),
            note: Some(format!(
                "{item_name} of pool {} is yours alone until {}; properties: {}. Release it with release_grant when done so others can use it.",
                grant.resource,
                iso_minutes(grant.expires_at),
                canonical_json::to_python_default_string(&Value::Object(props))
            )),
            properties: Some(properties),
            ..Credential::of(CredentialKind::PoolItem)
        })
    }

    fn catalog(&self, _agent: &AgentRow) -> Option<Value> {
        // Needs the database (who holds what): built by the catalog route
        // through `status`.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minutes() {
        let t = time::macros::datetime!(2026-10-25 14:30:59.5 UTC);
        assert_eq!(iso_minutes(t), "2026-10-25T14:30+00:00");
    }

    #[test]
    fn strerror_drops_the_code() {
        let e = std::io::Error::from_raw_os_error(2);
        assert_eq!(strerror(&e), "No such file or directory");
    }
}

//! Restricted zones: resources only their own agents reach (spec
//! core-lifecycle-policy §8.6, `core/zones.py`).
//!
//! A zone (policy `restricted`) names its members and what is theirs
//! (Kubernetes namespaces, GitHub repos). To an agent outside, those do not
//! exist: a request for them is refused before any rule is read, with the
//! same words as something the broker does not broker at all; members and
//! outsiders are not a2a peers; no outsider in an agent VM reaches a
//! member project; members write the wiki only if the zone says so; an
//! agent that would be a member is never minted without a human.
//!
//! The broker supplies what needs the database ([`ZoneFacts`]); the logic
//! here is pure. A request may only be routed with the [`ZonePassed`] that
//! [`check`] returns, so the check cannot be skipped.

use std::collections::BTreeSet;

use crate::authority::Authority;
use crate::glob::Glob;
use crate::platform::Platform;
use crate::policy::{AgentKind, AgentRef, Placement, Policy};
use crate::pyfmt::repr;

/// The runtime of the agent that mints the others in an agent VM.
pub const ORCHESTRATOR_RUNTIME: &str = "orchestrator";

/// What the check needs from the database, per platform.
#[derive(Debug, Clone, Copy)]
pub enum ZoneFacts<'a> {
    /// Kubernetes, GitHub, and platforms zones don't concern.
    Nothing,
    /// a2a: the target agent (looked up by exact name), if it exists.
    A2aPeer(Option<AgentRef<'a>>),
    /// sandbox: the requester's agent VM's name (its daemon), if it is in
    /// one, and the agents in that VM whose project is the requested one.
    Sandbox {
        daemon: Option<&'a str>,
        project_agents: &'a [AgentRef<'a>],
    },
    /// agents (minting): the requester's agent VM's name, if any.
    Agents { daemon: Option<&'a str> },
}

/// The zone check passed. Carries the note when a human must decide.
#[derive(Debug, PartialEq, Eq)]
pub struct ZonePassed {
    human_note: Option<String>,
}

impl ZonePassed {
    #[cfg(test)]
    pub(crate) fn for_tests(human_note: Option<&str>) -> ZonePassed {
        ZonePassed {
            human_note: human_note.map(str::to_owned),
        }
    }

    /// Set when the request may only be approved by a human.
    #[must_use]
    pub fn human_note(&self) -> Option<&str> {
        self.human_note.as_deref()
    }
}

/// The request names a zone's resource from outside the zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneDenied {
    text: String,
}

impl ZoneDenied {
    /// What the platform itself says about a resource it doesn't broker.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The request's `decision_reason`.
    #[must_use]
    pub fn request_reason(&self) -> String {
        format!("validator: {}", self.text)
    }
}

/// The platforms' own refusal texts (`NOT_BROKERED`), so a zone's refusal
/// says nothing about the zone.
#[must_use]
pub fn not_brokered(platform: Platform, resource: &str) -> Option<String> {
    let r = repr(resource);
    match platform {
        Platform::Kubernetes => Some(format!("namespace {r} is not brokered (allowlist)")),
        Platform::Github => Some(format!("repo {r} is never brokered (denylist)")),
        Platform::A2a => Some(format!("unknown target agent {r}")),
        Platform::Sandbox => Some(format!("no project {r} in this agent VM")),
        _ => None,
    }
}

fn deny(platform: Platform, resource: &str) -> ZoneDenied {
    ZoneDenied {
        text: not_brokered(platform, resource).unwrap_or_else(|| "not brokered".to_owned()),
    }
}

/// The zones the agent is a member of (none for the operator).
#[must_use]
pub fn member_of<'p>(policy: &'p Policy, agent: &AgentRef<'_>) -> BTreeSet<&'p str> {
    if agent.kind == AgentKind::Operator {
        return BTreeSet::new();
    }
    policy
        .restricted()
        .iter()
        .filter(|(_, zone)| zone.members.iter().any(|p| p.matches(agent)))
        .map(|(name, _)| name.as_str())
        .collect()
}

#[must_use]
pub fn is_member(policy: &Policy, agent: &AgentRef<'_>) -> bool {
    !member_of(policy, agent).is_empty()
}

/// The zones that own a resource (case-insensitively).
fn owner<'p>(policy: &'p Policy, platform: Platform, resource: &str) -> BTreeSet<&'p str> {
    let resource = resource.to_lowercase();
    policy
        .restricted()
        .iter()
        .filter(|(_, zone)| {
            let globs: &[Glob] = match platform {
                Platform::Kubernetes => &zone.kubernetes,
                Platform::Github => &zone.github,
                _ => &[],
            };
            globs
                .iter()
                .any(|g| Glob::new(&g.as_str().to_lowercase()).matches(&resource))
        })
        .map(|(name, _)| name.as_str())
        .collect()
}

/// The resource belongs to a zone this agent is not in.
#[must_use]
pub fn outside(policy: &Policy, agent: &AgentRef<'_>, platform: Platform, resource: &str) -> bool {
    let mine = member_of(policy, agent);
    owner(policy, platform, resource)
        .iter()
        .any(|z| !mine.contains(z))
}

/// Namespace globs a cluster-wide grant of this agent must leave out:
/// those of every zone it is not in, sorted, without repeats.
#[must_use]
pub fn excluded_namespaces(policy: &Policy, agent: &AgentRef<'_>) -> Vec<String> {
    let mine = member_of(policy, agent);
    let set: BTreeSet<String> = policy
        .restricted()
        .iter()
        .filter(|(name, _)| !mine.contains(name.as_str()))
        .flat_map(|(_, zone)| zone.kubernetes.iter().map(|g| g.as_str().to_owned()))
        .collect();
    set.into_iter().collect()
}

/// Two agents on different sides of a zone's edge (a2a). The operator is
/// on every side.
#[must_use]
pub fn apart(policy: &Policy, a: &AgentRef<'_>, b: &AgentRef<'_>) -> bool {
    if a.kind == AgentKind::Operator || b.kind == AgentKind::Operator {
        return false;
    }
    member_of(policy, a) != member_of(policy, b)
}

/// Members write the shared wiki only when every zone they are in allows it.
#[must_use]
pub fn may_write_wiki(policy: &Policy, agent: &AgentRef<'_>) -> bool {
    member_of(policy, agent)
        .iter()
        .all(|name| policy.restricted().get(*name).is_some_and(|z| z.wiki))
}

/// `Zones.check`, for a validated request: refuse it, require a human, or
/// let it through. Runs before any rule is read.
///
/// Facts that don't fit the platform (a programming error in the caller)
/// fail closed: refused, or for minting, a human.
pub fn check(
    policy: &Policy,
    agent: &AgentRef<'_>,
    authority: &Authority,
    resource: &str,
    facts: &ZoneFacts<'_>,
) -> Result<ZonePassed, ZoneDenied> {
    let pass = Ok(ZonePassed { human_note: None });
    if policy.restricted().is_empty() {
        return pass;
    }
    let platform = authority.platform();
    match (platform, facts) {
        (Platform::Kubernetes | Platform::Github, _) => {
            if outside(policy, agent, platform, resource) {
                Err(deny(platform, resource))
            } else {
                pass
            }
        }
        (Platform::A2a, ZoneFacts::A2aPeer(peer)) => match peer {
            Some(peer) if apart(policy, agent, peer) => Err(deny(platform, resource)),
            _ => pass,
        },
        (
            Platform::Sandbox,
            ZoneFacts::Sandbox {
                daemon,
                project_agents,
            },
        ) => {
            let mine = member_of(policy, agent);
            let reaches_in =
                |other: &AgentRef<'_>| member_of(policy, other).iter().any(|z| !mine.contains(z));
            if project_agents.iter().any(reaches_in) {
                return Err(deny(platform, resource));
            }
            if let Some(daemon) = daemon {
                for runtime in runtimes(policy) {
                    let name = format!("{runtime}-{resource}-{daemon}-sandbox");
                    let would_be = AgentRef {
                        name: &name,
                        runtime: Some(&runtime),
                        project: Some(resource),
                        host: Some(daemon),
                        placement: Placement::Sandbox,
                        kind: AgentKind::Service,
                    };
                    if reaches_in(&would_be) {
                        return Err(deny(platform, resource));
                    }
                }
            }
            pass
        }
        (Platform::Agents, ZoneFacts::Agents { daemon }) => {
            let runtime = match authority {
                Authority::Agents { runtime, .. } => runtime.as_deref().unwrap_or(""),
                _ => "",
            };
            let Some(daemon) = daemon else { return pass };
            let suffix = format!("-{daemon}-sandbox");
            if runtime.is_empty() || !resource.ends_with(&suffix) {
                return pass;
            }
            let project = py_slice(
                resource,
                runtime.chars().count().saturating_add(1),
                suffix.chars().count(),
            );
            let would_be = AgentRef {
                name: resource,
                runtime: Some(runtime),
                project: Some(&project),
                host: Some(daemon),
                placement: Placement::Sandbox,
                kind: AgentKind::Service,
            };
            let zones = member_of(policy, &would_be);
            if zones.is_empty() {
                pass
            } else {
                Ok(ZonePassed {
                    human_note: Some(format!(
                        "mints an agent inside restricted zone {}: always a human",
                        zones.into_iter().collect::<Vec<_>>().join(", ")
                    )),
                })
            }
        }
        (Platform::A2a | Platform::Sandbox, _) => Err(deny(platform, resource)),
        (Platform::Agents, _) => Ok(ZonePassed {
            human_note: Some(
                "mints an agent (restricted zones not checked): always a human".to_owned(),
            ),
        }),
        _ => pass,
    }
}

/// `sorted(agents.runtimes ∪ {"orchestrator"})`.
fn runtimes(policy: &Policy) -> BTreeSet<String> {
    let mut set: BTreeSet<String> = policy.platforms().agents.runtimes.iter().cloned().collect();
    set.insert(ORCHESTRATOR_RUNTIME.to_owned());
    set
}

/// Python's `s[start:-end_from_back]` in characters (empty when they cross).
fn py_slice(s: &str, start: usize, end_from_back: usize) -> String {
    let n = s.chars().count();
    let end = n.saturating_sub(end_from_back);
    if start >= end {
        return String::new();
    }
    s.chars()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy(extra: &str) -> Policy {
        Policy::from_yaml(&format!(
            "projects: {{soc: {{}}, ops: {{}}}}\n\
             restricted:\n  soc: {{members: [{{project: soc}}], kubernetes: [apps-soc], github: [jrt/soc]{extra}}}\n"
        ))
        .unwrap()
    }

    fn agent<'a>(name: &'a str, project: Option<&'a str>) -> AgentRef<'a> {
        AgentRef {
            project,
            ..AgentRef::named(name)
        }
    }

    fn k8s() -> Authority {
        Authority::from_wire(Platform::Kubernetes, "view", &serde_json::Map::new()).unwrap()
    }

    /// test_zones.py::test_outside_a_zone_its_resources_are_not_brokered_whatever_the_rules
    #[test]
    fn outsiders_are_refused_with_the_platforms_words() {
        let p = policy("");
        let outsider = agent("claude-ops", Some("ops"));
        let member = agent("claude-soc", Some("soc"));
        let refused = check(&p, &outsider, &k8s(), "apps-soc", &ZoneFacts::Nothing).unwrap_err();
        assert_eq!(
            refused.request_reason(),
            "validator: namespace 'apps-soc' is not brokered (allowlist)"
        );
        assert!(check(&p, &outsider, &k8s(), "APPS-SOC", &ZoneFacts::Nothing).is_err());
        assert_eq!(
            check(&p, &member, &k8s(), "apps-soc", &ZoneFacts::Nothing)
                .unwrap()
                .human_note(),
            None
        );
        assert!(check(&p, &member, &k8s(), "personal-site", &ZoneFacts::Nothing).is_ok());
        let gh = Authority::from_wire(
            Platform::Github,
            "repo",
            json!({"permissions": {"contents": "read"}})
                .as_object()
                .unwrap(),
        )
        .unwrap();
        let out = check(&p, &outsider, &gh, "jrt/soc", &ZoneFacts::Nothing).unwrap_err();
        assert!(out.text().contains("never brokered"));
    }

    /// test_zones.py::test_members_and_outsiders_are_not_peers
    #[test]
    fn members_and_outsiders_are_not_peers() {
        let p = policy("");
        let a2a = Authority::from_wire(Platform::A2a, "talk", &serde_json::Map::new()).unwrap();
        let outsider = agent("claude-ops", Some("ops"));
        let member = agent("codex-soc", Some("soc"));
        let peer = agent("peer-ops", Some("ops"));
        let d = check(
            &p,
            &outsider,
            &a2a,
            "codex-soc",
            &ZoneFacts::A2aPeer(Some(member)),
        )
        .unwrap_err();
        assert_eq!(d.text(), "unknown target agent 'codex-soc'");
        assert!(
            check(
                &p,
                &member,
                &a2a,
                "peer-ops",
                &ZoneFacts::A2aPeer(Some(peer))
            )
            .is_err()
        );
        assert!(
            check(
                &p,
                &outsider,
                &a2a,
                "peer-ops",
                &ZoneFacts::A2aPeer(Some(peer))
            )
            .is_ok()
        );
        assert!(check(&p, &outsider, &a2a, "nobody", &ZoneFacts::A2aPeer(None)).is_ok());
        let operator = AgentRef {
            kind: AgentKind::Operator,
            ..AgentRef::named("operator")
        };
        assert!(!apart(&p, &operator, &member));
        // Wrong facts fail closed.
        assert!(check(&p, &outsider, &a2a, "peer-ops", &ZoneFacts::Nothing).is_err());
    }

    /// test_zones.py::test_a_member_is_never_minted_without_a_human
    #[test]
    fn a_member_is_never_minted_without_a_human() {
        let p = policy("");
        let orchestrator = AgentRef {
            runtime: Some("orchestrator"),
            host: Some("galaxy"),
            placement: Placement::Sandbox,
            ..AgentRef::named("orchestrator-galaxy-sandbox")
        };
        let mint = |runtime: &str| {
            Authority::from_wire(
                Platform::Agents,
                "mint",
                json!({"runtime": runtime}).as_object().unwrap(),
            )
            .unwrap()
        };
        let facts = ZoneFacts::Agents {
            daemon: Some("galaxy"),
        };
        let zoned = check(
            &p,
            &orchestrator,
            &mint("codex"),
            "codex-soc-galaxy-sandbox",
            &facts,
        )
        .unwrap();
        assert_eq!(
            zoned.human_note(),
            Some("mints an agent inside restricted zone soc: always a human")
        );
        let free = check(
            &p,
            &orchestrator,
            &mint("codex"),
            "codex-ops-galaxy-sandbox",
            &facts,
        )
        .unwrap();
        assert_eq!(free.human_note(), None);
        // Not in a VM, or not a name of that VM: nothing to say.
        assert_eq!(
            check(
                &p,
                &orchestrator,
                &mint("codex"),
                "codex-soc-galaxy-sandbox",
                &ZoneFacts::Agents { daemon: None }
            )
            .unwrap()
            .human_note(),
            None
        );
        // Nor may an outsider in the VM read the zone's project.
        let sandbox =
            Authority::from_wire(Platform::Sandbox, "project.read", &serde_json::Map::new())
                .unwrap();
        let facts = ZoneFacts::Sandbox {
            daemon: Some("galaxy"),
            project_agents: &[],
        };
        let denied = check(&p, &orchestrator, &sandbox, "soc", &facts).unwrap_err();
        assert_eq!(denied.text(), "no project 'soc' in this agent VM");
        assert!(check(&p, &orchestrator, &sandbox, "ops", &facts).is_ok());
        // An existing member agent of that project counts too.
        let member = agent("x", Some("soc"));
        let facts = ZoneFacts::Sandbox {
            daemon: None,
            project_agents: &[member],
        };
        assert!(check(&p, &orchestrator, &sandbox, "soc", &facts).is_err());
        // A member reads outside its zone (one way).
        assert!(
            check(
                &p,
                &member,
                &sandbox,
                "ops",
                &ZoneFacts::Sandbox {
                    daemon: Some("galaxy"),
                    project_agents: &[]
                }
            )
            .is_ok()
        );
    }

    /// test_zones.py::test_members_do_not_write_the_wiki_unless_the_zone_says_so
    #[test]
    fn wiki_writes() {
        let p = policy("");
        let member = agent("claude-soc", Some("soc"));
        let other = agent("claude-ops", Some("ops"));
        assert!(!may_write_wiki(&p, &member));
        assert!(may_write_wiki(&p, &other));
        assert!(may_write_wiki(&policy(", wiki: true"), &member));
    }

    #[test]
    fn excluded_namespaces_for_outsiders() {
        let p = policy("");
        assert_eq!(
            excluded_namespaces(&p, &agent("x", Some("ops"))),
            vec!["apps-soc"]
        );
        assert!(excluded_namespaces(&p, &agent("x", Some("soc"))).is_empty());
    }

    #[test]
    fn no_zones_no_checks() {
        let p = Policy::default();
        assert!(
            check(
                &p,
                &AgentRef::named("x"),
                &k8s(),
                "anything",
                &ZoneFacts::Nothing
            )
            .is_ok()
        );
    }

    #[test]
    fn python_slices() {
        assert_eq!(py_slice("codex-soc-galaxy-sandbox", 6, 15), "soc");
        assert_eq!(py_slice("x-galaxy-sandbox", 6, 15), "");
        assert_eq!(py_slice("ab", 5, 0), "");
    }
}

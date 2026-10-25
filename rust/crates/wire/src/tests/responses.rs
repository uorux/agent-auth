//! Responses: shapes from the spec, and the property that every response
//! type serializes and deserializes to itself.

use std::collections::BTreeMap;

use agent_auth_core::{
    AgentId, DaemonId, DecisionSource, GrantId, GrantStatus, JobId, MessageId, Platform, RequestId,
    RequestStatus, RuleId, SessionId, ThreadId,
};
use proptest::collection::{btree_map, vec};
use proptest::option;
use proptest::prelude::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::a2a::*;
use crate::admin::*;
use crate::admin_log::*;
use crate::agent::*;
use crate::audit::*;
use crate::catalog::*;
use crate::chat::*;
use crate::common::*;
use crate::containment::*;
use crate::daemon::channel::{CallId, PromptId, Reply};
use crate::daemon::host::{
    Answer, BrokerToHost, DesktopStatus, Dnd, HostStatus, HostToBroker, JobDone, JobOutput, JobRef,
    Lockdown, Notify, Presence, PromptAnswer, PromptCancel, ShellRef, TierStatus, Unlock, Urgency,
    VmStatus,
};
use crate::daemon::pairing::PairResponse;
use crate::daemon::sandbox::{
    AgentsContained, BrokerToSandbox, KeyAck, KeyDelivery, KeyRotate, ProjectAccessName,
    ProjectGrant, ProjectRevoke, SandboxStatus, SandboxToBroker, SandboxUnlock,
};
use crate::hostexec::*;
use crate::json::{ReplyData, StatusObject};
use crate::literal::{Bearer, True};
use crate::oauth::*;
use crate::secret::WireSecret;
use crate::text::{BoundedVec, DaemonName, LowerHex, Text};
use crate::wiki::*;

// ------------------------------------------------------------ strategies

fn ts() -> impl Strategy<Value = OffsetDateTime> {
    (0i64..253_402_300_799_999_999).prop_map(|micros| {
        OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros).saturating_mul(1000))
            .unwrap_or(OffsetDateTime::UNIX_EPOCH)
    })
}

fn s() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 _.:/é日🙂\"\\\\\n-]{0,10}"
}

fn os() -> impl Strategy<Value = Option<String>> {
    option::of(s())
}

/// Floats that survive any JSON path exactly.
fn float() -> impl Strategy<Value = f64> {
    any::<u32>().prop_map(f64::from)
}

fn uuid() -> impl Strategy<Value = Uuid> {
    any::<u128>().prop_map(Uuid::from_u128)
}

macro_rules! id_strategy {
    ($($f:ident: $t:ty),*) => {$(
        fn $f() -> impl Strategy<Value = $t> {
            uuid().prop_map(<$t>::from_uuid)
        }
    )*};
}
id_strategy!(agent_id: AgentId, session_id: SessionId, request_id: RequestId, grant_id: GrantId,
             rule_id: RuleId, thread_id: ThreadId, message_id: MessageId, daemon_id: DaemonId,
             job_id: JobId);

fn leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        s().prop_map(Value::String),
    ]
}

fn json_value() -> impl Strategy<Value = Value> {
    leaf().prop_recursive(3, 16, 4, |inner| {
        prop_oneof![
            vec(inner.clone(), 0..3).prop_map(Value::Array),
            btree_map(s(), inner, 0..3).prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

fn object() -> impl Strategy<Value = Map<String, Value>> {
    btree_map(s(), json_value(), 0..4).prop_map(|m| m.into_iter().collect())
}

/// A JSON value that is never `null` (an `Option<Value>` reads `null` as
/// `None`).
fn non_null() -> impl Strategy<Value = Value> {
    json_value().prop_filter("not null", |v| !v.is_null())
}

fn strings() -> impl Strategy<Value = Vec<String>> {
    vec(s(), 0..3)
}

fn secret<const N: usize>() -> impl Strategy<Value = WireSecret<N>> {
    "[a-zA-Z0-9_-]{1,20}".prop_map(|v| WireSecret::new(v).unwrap())
}

macro_rules! pick {
    ($($v:expr),+ $(,)?) => { prop_oneof![$(Just($v)),+] };
}

fn platform() -> impl Strategy<Value = Platform> {
    proptest::sample::select(Platform::ALL.to_vec())
}
fn request_status() -> impl Strategy<Value = RequestStatus> {
    proptest::sample::select(RequestStatus::ALL.to_vec())
}
fn grant_status() -> impl Strategy<Value = GrantStatus> {
    proptest::sample::select(GrantStatus::ALL.to_vec())
}
fn source() -> impl Strategy<Value = DecisionSource> {
    pick![
        DecisionSource::Policy,
        DecisionSource::Rule,
        DecisionSource::Llm,
        DecisionSource::Human
    ]
}
fn tier() -> impl Strategy<Value = TierName> {
    pick![TierName::User, TierName::Root]
}
fn agent_kind() -> impl Strategy<Value = AgentKind> {
    pick![
        AgentKind::Service,
        AgentKind::Ephemeral,
        AgentKind::Operator
    ]
}
fn placement() -> impl Strategy<Value = Placement> {
    pick![Placement::Host, Placement::Sandbox]
}
fn thread_state() -> impl Strategy<Value = ThreadState> {
    pick![
        ThreadState::PendingOpen,
        ThreadState::Open,
        ThreadState::Closed
    ]
}
fn close_reason() -> impl Strategy<Value = CloseReason> {
    pick![
        CloseReason::Rejected,
        CloseReason::Closed,
        CloseReason::OpenTimeout,
        CloseReason::IdleTimeout,
        CloseReason::PeerGone,
        CloseReason::GrantRevoked,
        CloseReason::Contained,
    ]
}
fn job_status() -> impl Strategy<Value = JobStatus> {
    pick![
        JobStatus::Starting,
        JobStatus::Running,
        JobStatus::Done,
        JobStatus::Refused,
        JobStatus::Lost
    ]
}
fn daemon_role() -> impl Strategy<Value = DaemonRole> {
    pick![DaemonRole::Host, DaemonRole::Sandbox]
}
fn disposition() -> impl Strategy<Value = Disposition> {
    pick![
        Disposition::AutoApprove,
        Disposition::HumanReview,
        Disposition::LlmReview,
        Disposition::Denied
    ]
}
fn credential_kind() -> impl Strategy<Value = CredentialKind> {
    pick![
        CredentialKind::GithubInstallationToken,
        CredentialKind::GithubRepo,
        CredentialKind::KubernetesToken,
        CredentialKind::LldapAccount,
        CredentialKind::LldapGroup,
        CredentialKind::McpToken,
        CredentialKind::ModelGatewayKey,
        CredentialKind::A2aGrant,
        CredentialKind::AgentIdentity,
        CredentialKind::ProjectAccess,
        CredentialKind::HostexecShell,
        CredentialKind::HostexecJob,
    ]
}
fn lockdown_scope() -> impl Strategy<Value = LockdownScope> {
    pick![
        LockdownScope::Sandboxes,
        LockdownScope::All,
        LockdownScope::Host
    ]
}
fn call_id() -> impl Strategy<Value = Option<CallId>> {
    option::of(uuid().prop_map(|u| CallId::parse(&u.simple().to_string()).unwrap()))
}
fn hex64() -> impl Strategy<Value = LowerHex<64>> {
    "[0-9a-f]{64}".prop_map(|h| LowerHex::new(h).unwrap())
}
fn text<const A: usize, const B: usize>() -> impl Strategy<Value = Text<A, B>> {
    s().prop_filter_map("in bounds", |v| Text::new(v).ok())
}

fn me() -> impl Strategy<Value = Me> {
    (
        (agent_id(), s(), s(), agent_kind(), os(), os()),
        (
            os(),
            os(),
            os(),
            placement(),
            option::of((session_id(), s())),
        ),
    )
        .prop_map(
            |(
                (id, name, description, kind, webhook_url, lldap_username),
                (runtime, project, host, placement, session),
            )| Me {
                id,
                name,
                description,
                kind,
                webhook_url,
                lldap_username,
                runtime,
                project,
                host,
                placement,
                session: session.map(|(id, name)| SessionRef { id, name }),
            },
        )
}

fn request_out() -> impl Strategy<Value = RequestOut> {
    (
        (
            request_id(),
            s(),
            platform(),
            s(),
            s(),
            object(),
            s(),
            any::<u32>(),
        ),
        (
            request_status(),
            any::<u32>(),
            option::of(source()),
            os(),
            option::of(any::<u32>()),
            option::of(object()),
        ),
        (
            os(),
            option::of(grant_id()),
            os(),
            option::of(thread_id()),
            ts(),
            os(),
        ),
    )
        .prop_map(|(a, b, c)| RequestOut {
            id: a.0,
            agent: a.1,
            platform: a.2,
            capability: a.3,
            resource: a.4,
            scope: a.5,
            justification: a.6,
            requested_duration_secs: a.7,
            status: b.0,
            attempt: b.1,
            decision_source: b.2,
            decision_reason: b.3,
            approved_duration_secs: b.4,
            approved_scope: b.5,
            approved_resource: c.0,
            grant_id: c.1,
            delegator: c.2,
            delegation_thread_id: c.3,
            created_at: c.4,
            guidance: c.5,
        })
}

fn grant_out() -> impl Strategy<Value = GrantOut> {
    (
        (
            grant_id(),
            request_id(),
            s(),
            platform(),
            s(),
            s(),
            object(),
        ),
        (ts(), ts(), grant_status(), os(), option::of(thread_id())),
    )
        .prop_map(|(a, b)| GrantOut {
            id: a.0,
            request_id: a.1,
            agent: a.2,
            platform: a.3,
            capability: a.4,
            resource: a.5,
            scope: a.6,
            granted_at: b.0,
            expires_at: b.1,
            status: b.2,
            delegator: b.3,
            delegation_thread_id: b.4,
        })
}

fn credential_out() -> impl Strategy<Value = CredentialOut> {
    (
        credential_kind(),
        option::of(secret::<16384>()),
        os(),
        os(),
        option::of(ts()),
        os(),
    )
        .prop_map(
            |(kind, value, username, url, expires_at, note)| CredentialOut {
                kind,
                value,
                username,
                url,
                expires_at,
                note,
            },
        )
}

fn peer_entry() -> impl Strategy<Value = PeerEntry> {
    (
        s(),
        os(),
        agent_kind(),
        any::<bool>(),
        any::<bool>(),
        pick![
            Reach::Webhook,
            Reach::Polling,
            Reach::Idle,
            Reach::Ephemeral
        ],
        option::of(ts()),
        option::of(ts()),
        any::<bool>(),
    )
        .prop_map(
            |(
                name,
                description,
                kind,
                addressable,
                reachable,
                why,
                last_seen_at,
                last_listen_at,
                has_webhook,
            )| PeerEntry {
                name,
                description,
                kind,
                addressable,
                reachable,
                why,
                last_seen_at,
                last_listen_at,
                has_webhook,
            },
        )
}

fn catalog_entry() -> impl Strategy<Value = CatalogEntry> {
    (s(), os(), option::of(disposition())).prop_map(|(name, description, typical_disposition)| {
        CatalogEntry {
            name,
            description,
            typical_disposition,
        }
    })
}

fn platform_catalog() -> impl Strategy<Value = PlatformCatalog> {
    (
        (
            platform(),
            s(),
            s(),
            option::of(vec(catalog_entry(), 0..2)),
            option::of(strings()),
            option::of(strings()),
        ),
        (
            option::of(strings()),
            option::of(btree_map(s(), s(), 0..3)),
            option::of(strings()),
            option::of(disposition()),
        ),
        (
            option::of(vec(catalog_entry(), 0..2)),
            option::of(strings()),
            option::of(vec(peer_entry(), 0..2)),
        ),
        (
            option::of(vec(
                (
                    s(),
                    any::<bool>(),
                    any::<bool>(),
                    btree_map(tier(), (any::<bool>(), any::<bool>()), 0..2),
                    strings(),
                ),
                0..2,
            )),
            option::of(vec((s(), s(), s(), option::of(strings())), 0..2)),
            option::of((s(), s(), option::of(strings()))),
        ),
    )
        .prop_map(|(a, b, c, d)| {
            let mut p = PlatformCatalog::new(a.0, a.1, a.2);
            p.roles = a.3;
            p.cluster_roles = a.4;
            p.namespace_allowlist = a.5;
            p.repo_allowlist = b.0;
            p.permission_ceiling = b.1;
            p.create_owners = b.2;
            p.create_disposition = b.3;
            p.groups = c.0;
            p.capabilities = c.1;
            p.peers = c.2;
            p.hosts = d.0.map(|hosts| {
                hosts
                    .into_iter()
                    .map(|(name, online, lockdown, tiers, templates)| CatalogHost {
                        name,
                        online,
                        lockdown,
                        tiers: tiers
                            .into_iter()
                            .map(|(t, (armed, shell))| (t, CatalogTier { armed, shell }))
                            .collect(),
                        templates,
                    })
                    .collect()
            });
            p.servers = d.1.map(|v| {
                v.into_iter()
                    .map(|(name, url, description, tools)| McpServerEntry {
                        name,
                        url,
                        description,
                        tools,
                    })
                    .collect()
            });
            p.gateway =
                d.2.map(|(name, url, models)| GatewayEntry { name, url, models });
            p
        })
}

fn thread_out() -> impl Strategy<Value = ThreadOut> {
    (
        (
            thread_id(),
            os(),
            pick![ThreadRole::Initiator, ThreadRole::Responder],
            os(),
            thread_state(),
            option::of(close_reason()),
            os(),
        ),
        (
            option::of(grant_id()),
            any::<u64>(),
            ts(),
            option::of(ts()),
            option::of(ts()),
            ts(),
            option::of(ts()),
            any::<bool>(),
        ),
    )
        .prop_map(|(a, b)| ThreadOut {
            thread_id: a.0,
            peer: a.1,
            role: a.2,
            topic: a.3,
            state: a.4,
            close_reason: a.5,
            close_note: a.6,
            grant_id: b.0,
            last_seq: b.1,
            created_at: b.2,
            accepted_at: b.3,
            closed_at: b.4,
            last_activity_at: b.5,
            peer_last_seen_at: b.6,
            peer_alive: b.7,
        })
}

fn message_out() -> impl Strategy<Value = MessageOut> {
    (message_id(), any::<u64>(), s(), object(), ts()).prop_map(
        |(message_id, seq, from, payload, created_at)| MessageOut {
            message_id,
            seq,
            from,
            payload,
            created_at,
        },
    )
}

fn job_command() -> impl Strategy<Value = JobCommand> {
    prop_oneof![
        strings().prop_map(JobCommand::Argv),
        s().prop_map(JobCommand::Template)
    ]
}

fn job_out() -> impl Strategy<Value = JobOut> {
    (
        (
            job_id(),
            s(),
            tier(),
            job_status(),
            option::of(any::<i32>()),
            os(),
        ),
        (
            option::of(any::<u64>()),
            option::of(any::<u64>()),
            os(),
            option::of(any::<bool>()),
            option::of(job_command()),
            os(),
        ),
    )
        .prop_map(|(a, b)| JobOut {
            job_id: a.0,
            host: a.1,
            tier: a.2,
            status: a.3,
            exit_code: a.4,
            error: a.5,
            duration_ms: b.0,
            output_bytes: b.1,
            output_sha256: b.2,
            truncated: b.3,
            command: b.4,
            output: b.5,
        })
}

fn agent_out() -> impl Strategy<Value = AgentOut> {
    (
        (
            agent_id(),
            s(),
            s(),
            agent_kind(),
            os(),
            os(),
            any::<bool>(),
            any::<bool>(),
            option::of(ts()),
        ),
        (
            option::of(agent_id()),
            option::of(daemon_id()),
            os(),
            os(),
            os(),
            placement(),
            option::of(ts()),
        ),
        (option::of(secret::<512>()), option::of(secret::<512>())),
    )
        .prop_map(|(a, b, c)| AgentOut {
            id: a.0,
            name: a.1,
            description: a.2,
            kind: a.3,
            webhook_url: a.4,
            lldap_username: a.5,
            lldap_managed: a.6,
            disabled: a.7,
            last_seen_at: a.8,
            parent: b.0,
            sandbox: b.1,
            runtime: b.2,
            project: b.3,
            host: b.4,
            placement: b.5,
            lease_expires_at: b.6,
            api_key: c.0,
            webhook_secret: c.1,
        })
}

fn containment_entry() -> impl Strategy<Value = ContainmentEntry> {
    ("[0-9a-f]{8}", object(), s(), s(), s(), s(), ts()).prop_map(
        |(id, matches, reason, evidence, by, source, at)| ContainmentEntry {
            id,
            matches,
            reason,
            evidence,
            by,
            source,
            at,
        },
    )
}

fn security_event() -> impl Strategy<Value = SecurityEvent> {
    (
        "s[0-9]{1,4}",
        ts(),
        os(),
        os(),
        btree_map("f_[a-z]{1,5}", os(), 0..3),
    )
        .prop_map(|(id, at, client, path, fields)| SecurityEvent {
            id,
            at,
            client,
            path,
            fields,
        })
}

fn audit_event() -> impl Strategy<Value = AuditEvent> {
    let request = (
        (request_id(), ts(), ts(), s(), os(), platform(), s(), s()),
        (
            request_status(),
            option::of(source()),
            os(),
            os(),
            s(),
            strings(),
            any::<u32>(),
        ),
    )
        .prop_map(|(a, b)| {
            AuditEvent::Request(RequestEvent {
                id: a.0,
                at: a.1,
                created_at: a.2,
                agent: a.3,
                for_: a.4,
                platform: a.5,
                what: a.6,
                resource: a.7,
                status: b.0,
                source: b.1,
                by: b.2,
                reason: b.3,
                justification: b.4,
                risk_notes: b.5,
                duration_secs: b.6,
            })
        });
    let issued = (
        ts(),
        ts(),
        grant_id(),
        s(),
        platform(),
        s(),
        s(),
        request_id(),
    )
        .prop_map(|g| {
            AuditEvent::GrantIssued(GrantIssued {
                at: g.0,
                status: GrantStatus::Active,
                expires_at: g.1,
                id: g.2,
                agent: g.3,
                platform: g.4,
                what: g.5,
                resource: g.6,
                request_id: g.7,
            })
        });
    let ended = (
        ts(),
        grant_status(),
        os(),
        grant_id(),
        s(),
        platform(),
        s(),
        s(),
        request_id(),
    )
        .prop_map(|g| {
            AuditEvent::GrantEnded(GrantEnded {
                at: g.0,
                status: g.1,
                reason: g.2,
                id: g.3,
                agent: g.4,
                platform: g.5,
                what: g.6,
                resource: g.7,
                request_id: g.8,
            })
        });
    let job = (
        (
            ts(),
            pick![
                JobPhase::Started,
                JobPhase::Done,
                JobPhase::Refused,
                JobPhase::Lost
            ],
            job_id(),
            ts(),
            s(),
            s(),
            tier(),
        ),
        (
            any::<bool>(),
            s(),
            os(),
            os(),
            option::of(any::<i32>()),
            os(),
        ),
    )
        .prop_map(|(a, b)| {
            AuditEvent::HostJob(HostJobEvent {
                at: a.0,
                status: a.1,
                id: a.2,
                created_at: a.3,
                agent: a.4,
                host: a.5,
                tier: a.6,
                shell: b.0,
                command: b.1,
                cwd: b.2,
                via: b.3,
                exit_code: b.4,
                error: b.5,
            })
        });
    let opened = (ts(), thread_id(), s(), s(), os(), any::<bool>()).prop_map(|t| {
        AuditEvent::A2aOpened(A2aOpened {
            at: t.0,
            status: ThreadState::Open,
            id: t.1,
            from: t.2,
            to: t.3,
            topic: t.4,
            operator: t.5,
        })
    });
    let closed = (
        ts(),
        option::of(close_reason()),
        thread_id(),
        s(),
        s(),
        os(),
        any::<bool>(),
    )
        .prop_map(|t| {
            AuditEvent::A2aClosed(A2aClosed {
                at: t.0,
                status: ThreadState::Closed,
                reason: t.1,
                id: t.2,
                from: t.3,
                to: t.4,
                topic: t.5,
                operator: t.6,
            })
        });
    let created = (
        (agent_id(), ts(), s(), agent_kind()),
        (os(), os(), os(), placement(), os()),
    )
        .prop_map(|(a, b)| {
            AuditEvent::AgentCreated(AgentCreated {
                id: a.0,
                at: a.1,
                status: Created,
                agent: a.2,
                agent_kind: a.3,
                runtime: b.0,
                project: b.1,
                host: b.2,
                placement: b.3,
                parent: b.4,
            })
        });
    let standing = ("[0-9a-f]{8}", ts(), object(), s(), s(), s()).prop_map(|c| {
        AuditEvent::Containment(ContainmentStanding {
            id: c.0,
            at: c.1,
            status: Standing,
            matches: c.2,
            reason: c.3,
            by: c.4,
            source: c.5,
        })
    });
    prop_oneof![
        request,
        issued,
        ended,
        job,
        opened,
        closed,
        created,
        standing,
        security_event().prop_map(AuditEvent::BadKey),
        security_event().prop_map(AuditEvent::BadAdminToken),
        security_event().prop_map(AuditEvent::CredentialRefused),
        security_event().prop_map(AuditEvent::ContainmentLifted),
    ]
}

fn command_item() -> impl Strategy<Value = CommandItem> {
    (
        (job_id(), ts(), s(), s(), tier(), any::<bool>(), s(), os()),
        (
            job_status(),
            os(),
            option::of(any::<i32>()),
            os(),
            option::of(any::<u64>()),
            option::of(any::<u64>()),
            option::of(request_id()),
        ),
    )
        .prop_map(|(a, b)| CommandItem {
            id: a.0,
            at: a.1,
            agent: a.2,
            host: a.3,
            tier: a.4,
            shell: a.5,
            command: a.6,
            cwd: a.7,
            status: b.0,
            via: b.1,
            exit_code: b.2,
            error: b.3,
            duration_ms: b.4,
            output_bytes: b.5,
            request_id: b.6,
        })
}

fn delegated() -> impl Strategy<Value = DelegatedRequest> {
    (platform(), s(), s(), request_status(), option::of(source())).prop_map(
        |(platform, what, resource, status, source)| DelegatedRequest {
            platform,
            what,
            resource,
            status,
            source,
        },
    )
}

fn tier_status() -> impl Strategy<Value = TierStatus> {
    (
        any::<bool>(),
        option::of(float()),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(|(enabled, armed_until, shell, totp)| TierStatus {
            enabled,
            armed_until,
            shell,
            totp,
        })
}

fn desktop_status() -> impl Strategy<Value = DesktopStatus> {
    (any::<bool>(), any::<bool>(), os(), option::of(float())).prop_map(
        |(enabled, present, away_reason, dnd_until)| DesktopStatus {
            enabled,
            present,
            away_reason,
            dnd_until,
        },
    )
}

fn status_object() -> impl Strategy<Value = StatusObject> {
    object().prop_map(|m| StatusObject::new(m).unwrap())
}

fn reply() -> impl Strategy<Value = Reply> {
    (
        call_id(),
        any::<bool>(),
        option::of(object().prop_map(|m| ReplyData::new(m).unwrap())),
        option::of(text::<0, 16384>()),
    )
        .prop_map(|(call_id, ok, data, error)| Reply {
            call_id,
            ok,
            data,
            error,
        })
}

fn name<const A: usize, const B: usize>() -> impl Strategy<Value = Text<A, B>> {
    "[a-z][a-z0-9-]{0,20}".prop_filter_map("in bounds", |v| Text::new(v).ok())
}

// ---------------------------------------------------------- round trips

fn round_trip<T>(value: &T) -> Result<(), TestCaseError>
where
    T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let v = serde_json::to_value(value).map_err(|e| TestCaseError::fail(e.to_string()))?;
    let back: T =
        serde_json::from_value(v.clone()).map_err(|e| TestCaseError::fail(format!("{e}: {v}")))?;
    prop_assert_eq!(&back, value);
    // And through text, as it travels.
    let text = serde_json::to_string(value).map_err(|e| TestCaseError::fail(e.to_string()))?;
    let back: T =
        serde_json::from_str(&text).map_err(|e| TestCaseError::fail(format!("{e}: {text}")))?;
    prop_assert_eq!(&back, value);
    Ok(())
}

macro_rules! round_trips {
    ($($name:ident: $strategy:expr;)*) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]
            $(
                #[test]
                fn $name(value in $strategy) {
                    round_trip(&value)?;
                }
            )*
        }
    };
}

round_trips! {
    rt_me: me();
    rt_attention_out: (any::<bool>(), strings()).prop_map(|(sent, desktops)| AttentionOut { sent, desktops });
    rt_request_out: request_out();
    rt_grant_out: grant_out();
    rt_credential_out: credential_out();
    rt_catalog: vec(platform_catalog(), 0..3).prop_map(|platforms| CatalogOut { platforms });
    rt_peer_entry: peer_entry();
    rt_check: (any::<bool>(), option::of(grant_id()), option::of(ts()), os(), option::of(peer_entry()))
        .prop_map(|(allowed, grant_id, expires_at, reason, peer)| A2aCheckOut { allowed, grant_id, expires_at, reason, peer });
    rt_session_out: (session_id(), s(), ts()).prop_map(|(session_id, name, created_at)| SessionOut { session_id, name, created_at });
    rt_session_closed: any::<u32>().prop_map(|threads_closed| SessionClosed { ok: True, threads_closed });
    rt_thread_out: thread_out();
    rt_thread_messages: (thread_out(), vec(message_out(), 0..3)).prop_map(|(thread, messages)| ThreadMessages { thread, messages });
    rt_message_sent: (message_id(), any::<u64>(), thread_state()).prop_map(|(message_id, seq, thread_state)| MessageSent { message_id, seq, thread_state });
    rt_events: (vec(thread_out(), 0..2), vec(thread_out(), 0..2), option::of(ts()))
        .prop_map(|(pending_opens, activity, cursor)| EventsSnapshot { pending_opens, activity, cursor });
    rt_webhook: prop_oneof![
        (thread_id(), s(), os(), any::<u64>()).prop_map(|(thread_id, from, topic, seq)| WebhookPing::ThreadOpen { thread_id, from, topic, seq }),
        (thread_id(), message_id(), s(), os(), any::<u64>()).prop_map(|(thread_id, message_id, from, topic, seq)| WebhookPing::Message { thread_id, message_id, from, topic, seq }),
        (thread_id(), os(), option::of(close_reason())).prop_map(|(thread_id, topic, close_reason)| WebhookPing::ThreadClosed { thread_id, topic, close_reason }),
    ];
    rt_wiki_list: (s(), strings(), vec((s(), s(), any::<u64>()), 0..3)).prop_map(|(repo, you_may_write, pages)| WikiList {
        repo, you_may_write, pages: pages.into_iter().map(|(path, title, bytes)| WikiPageEntry { path, title, bytes }).collect(),
    });
    rt_wiki_page: (s(), s(), os(), option::of((s(), s(), s())), s()).prop_map(|(path, sha, project, change, content)| WikiPage {
        path, sha, project, last_change: change.map(|(author, at, summary)| LastChange { author, at, summary }), content,
    });
    rt_wiki_search: (s(), any::<u64>(), vec((s(), s(), os(), strings()), 0..3)).prop_map(|(query, matches, results)| WikiSearch {
        query, matches, results: results.into_iter().map(|(path, title, project, lines)| WikiSearchHit { path, title, project, lines }).collect(),
    });
    rt_wiki_written: prop_oneof![
        (s(), s(), any::<bool>()).prop_map(|(path, sha, created)| WikiWritten::Written { path, sha, created }),
        (s(), s()).prop_map(|(path, sha)| WikiWritten::Unchanged { path, sha, unchanged: True }),
    ];
    rt_wiki_deleted: s().prop_map(|path| WikiDeleted { path, deleted: True });
    rt_audit_page: (vec(audit_event(), 0..4), ts(), any::<bool>()).prop_map(|(events, next, truncated)| AuditPage { events, next, truncated });
    rt_containment_entry: containment_entry();
    rt_contain_result: (containment_entry(), strings(), any::<u32>(), any::<u32>(), any::<u32>(), btree_map(s(), leaf(), 0..3))
        .prop_map(|(entry, agents, grants_revoked, requests_denied, threads_closed, daemons)| ContainResult {
            entry, agents, grants_revoked, requests_denied, threads_closed, daemons,
        });
    rt_lifted: vec(containment_entry(), 0..3).prop_map(|lifted| Lifted { lifted });
    rt_job_out: job_out();
    rt_job_summary: (job_out(), s()).prop_map(|(j, output_tail)| JobSummary {
        job_id: j.job_id, host: j.host, tier: j.tier, status: j.status, exit_code: j.exit_code, error: j.error,
        duration_ms: j.duration_ms, output_bytes: j.output_bytes, output_sha256: j.output_sha256,
        truncated: j.truncated, command: j.command, output_tail,
    });
    rt_shell_closed: any::<bool>().prop_map(|closed| ShellClosed { closed });
    rt_agent_out: agent_out();
    rt_agent_renamed: (agent_out(), s(), any::<u64>(), any::<u64>()).prop_map(|(agent, previous_name, rules, grants)| AgentRenamed { agent, previous_name, rules, grants });
    rt_disabled: strings().prop_map(|disabled| Disabled { disabled });
    rt_rule_out: (
        (rule_id(), pick![RuleAction::AutoApprove, RuleAction::AutoDeny], s(), os(), platform(), s()),
        (s(), option::of(object()), option::of(any::<u32>()), any::<bool>(), s(), s()),
    ).prop_map(|(a, b)| RuleOut {
        id: a.0, action: a.1, agent_pattern: a.2, delegator_pattern: a.3, platform: a.4, capability_pattern: a.5,
        resource_pattern: b.0, authority: b.1, max_duration_secs: b.2, enabled: b.3, created_by: b.4, notes: b.5,
    });
    rt_revoked: (grant_id(), grant_status()).prop_map(|(grant_id, status)| Revoked { ok: True, grant_id, status });
    rt_projects: (btree_map(s(), (s(), strings(), any::<bool>(), strings()), 0..3), os()).prop_map(|(p, wiki)| Projects {
        projects: p.into_iter().map(|(k, (description, repos, in_policy, agents))| (k, ProjectOut { description, repos, in_policy, agents })).collect(),
        wiki,
    });
    rt_pairing_code: (daemon_role(), "[a-z0-9][a-z0-9-]{0,20}", secret::<64>(), ts(), s()).prop_map(|(role, name, code, expires_at, broker_public_key)| PairingCodeOut {
        role, name: DaemonName::new(name).unwrap(), code, expires_at, broker_public_key,
    });
    rt_daemon_out: ((daemon_id(), daemon_role(), s(), s(), any::<bool>()), (option::of(ts()), option::of(ts()), os(), option::of(status_object())))
        .prop_map(|(a, b)| DaemonOut { id: a.0, role: a.1, name: a.2, fingerprint: a.3, online: a.4, paired_at: b.0, last_seen_at: b.1, version: b.2, status: b.3 });
    rt_broker_key: s().prop_map(|broker_public_key| BrokerKey { broker_public_key });
    rt_hosts: (
        (option::of(strings()), os(), option::of(ts()), option::of(lockdown_scope())),
        vec((s(), any::<bool>(), btree_map(tier(), tier_status(), 0..2), any::<bool>(), strings(),
             option::of((s(), s())), option::of(desktop_status())), 0..3),
    ).prop_map(|((hosts, by, at, scope), list)| HostsOut {
        lockdown: LockdownFlag { hosts, by, at, scope },
        hosts: list.into_iter().map(|(name, online, tiers, lockdown, templates, vm, desktop)| HostOut {
            name, online, tiers, lockdown, templates, vm: vm.map(|(unit, state)| VmStatus { unit, state }), desktop,
        }).collect(),
    });
    rt_lockdown_result: (lockdown_scope(), os(), btree_map(s(), s(), 0..3), any::<u32>(), any::<u32>())
        .prop_map(|(scope, host, daemons, grants_revoked, threads_closed)| LockdownResult { scope, host, daemons, grants_revoked, threads_closed });
    rt_unlock_result: (os(), btree_map(s(), s(), 0..3), strings()).prop_map(|(host, daemons, broker_locked)| UnlockResult { host, daemons, broker_locked });
    rt_decision_item: (
        (request_id(), ts(), option::of(ts()), s(), os(), platform(), s(), s()),
        (request_status(), option::of(source()), os(), os(), s(), any::<u32>()),
    ).prop_map(|(a, b)| DecisionItem {
        id: a.0, at: a.1, decided_at: a.2, agent: a.3, for_: a.4, platform: a.5, what: a.6, resource: a.7,
        status: b.0, source: b.1, by: b.2, reason: b.3, justification: b.4, duration_secs: b.5,
    });
    rt_command_item: command_item();
    rt_command_detail: (command_item(), os(), os(), s(), any::<bool>(), os()).prop_map(|(item, justification, decided_by, output, output_cut, output_sha256)| CommandDetail {
        item, justification, decided_by, output, output_cut, output_sha256,
    });
    rt_graph: (
        any::<u32>(), ts(),
        vec((s(), os(), os(), os(), placement(), agent_kind(), any::<bool>()), 0..3),
        vec((s(), s(), any::<u32>(), any::<u32>(), any::<u32>(), any::<u32>(), ts()), 0..3),
        vec(((thread_id(), s(), s(), os(), thread_state(), option::of(close_reason())), (any::<u32>(), any::<u32>(), ts(), ts())), 0..3),
    ).prop_map(|(hours, now, nodes, edges, threads)| A2aGraph {
        hours, now,
        nodes: nodes.into_iter().map(|(name, runtime, project, host, placement, kind, alive)| GraphNode { name, runtime, project, host, placement, kind, alive }).collect(),
        edges: edges.into_iter().map(|(from, to, threads, open, messages, requests, last)| GraphEdge { from, to, threads, open, messages, requests, last }).collect(),
        threads: threads.into_iter().map(|(a, b)| GraphThread {
            id: a.0, from: a.1, to: a.2, topic: a.3, state: a.4, close_reason: a.5, messages: b.0, requests: b.1, opened: b.2, last: b.3,
        }).collect(),
    });
    rt_admin_thread: (
        (thread_id(), s(), s(), os(), thread_state(), option::of(close_reason()), ts()),
        vec((any::<u64>(), ts(), s(), option::of(non_null()), s(), any::<bool>()), 0..3),
        vec(delegated(), 0..2),
    ).prop_map(|(a, messages, requests)| AdminThread {
        id: a.0, from: a.1, to: a.2, topic: a.3, state: a.4, close_reason: a.5, opened: a.6,
        messages: messages.into_iter().map(|(seq, at, from, kind, text, cut)| AdminMessage { seq, at, from, kind, text, cut }).collect(),
        requests,
    });
    rt_models_usage: (any::<bool>(), os(), os(), vec((s(), os(), os(), os(), placement(), float(), option::of(float())), 0..3))
        .prop_map(|(enabled, gateway, error, rows)| ModelsUsage {
            enabled, gateway, error,
            agents: rows.into_iter().map(|(agent, runtime, project, host, placement, spend, max_budget)| UsageRow { agent, runtime, project, host, placement, spend, max_budget }).collect(),
        });
    rt_chat_peer: (peer_entry(), os(), os(), os(), placement()).prop_map(|(peer, runtime, project, host, placement)| ChatPeer { peer, runtime, project, host, placement });
    rt_chat_thread_item: ((thread_id(), s(), os(), thread_state(), option::of(close_reason())), (ts(), ts(), any::<u64>(), s(), any::<bool>()))
        .prop_map(|(a, b)| ChatThreadItem { id: a.0, to: a.1, topic: a.2, state: a.3, close_reason: a.4, opened: b.0, last: b.1, last_seq: b.2, preview: b.3, last_from_operator: b.4 });
    rt_chat_view: (
        thread_out(),
        vec(((any::<u64>(), ts(), s(), option::of(non_null())), (os(), os(), os(), option::of(object()), os())), 0..3),
        vec((request_id(), delegated()), 0..2),
    ).prop_map(|(thread, messages, requests)| ChatThreadView {
        thread,
        messages: messages.into_iter().map(|(a, b)| ChatMessage { seq: a.0, at: a.1, from: a.2, kind: a.3, text: b.0, status: b.1, summary: b.2, payload: b.3, operator: b.4 }).collect(),
        requests: requests.into_iter().map(|(id, d)| ChatRequest { id, platform: d.platform, what: d.what, resource: d.resource, status: d.status, source: d.source }).collect(),
    });
    rt_operator_payload: (s(), s()).prop_map(|(t, o)| OperatorPayload::message(t, o));
    rt_client_registered: ((s(), any::<i64>(), os(), strings()), (strings(), strings(), pick![TokenAuthMethod::None, TokenAuthMethod::ClientSecretPost, TokenAuthMethod::ClientSecretBasic], option::of(secret::<256>()), option::of(any::<i64>())))
        .prop_map(|(a, b)| ClientRegistered {
            client_id: a.0, client_id_issued_at: a.1, client_name: a.2, redirect_uris: a.3, grant_types: b.0, response_types: b.1,
            token_endpoint_auth_method: b.2, client_secret: b.3, client_secret_expires_at: b.4,
        });
    rt_token_response: (secret::<256>(), any::<u64>(), secret::<256>()).prop_map(|(access_token, expires_in, refresh_token)| TokenResponse { access_token, token_type: Bearer, expires_in, refresh_token });
    rt_oauth_error: (pick![OAuthErrorCode::InvalidGrant, OAuthErrorCode::InvalidClient, OAuthErrorCode::InvalidClientMetadata, OAuthErrorCode::UnsupportedGrantType], s())
        .prop_map(|(e, d)| OAuthError::new(e, d));
    rt_as_metadata: s().prop_map(|b| AuthorizationServerMetadata::for_base(&b));
    rt_pr_metadata: (s(), strings(), strings(), s()).prop_map(|(resource, authorization_servers, bearer_methods_supported, resource_name)| ProtectedResourceMetadata { resource, authorization_servers, bearer_methods_supported, resource_name });
    rt_connector: ((s(), os(), strings(), os()), (ts(), option::of(ts()), option::of(ts()), any::<u32>()))
        .prop_map(|(a, b)| ConnectorOut { client_id: a.0, name: a.1, redirect_uris: a.2, agent: a.3, created_at: b.0, last_used_at: b.1, revoked_at: b.2, live_authorizations: b.3 });
    rt_connector_revoked: s().prop_map(|revoked| ConnectorRevoked { revoked });
    rt_pair_response: (s(), hex64(), s()).prop_map(|(broker_public_key, proof, fingerprint)| PairResponse { broker_public_key, proof, fingerprint });
    rt_ok: Just(Ok::default());
    rt_error_body: prop_oneof![
        s().prop_map(ErrorBody::text),
        vec((s(), vec(leaf(), 0..3), s(), option::of(non_null()), option::of(object())), 0..2).prop_map(|issues| ErrorBody {
            detail: Detail::Issues(issues.into_iter().map(|(kind, loc, msg, input, ctx)| Issue { kind, loc, msg, input, ctx }).collect()),
        }),
    ];
    rt_host_status: (
        (os(), os(), option::of(float()), btree_map(tier(), tier_status(), 0..2), any::<u32>(), any::<u32>()),
        (any::<bool>(), option::of((s(), s())), strings(), option::of(desktop_status()), os()),
    ).prop_map(|(a, b)| HostStatus {
        version: a.0, role: a.1, started_at: a.2, tiers: a.3, jobs: a.4, shells: a.5, lockdown: b.0,
        vm: b.1.map(|(unit, state)| VmStatus { unit, state }), templates: b.2, desktop: b.3, error: b.4,
    });
    rt_sandbox_status: ((os(), os(), os(), any::<u32>(), any::<u32>()), (btree_map(s(), any::<u32>(), 0..3), any::<bool>(), any::<u32>(), os()))
        .prop_map(|(a, b)| SandboxStatus { version: a.0, role: a.1, host: a.2, agents: a.3, projects: a.4, conversations: b.0, lockdown: b.1, processes: b.2, error: b.3 });
    rt_host_to_broker: prop_oneof![
        status_object().prop_map(|status| HostToBroker::Heartbeat(crate::daemon::Heartbeat { status })),
        reply().prop_map(HostToBroker::Reply),
        (job_id(), option::of(any::<u32>()), "[A-Za-z0-9+/=]{0,40}").prop_map(|(job_id, chunk, data)| HostToBroker::JobOutput(JobOutput { job_id, chunk, data: Text::new(data).unwrap() })),
        (job_id(), option::of(any::<i32>()), option::of(text::<0, 16384>()), option::of(float()), any::<u64>(), hex64(), any::<bool>())
            .prop_map(|(job_id, exit_code, error, duration_secs, bytes, sha256, truncated)| HostToBroker::JobDone(JobDone { job_id, exit_code, error, duration_secs, bytes, sha256, truncated, lost: false })),
        (any::<bool>(), any::<bool>(), option::of(text::<0, 256>()), option::of(float()))
            .prop_map(|(enabled, present, away_reason, dnd_until)| HostToBroker::Presence(Presence { enabled, present, away_reason, dnd_until })),
        (uuid(), pick![Answer::Allow, Answer::Deny, Answer::Mute, Answer::Discord, Answer::Timeout], any::<bool>())
            .prop_map(|(u, answer, authorized)| HostToBroker::PromptAnswer(PromptAnswer { prompt_id: u.hyphenated().to_string().parse::<PromptId>().unwrap(), answer, authorized })),
    ];
    rt_broker_to_host: prop_oneof![
        (job_id(), call_id()).prop_map(|(job_id, call_id)| BrokerToHost::JobKill(JobRef { job_id, call_id })),
        (job_id(), call_id()).prop_map(|(job_id, call_id)| BrokerToHost::JobAck(JobRef { job_id, call_id })),
        (request_id(), call_id()).prop_map(|(shell_id, call_id)| BrokerToHost::ShellClose(ShellRef { shell_id, call_id })),
        (any::<bool>(), call_id()).prop_map(|(kill_vm, call_id)| BrokerToHost::Lockdown(Lockdown { kill_vm, call_id })),
        ("[0-9]{6}", call_id()).prop_map(|(t, call_id)| BrokerToHost::Unlock(Unlock { totp: WireSecret::new(t).unwrap(), call_id })),
        (option::of(1u64..=crate::duration::MAX_HOST_DURATION_SECS), call_id()).prop_map(|(d, call_id)| BrokerToHost::Dnd(Dnd { duration: d.map(|d| crate::duration::HostDuration::from_secs(d).unwrap()), call_id })),
        (uuid(), call_id()).prop_map(|(u, call_id)| BrokerToHost::PromptCancel(PromptCancel { prompt_id: u.hyphenated().to_string().parse().unwrap(), call_id })),
        (text::<0, 1024>(), text::<0, 4096>(), pick![Urgency::Low, Urgency::Normal, Urgency::Critical], call_id())
            .prop_map(|(title, text, urgency, call_id)| BrokerToHost::Notify(Notify { title, text, urgency, call_id })),
    ];
    rt_broker_to_sandbox: prop_oneof![
        (agent_id(), name::<1, 128>(), option::of(name::<0, 64>()), option::of(name::<0, 64>()), secret::<512>(), call_id())
            .prop_map(|(agent_id, name, runtime, project, api_key, call_id)| BrokerToSandbox::Key(KeyDelivery { agent_id, name, runtime, project, api_key, call_id })),
        (grant_id(), name::<1, 64>(), name::<1, 64>(), pick![ProjectAccessName::Read, ProjectAccessName::Write], call_id())
            .prop_map(|(grant_id, project, target, access, call_id)| BrokerToSandbox::ProjectGrant(ProjectGrant { grant_id, project, target, access, call_id })),
        (grant_id(), name::<1, 64>(), name::<1, 64>(), call_id())
            .prop_map(|(grant_id, project, target, call_id)| BrokerToSandbox::ProjectRevoke(ProjectRevoke { grant_id, project, target, call_id })),
        call_id().prop_map(|call_id| BrokerToSandbox::Unlock(SandboxUnlock { call_id })),
        (vec(name::<1, 128>(), 0..4), call_id()).prop_map(|(agents, call_id)| BrokerToSandbox::AgentsContained(AgentsContained { agents: BoundedVec::new(agents).unwrap(), call_id })),
    ];
    rt_sandbox_to_broker: prop_oneof![
        status_object().prop_map(|status| SandboxToBroker::Heartbeat(crate::daemon::Heartbeat { status })),
        reply().prop_map(SandboxToBroker::Reply),
        agent_id().prop_map(|agent_id| SandboxToBroker::KeyAck(KeyAck { agent_id })),
        name::<1, 128>().prop_map(|name| SandboxToBroker::KeyRotate(KeyRotate { name })),
    ];
}

// ------------------------------------------------------------- shapes

fn sample_request() -> RequestOut {
    let id: RequestId = "0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9".parse().unwrap();
    RequestOut {
        id,
        agent: "claude-x".into(),
        platform: Platform::A2a,
        capability: "talk".into(),
        resource: "bob".into(),
        scope: Map::new(),
        justification: "j".into(),
        requested_duration_secs: 600,
        status: RequestStatus::AwaitingHuman,
        attempt: 1,
        decision_source: None,
        decision_reason: None,
        approved_duration_secs: None,
        approved_scope: None,
        approved_resource: None,
        grant_id: None,
        delegator: None,
        delegation_thread_id: None,
        created_at: OffsetDateTime::UNIX_EPOCH,
        guidance: guidance(RequestStatus::AwaitingHuman, id, None),
    }
}

#[test]
fn request_out_has_every_key() {
    let v = serde_json::to_value(sample_request()).unwrap();
    let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    let mut want = vec![
        "id",
        "agent",
        "platform",
        "capability",
        "resource",
        "scope",
        "justification",
        "requested_duration_secs",
        "status",
        "attempt",
        "decision_source",
        "decision_reason",
        "approved_duration_secs",
        "approved_scope",
        "approved_resource",
        "grant_id",
        "delegator",
        "delegation_thread_id",
        "created_at",
        "guidance",
    ];
    want.sort_unstable();
    assert_eq!(keys, want);
    assert_eq!(v["created_at"], json!("1970-01-01T00:00:00.000000Z"));
    assert!(v["guidance"].as_str().unwrap().contains("Discord"));
    // Never: raw authorities, risk notes, who decided, the session.
    for hidden in [
        "authority",
        "approved_authority",
        "risk_notes",
        "decided_by",
        "session_id",
    ] {
        assert!(v.get(hidden).is_none());
    }
}

#[test]
fn guidance_texts() {
    let id: RequestId = "0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9".parse().unwrap();
    let grant: GrantId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".parse().unwrap();
    assert_eq!(guidance(RequestStatus::Pending, id, None), None);
    assert_eq!(guidance(RequestStatus::Approved, id, None), None);
    assert_eq!(guidance(RequestStatus::Provisioning, id, None), None);
    assert_eq!(
        guidance(RequestStatus::Granted, id, Some(grant)).unwrap(),
        "Granted. If the grant carries a credential (a token, an account, a created repo's URL), \
         fetch it with get_credential(\"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\") / \
         GET /v1/grants/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/credential — and re-fetch rather than caching it."
    );
    assert!(
        guidance(RequestStatus::Granted, id, None)
            .unwrap()
            .contains("get_credential(\"?\")")
    );
    assert_eq!(
        guidance(RequestStatus::LlmDenied, id, None).unwrap(),
        "Denied by LLM review — see decision_reason. Retry with a revised justification that \
         answers it (retry_request / POST /v1/requests/0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9/retry), \
         or ask for human review (escalate_request / POST /v1/requests/0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9/escalate)."
    );
}

#[test]
fn credential_out_keeps_null_keys() {
    let a2a = CredentialOut::note_only(
        CredentialKind::A2aGrant,
        "a2a grants are check-based; open a thread via POST /v1/a2a/threads",
    );
    assert_eq!(
        serde_json::to_value(&a2a).unwrap(),
        json!({"kind": "a2a_grant", "value": null, "username": null, "url": null,
               "expires_at": null,
               "note": "a2a grants are check-based; open a thread via POST /v1/a2a/threads"})
    );
    let token = CredentialOut {
        kind: CredentialKind::GithubInstallationToken,
        value: Some(WireSecret::new("ghs_secret").unwrap()),
        username: None,
        url: None,
        expires_at: Some(OffsetDateTime::UNIX_EPOCH),
        note: None,
    };
    assert!(!format!("{token:?}").contains("ghs_secret"));
    assert_eq!(
        serde_json::to_value(&token).unwrap()["value"],
        json!("ghs_secret")
    );
}

#[test]
fn catalog_drops_only_model_nulls() {
    let mut mcp = PlatformCatalog::new(Platform::Mcp, "use", "<server>");
    mcp.capabilities = Some(vec!["use".into()]);
    mcp.servers = Some(vec![McpServerEntry {
        name: "search".into(),
        url: "https://mcp.example".into(),
        description: "".into(),
        tools: None,
    }]);
    let mut k8s = PlatformCatalog::new(Platform::Kubernetes, "<role name>", "<namespace>");
    k8s.roles = Some(vec![CatalogEntry {
        name: "view".into(),
        description: None,
        typical_disposition: Some(Disposition::AutoApprove),
    }]);
    k8s.namespace_allowlist = Some(Vec::new());
    let v = serde_json::to_value(CatalogOut {
        platforms: vec![mcp, k8s],
    })
    .unwrap();
    assert_eq!(
        v,
        json!({"platforms": [
            {"platform": "mcp", "capability_hint": "use", "resource_hint": "<server>",
             "capabilities": ["use"],
             "servers": [{"name": "search", "url": "https://mcp.example", "description": "", "tools": null}]},
            {"platform": "kubernetes", "capability_hint": "<role name>", "resource_hint": "<namespace>",
             "roles": [{"name": "view", "typical_disposition": "auto-approve"}],
             "namespace_allowlist": []},
        ]})
    );
}

#[test]
fn agent_out_null_dropping() {
    let agent = AgentOut {
        id: "11111111-2222-4333-8444-555555555555".parse().unwrap(),
        name: "new-agent".into(),
        description: "".into(),
        kind: AgentKind::Ephemeral,
        webhook_url: None,
        lldap_username: None,
        lldap_managed: false,
        disabled: false,
        last_seen_at: None,
        parent: None,
        sandbox: None,
        runtime: None,
        project: None,
        host: None,
        placement: Placement::Host,
        lease_expires_at: None,
        api_key: Some(WireSecret::new("aa_0123456789ab_x").unwrap()),
        webhook_secret: None,
    };
    let full = serde_json::to_value(&agent).unwrap();
    assert_eq!(full["webhook_url"], Value::Null);
    let lean = agent.without_nulls().unwrap();
    assert!(lean.get("webhook_url").is_none());
    assert_eq!(lean["api_key"], json!("aa_0123456789ab_x"));
    // Both shapes read back.
    let _: AgentOut = serde_json::from_value(lean).unwrap();
    assert!(!format!("{agent:?}").contains("aa_0123456789ab_x"));
}

#[test]
fn thread_shapes_from_the_spec() {
    let t = json!({
        "thread_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "peer": "auto-r", "role": "initiator",
        "topic": null, "state": "pending_open", "close_reason": null, "close_note": null,
        "grant_id": "11111111-2222-4333-8444-555555555555", "last_seq": 1,
        "created_at": "2026-01-01T00:00:00+00:00", "accepted_at": null, "closed_at": null,
        "last_activity_at": "2026-01-01T00:00:00.000005+00:00", "peer_last_seen_at": null,
        "peer_alive": false,
    });
    let parsed: ThreadOut = serde_json::from_value(t).unwrap();
    let out = serde_json::to_value(&parsed).unwrap();
    // Re-emitted in the one format.
    assert_eq!(out["created_at"], json!("2026-01-01T00:00:00.000000Z"));
    assert_eq!(
        out["last_activity_at"],
        json!("2026-01-01T00:00:00.000005Z")
    );
    let events: EventsSnapshot = serde_json::from_value(json!({
        "pending_opens": [], "activity": [], "cursor": "2026-01-01T00:00:00.123456+00:00"
    }))
    .unwrap();
    assert_eq!(
        serde_json::to_value(&events).unwrap()["cursor"],
        json!("2026-01-01T00:00:00.123456Z")
    );
}

#[test]
fn audit_items_are_tagged_by_kind() {
    let v = json!({"kind": "security.bad_key", "id": "s3", "at": "2026-01-01T00:00:00Z",
                   "client": "10.0.0.1", "path": "/v1/me", "key_id": "0123456789ab",
                   "agent": null, "reason": "wrong secret"});
    let e: AuditEvent = serde_json::from_value(v).unwrap();
    let AuditEvent::BadKey(ref s) = e else {
        panic!("{e:?}")
    };
    assert_eq!(s.fields.get("reason"), Some(&Some("wrong secret".into())));
    assert_eq!(s.fields.get("agent"), Some(&None));
    let back = serde_json::to_value(&e).unwrap();
    assert_eq!(back["kind"], json!("security.bad_key"));
    assert_eq!(back["key_id"], json!("0123456789ab"));
    let created = json!({"kind": "agent.created", "id": "11111111-2222-4333-8444-555555555555",
        "at": "2026-01-01T00:00:00Z", "status": "created", "agent": "x", "agent_kind": "service",
        "runtime": null, "project": null, "host": null, "placement": "host", "parent": null});
    let _: AuditEvent = serde_json::from_value(created).unwrap();
    let wrong = json!({"kind": "agent.created", "id": "11111111-2222-4333-8444-555555555555",
        "at": "2026-01-01T00:00:00Z", "status": "deleted", "agent": "x", "agent_kind": "service",
        "runtime": null, "project": null, "host": null, "placement": "host", "parent": null});
    assert!(serde_json::from_value::<AuditEvent>(wrong).is_err());
}

#[test]
fn reply_data_reads_as_the_call_answer() {
    use crate::daemon::host::{PrecheckReply, ShellOpenedReply};
    let r: Reply = serde_json::from_value(json!({"call_id": "4c0ffee0c0ffee0c0ffee0c0ffee0c0f",
        "ok": true, "data": {"expires_at": 1_767_225_600.5}}))
    .unwrap();
    let opened: ShellOpenedReply = r.data_as().unwrap();
    assert!((opened.expires_at - 1_767_225_600.5).abs() < 1e-6);
    let r: Reply = serde_json::from_value(json!({"call_id": null, "ok": true})).unwrap();
    let p: PrecheckReply = r.data_as().unwrap();
    assert_eq!(p, PrecheckReply::default());
}

#[test]
fn statuses_read_leniently() {
    let h: HostStatus =
        serde_json::from_value(json!({"error": "status unavailable", "version": "0.1",
                                                       "future": 1}))
        .unwrap();
    assert_eq!(h.error.as_deref(), Some("status unavailable"));
    assert!(h.tiers.is_empty());
    let s: SandboxStatus = serde_json::from_value(json!({})).unwrap();
    assert_eq!(s, SandboxStatus::default());
    let _ = BTreeMap::<String, u8>::new();
}

//! Homelab / LLDAP (provisioners spec §3, §14), against a fake LLDAP
//! (GraphQL over HTTP) and a fake LDAP server (password changes).

use std::collections::{BTreeMap, BTreeSet};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use agent_auth_broker::provisioners::Provisioner;
use agent_auth_broker::provisioners::http::Http;
use agent_auth_broker::provisioners::ldap::LdapTarget;
use agent_auth_broker::provisioners::ldap::decode::{self, Request};
use agent_auth_broker::provisioners::lldap::LldapProvisioner;
use agent_auth_core::policy::schema::HomelabConfig;
use agent_auth_core::{Authority, Platform};
use agent_auth_crypto::Secret;
use agent_auth_store::Store;
use serde_json::{Value, json};
use sqlx::PgPool;

use crate::common::*;

#[derive(Debug, Default)]
pub struct LldapState {
    groups: Vec<(i64, String)>,
    /// id → (display name, groups)
    users: BTreeMap<String, (String, BTreeSet<i64>)>,
    adds: Vec<(String, i64)>,
    removes: Vec<(String, i64)>,
    creates: Vec<Value>,
    logins: usize,
    /// Every GraphQL call fails: `Some(503)` with that status, `Some(200)`
    /// with a GraphQL error (LLDAP's database down).
    outage: Option<u16>,
}

fn gql_error() -> R {
    r(200, json!({"errors": [{"message": "database error"}]}))
}

fn lldap_handler(s: &Arc<Mutex<LldapState>>, c: &Call) -> R {
    let mut st = s.lock().unwrap();
    if c.is("POST", "/auth/simple/login") {
        st.logins += 1;
        return if c.body == json!({"username": "admin", "password": "pw"}) {
            r(200, json!({"token": "jwt-1"}))
        } else {
            r(401, json!({}))
        };
    }
    if !c.is("POST", "/api/graphql") || c.header("authorization") != "Bearer jwt-1" {
        return r(401, json!({}));
    }
    match st.outage {
        Some(200) => return gql_error(),
        Some(status) => return r(status, json!({})),
        None => {}
    }
    let q = c.body["query"].as_str().unwrap_or("");
    let v = &c.body["variables"];
    let user = v["user"].as_str().unwrap_or("").to_owned();
    let group = v["group"].as_i64().unwrap_or(-1);
    if q.contains("AddUserToGroup") {
        let done = st
            .users
            .get_mut(&user)
            .is_some_and(|(_, gs)| gs.insert(group));
        if done {
            st.adds.push((user, group));
            r(200, json!({"data": {"addUserToGroup": {"ok": true}}}))
        } else {
            gql_error()
        }
    } else if q.contains("RemoveUserFromGroup") {
        let done = st
            .users
            .get_mut(&user)
            .is_some_and(|(_, gs)| gs.remove(&group));
        if done {
            st.removes.push((user, group));
            r(200, json!({"data": {"removeUserFromGroup": {"ok": true}}}))
        } else {
            gql_error()
        }
    } else if q.contains("CreateUser") {
        let u = v["user"].clone();
        st.users.insert(
            u["id"].as_str().unwrap().to_owned(),
            (
                u["displayName"].as_str().unwrap().to_owned(),
                BTreeSet::new(),
            ),
        );
        st.creates.push(u);
        r(200, json!({"data": {"createUser": {"id": "x"}}}))
    } else if q.contains("UserExists") {
        match st.users.get(&user) {
            Some((d, _)) => r(
                200,
                json!({"data": {"user": {"id": user, "displayName": d}}}),
            ),
            None => gql_error(),
        }
    } else if q.contains("ListUsers") {
        r(
            200,
            json!({"data": {"users": st.users.keys().map(|id| json!({"id": id})).collect::<Vec<_>>()}}),
        )
    } else if q.contains("UserGroups") {
        match st.users.get(&user) {
            Some((_, gs)) => r(
                200,
                json!({"data": {"user": {"groups": gs.iter().map(|g| json!({"id": g})).collect::<Vec<_>>()}}}),
            ),
            None => gql_error(),
        }
    } else if q.contains("groups {") {
        r(
            200,
            json!({"data": {"groups": st.groups.iter().map(|(id, n)| json!({"id": id, "displayName": n})).collect::<Vec<_>>()}}),
        )
    } else {
        gql_error()
    }
}

/// A fake LDAP server: accepts the admin's bind and records password
/// changes (user DN → password). `fail` makes password changes fail.
#[derive(Clone, Default)]
pub struct FakeLdap {
    pub binds: Arc<Mutex<Vec<(String, String)>>>,
    pub passwords: Arc<Mutex<Vec<(String, String)>>>,
    pub fail: Arc<AtomicBool>,
    pub url: String,
}

impl FakeLdap {
    pub fn start() -> FakeLdap {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut f = FakeLdap {
            url: format!("ldap://{}", listener.local_addr().unwrap()),
            ..FakeLdap::default()
        };
        let me = f.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut conn) = conn else { return };
                let me = me.clone();
                std::thread::spawn(move || {
                    use std::io::Write;
                    let mut bound = false;
                    while let Some(msg) = decode::read(&mut conn) {
                        let reply = match decode::request(&msg) {
                            Some(Request::Bind { id, dn, password }) => {
                                bound = dn == "uid=admin,ou=people,dc=example,dc=com"
                                    && password == "pw";
                                me.binds.lock().unwrap().push((dn, password));
                                decode::result(id, 0x61, if bound { 0 } else { 49 }, "")
                            }
                            Some(Request::PasswordModify {
                                id,
                                user,
                                new_password,
                            }) => {
                                if !bound || me.fail.load(Ordering::SeqCst) {
                                    decode::result(id, 0x78, 50, "insufficient access")
                                } else {
                                    me.passwords.lock().unwrap().push((user, new_password));
                                    decode::result(id, 0x78, 0, "")
                                }
                            }
                            _ => return,
                        };
                        if conn.write_all(&reply).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        f.url = f.url.clone();
        f
    }

    pub fn last_password(&self) -> Option<(String, String)> {
        self.passwords.lock().unwrap().last().cloned()
    }
}

pub struct L {
    pub store: Store,
    pub fake: Fake,
    pub state: Arc<Mutex<LldapState>>,
    pub ldap: FakeLdap,
    pub p: LldapProvisioner,
}

pub fn config(allowed: &[&str]) -> HomelabConfig {
    let mut c = HomelabConfig::default();
    c.allowed_groups = allowed.iter().map(|s| (*s).to_owned()).collect();
    c
}

pub async fn setup_with(pool: PgPool, cfg: HomelabConfig, managed: bool) -> L {
    let state = Arc::new(Mutex::new(LldapState {
        groups: vec![
            (1, "lldap_admin".into()),
            (4, "svc-gitea".into()),
            (5, "media".into()),
        ],
        ..LldapState::default()
    }));
    let s2 = state.clone();
    let fake = Fake::start(move |c| lldap_handler(&s2, c)).await;
    let ldap = FakeLdap::start();
    let target = LdapTarget::parse(&ldap.url, "dc=example,dc=com", false).unwrap();
    let p = LldapProvisioner::new(
        &format!("{}/", fake.url),
        "admin",
        Secret::new("pw".to_owned()),
        cfg,
        managed.then(secret_box),
        managed.then_some(target),
        Http::new().unwrap(),
    );
    L {
        store: Store::from_pool(pool),
        fake,
        state,
        ldap,
        p,
    }
}

impl L {
    fn user(&self, id: &str, display: &str, groups: &[i64]) {
        self.state.lock().unwrap().users.insert(
            id.into(),
            (display.into(), groups.iter().copied().collect()),
        );
    }
    fn adds(&self) -> Vec<(String, i64)> {
        self.state.lock().unwrap().adds.clone()
    }
    fn removes(&self) -> Vec<(String, i64)> {
        self.state.lock().unwrap().removes.clone()
    }
    fn creates(&self) -> Vec<Value> {
        self.state.lock().unwrap().creates.clone()
    }
    fn member(&self, user: &str, group: i64) -> bool {
        self.state
            .lock()
            .unwrap()
            .users
            .get(user)
            .is_some_and(|(_, g)| g.contains(&group))
    }
}

async fn hand_registered(t: &L, name: &str, user: &str) -> agent_auth_store::agents::AgentRow {
    t.user(user, "hand made", &[]);
    agent_with(
        &t.store,
        AgentSpec {
            lldap_username: Some(user),
            ..AgentSpec::named(name)
        },
    )
    .await
}

#[sqlx::test(migrations = "../store/migrations")]
async fn grant_then_expiry_adds_then_removes(pool: PgPool) {
    let t = setup_with(pool, config(&["svc-gitea"]), false).await;
    let a = hand_registered(&t, "homelab-agent", "svc-homelab-agent").await;
    let g = granted(&t.store, &t.p, a.id, &Authority::Homelab, "svc-gitea").await;
    assert_eq!(t.adds(), [("svc-homelab-agent".to_owned(), 4)]);
    assert_eq!(
        g.provisioner_state,
        json!({"lldap_user": "svc-homelab-agent", "group": "svc-gitea", "group_id": 4})
    );
    let c = credential(&t.store, &t.p, &g).await.unwrap();
    assert_eq!(kind_name(&c), "lldap_group");
    assert!(c.value.is_none());
    assert_eq!(c.username.as_deref(), Some("svc-homelab-agent"));
    assert_eq!(
        c.note.as_deref(),
        Some(
            "your service account is now in group 'svc-gitea'; authenticate to Authelia-protected services with your own credentials"
        )
    );
    expire(&t.store, &t.p, g.id).await.unwrap();
    assert_eq!(t.removes(), [("svc-homelab-agent".to_owned(), 4)]);
    assert_eq!(
        credential(&t.store, &t.p, &g).await.unwrap_err().text(),
        "grant is not active"
    );
    // Hand-registered: no account made, no password set.
    assert!(t.creates().is_empty());
    assert!(t.ldap.passwords.lock().unwrap().is_empty());
}

#[sqlx::test(migrations = "../store/migrations")]
async fn existing_membership_and_out_of_band_removal_are_fine(pool: PgPool) {
    let t = setup_with(pool, config(&[]), false).await;
    let a = hand_registered(&t, "homelab-agent", "svc-homelab-agent").await;
    t.user("svc-homelab-agent", "hand made", &[4]);
    let g = granted(&t.store, &t.p, a.id, &Authority::Homelab, "svc-gitea").await;
    assert!(t.adds().is_empty(), "verified, not re-added");
    t.user("svc-homelab-agent", "hand made", &[]);
    expire(&t.store, &t.p, g.id).await.unwrap();
    assert!(t.removes().is_empty());
}

#[sqlx::test(migrations = "../store/migrations")]
async fn overlapping_grants_keep_the_membership_until_the_last(pool: PgPool) {
    let t = setup_with(pool, config(&[]), false).await;
    let a = hand_registered(&t, "homelab-agent", "svc-homelab-agent").await;
    let g1 = granted(&t.store, &t.p, a.id, &Authority::Homelab, "svc-gitea").await;
    let g2 = granted(&t.store, &t.p, a.id, &Authority::Homelab, "svc-gitea").await;
    expire(&t.store, &t.p, g1.id).await.unwrap();
    assert!(t.removes().is_empty());
    assert!(t.member("svc-homelab-agent", 4));
    expire(&t.store, &t.p, g2.id).await.unwrap();
    assert_eq!(t.removes().len(), 1);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn grants_lapsing_in_one_tick_remove_once(pool: PgPool) {
    let t = setup_with(pool, config(&[]), false).await;
    let a = hand_registered(&t, "homelab-agent", "svc-homelab-agent").await;
    let g1 = granted(&t.store, &t.p, a.id, &Authority::Homelab, "svc-gitea").await;
    let g2 = granted(&t.store, &t.p, a.id, &Authority::Homelab, "svc-gitea").await;
    let tx = t.store.begin().await.unwrap();
    agent_auth_store::grants::expire_now(&tx, g1.id, now())
        .await
        .unwrap();
    agent_auth_store::grants::expire_now(&tx, g2.id, now())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    revoke_due(&t.store, &t.p, g1.id).await.unwrap();
    revoke_due(&t.store, &t.p, g2.id).await.unwrap();
    assert_eq!(t.removes().len(), 1);
    assert!(!t.member("svc-homelab-agent", 4));
    for g in [g1.id, g2.id] {
        assert_eq!(
            grant(&t.store, g).await.status,
            agent_auth_core::GrantStatus::Expired
        );
    }
}

#[sqlx::test(migrations = "../store/migrations")]
async fn administration_groups_are_never_brokered(pool: PgPool) {
    for allowed in [
        vec![],
        vec!["svc-gitea"],
        vec!["svc-gitea", "lldap_admin", "LLDAP_Password_Manager"],
    ] {
        let t = setup_with(pool.clone(), config(&allowed), true).await;
        let a = agent(&t.store, &format!("a{}", allowed.len())).await;
        for group in [
            "lldap_admin",
            "lldap_password_manager",
            "lldap_strict_readonly",
            " LLDAP_ADMIN ",
        ] {
            let err = validate(
                &t.store,
                &t.p,
                &a,
                Platform::Homelab,
                "group",
                json!({}),
                group,
            )
            .await
            .unwrap_err();
            assert!(
                err.ends_with("is never brokered (it administers LLDAP itself)"),
                "{err}"
            );
        }
        // And provisioning refuses it too, should one get through.
        let g = provisioning(&t.store, a.id, &Authority::Homelab, "lldap_admin", 3600).await;
        assert!(
            provision(&t.store, &t.p, &g)
                .await
                .unwrap_err()
                .contains("never brokered")
        );
        assert!(t.adds().is_empty());
        let c = t.p.catalog(&a).unwrap();
        assert!(!c.to_string().contains("lldap_"), "{c}");
    }
}

#[sqlx::test(migrations = "../store/migrations")]
async fn validation(pool: PgPool) {
    let t = setup_with(pool.clone(), config(&["svc-gitea"]), true).await;
    let a = agent(&t.store, "fresh").await;
    let ok = validate(
        &t.store,
        &t.p,
        &a,
        Platform::Homelab,
        "group",
        json!({}),
        " svc-gitea ",
    )
    .await
    .unwrap();
    assert_eq!(ok.resource, "svc-gitea");
    assert_eq!(
        validate(
            &t.store,
            &t.p,
            &a,
            Platform::Homelab,
            "group",
            json!({}),
            "media"
        )
        .await
        .unwrap_err(),
        "group 'media' is not brokered (allowed_groups)"
    );
    // Managed accounts off (policy) or unavailable (no key): an agent
    // without an account is refused.
    let mut off = config(&["svc-gitea"]);
    off.managed_accounts = false;
    for t in [
        setup_with(pool.clone(), off, true).await,
        setup_with(pool.clone(), config(&["svc-gitea"]), false).await,
    ] {
        assert_eq!(
            validate(
                &t.store,
                &t.p,
                &a,
                Platform::Homelab,
                "group",
                json!({}),
                "svc-gitea"
            )
            .await
            .unwrap_err(),
            "agent 'fresh' has no LLDAP service account configured"
        );
    }
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_managed_account_is_made_once_and_handed_out(pool: PgPool) {
    let t = setup_with(pool, config(&[]), true).await;
    let a = agent(&t.store, "Worker").await;
    let g = granted(&t.store, &t.p, a.id, &Authority::Homelab, "svc-gitea").await;
    assert_eq!(
        t.creates(),
        [
            json!({"id": "svc-worker", "email": "svc-worker@agents.invalid", "displayName": "Worker (agent-auth managed)"})
        ]
    );
    assert_eq!(t.adds(), [("svc-worker".to_owned(), 4)]);
    assert_eq!(
        t.ldap.binds.lock().unwrap()[0],
        (
            "uid=admin,ou=people,dc=example,dc=com".to_owned(),
            "pw".to_owned()
        )
    );
    let (user, password) = t.ldap.last_password().unwrap();
    assert_eq!(user, "uid=svc-worker,ou=people,dc=example,dc=com");
    assert_eq!(password.len(), 43);
    let row = reload(&t.store, a.id).await;
    assert_eq!(row.lldap_username.as_deref(), Some("svc-worker"));
    let sealed = row.lldap_password_encrypted.unwrap();
    assert!(!sealed.contains(&password));
    // INV-L2: not in the provisioner state.
    assert!(!g.provisioner_state.to_string().contains(&password));

    let c = credential(&t.store, &t.p, &g).await.unwrap();
    assert_eq!(
        (kind_name(&c).as_str(), expose(&c), c.username.as_deref()),
        ("lldap_account", password.as_str(), Some("svc-worker"))
    );
    assert_eq!(
        c.note.as_deref(),
        Some(
            "LLDAP service account 'svc-worker' is in group 'svc-gitea'; log in to Authelia-protected services with this username/password"
        )
    );

    // A second grant: no new account, no new password.
    granted(&t.store, &t.p, a.id, &Authority::Homelab, "media").await;
    assert_eq!(t.creates().len(), 1);
    assert_eq!(t.ldap.passwords.lock().unwrap().len(), 1);
    assert_eq!(
        reload(&t.store, a.id)
            .await
            .lldap_password_encrypted
            .unwrap(),
        sealed
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_leftover_account_of_this_agent_is_adopted(pool: PgPool) {
    let t = setup_with(pool, config(&[]), true).await;
    t.user("svc-worker", "Worker (agent-auth managed)", &[]);
    let a = agent(&t.store, "Worker").await;
    granted(&t.store, &t.p, a.id, &Authority::Homelab, "svc-gitea").await;
    assert!(t.creates().is_empty());
    assert_eq!(t.ldap.passwords.lock().unwrap().len(), 1);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn someone_elses_account_is_never_taken_over(pool: PgPool) {
    let t = setup_with(pool, config(&[]), true).await;
    // An LLDAP user with the managed name that the broker did not make
    // for this agent.
    t.user("svc-human", "Human Being", &[1]);
    let a = agent(&t.store, "human").await;
    let g = provisioning(&t.store, a.id, &Authority::Homelab, "svc-gitea", 3600).await;
    let err = provision(&t.store, &t.p, &g).await.unwrap_err();
    assert_eq!(
        err,
        "LLDAP user 'svc-human' exists and was not created by the broker for this agent; refusing to adopt it"
    );

    // A case variant of an agent that already has its managed account.
    let foo = agent(&t.store, "Foo").await;
    granted(&t.store, &t.p, foo.id, &Authority::Homelab, "svc-gitea").await;
    let foo2 = agent(&t.store, "foo").await;
    let g = provisioning(&t.store, foo2.id, &Authority::Homelab, "svc-gitea", 3600).await;
    assert_eq!(
        provision(&t.store, &t.p, &g).await.unwrap_err(),
        "LLDAP account 'svc-foo' belongs to another agent; refusing to adopt it"
    );

    // A hand-registered account named like another agent's managed one.
    hand_registered(&t, "x", "svc-bar").await;
    let bar = agent(&t.store, "bar").await;
    let g = provisioning(&t.store, bar.id, &Authority::Homelab, "svc-gitea", 3600).await;
    assert_eq!(
        provision(&t.store, &t.p, &g).await.unwrap_err(),
        "LLDAP account 'svc-bar' belongs to another agent; refusing to adopt it"
    );

    // None of those set a password or touched a row (INV-L5).
    assert_eq!(t.ldap.passwords.lock().unwrap().len(), 1, "only Foo's");
    for id in [a.id, foo2.id, bar.id] {
        let row = reload(&t.store, id).await;
        assert!(row.lldap_username.is_none() && row.lldap_password_encrypted.is_none());
    }
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_failed_password_set_fails_closed(pool: PgPool) {
    let t = setup_with(pool, config(&[]), true).await;
    t.ldap.fail.store(true, Ordering::SeqCst);
    let a = agent(&t.store, "worker").await;
    let g = provisioning(&t.store, a.id, &Authority::Homelab, "svc-gitea", 3600).await;
    let err = provision(&t.store, &t.p, &g).await.unwrap_err();
    assert_eq!(err, "setting the LLDAP password failed (see broker logs)");
    let row = reload(&t.store, a.id).await;
    assert!(row.lldap_username.is_none() && row.lldap_password_encrypted.is_none());
    assert!(t.adds().is_empty());
    // A retry adopts the account made the first time.
    t.ldap.fail.store(false, Ordering::SeqCst);
    let g = provisioning(&t.store, a.id, &Authority::Homelab, "svc-gitea", 3600).await;
    provision(&t.store, &t.p, &g).await.unwrap();
    assert_eq!(t.creates().len(), 1);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn rotation_changes_the_password_of_managed_accounts_only(pool: PgPool) {
    let t = setup_with(pool, config(&[]), true).await;
    let a = agent(&t.store, "worker").await;
    let g = granted(&t.store, &t.p, a.id, &Authority::Homelab, "svc-gitea").await;
    let first = expose(&credential(&t.store, &t.p, &g).await.unwrap()).to_owned();
    let tx = t.store.begin().await.unwrap();
    t.p.rotate_password(&tx, a.id).await.unwrap();
    tx.commit().await.unwrap();
    let second = expose(&credential(&t.store, &t.p, &g).await.unwrap()).to_owned();
    assert_ne!(first, second);
    assert_eq!(t.ldap.last_password().unwrap().1, second);

    let h = hand_registered(&t, "hand", "svc-hand").await;
    let tx = t.store.begin().await.unwrap();
    let err =
        t.p.rotate_password(&tx, h.id)
            .await
            .unwrap_err()
            .to_string();
    assert_eq!(
        err,
        "agent 'hand' has no broker-managed LLDAP account to rotate"
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn the_reaper_removes_a_membership_with_no_recorded_state(pool: PgPool) {
    let t = setup_with(pool, config(&[]), false).await;
    let a = hand_registered(&t, "homelab-agent", "svc-homelab-agent").await;
    t.user("svc-homelab-agent", "hand made", &[4]);
    let g = provisioning(&t.store, a.id, &Authority::Homelab, "svc-gitea", 3600).await;
    reap(&t.store, &t.p, &g).await.unwrap();
    assert_eq!(t.removes(), [("svc-homelab-agent".to_owned(), 4)]);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_user_deleted_out_of_band_does_not_wedge_revocation(pool: PgPool) {
    let t = setup_with(pool, config(&[]), false).await;
    let a = hand_registered(&t, "homelab-agent", "svc-homelab-agent").await;
    let g = granted(&t.store, &t.p, a.id, &Authority::Homelab, "svc-gitea").await;
    t.state.lock().unwrap().users.clear();
    expire(&t.store, &t.p, g.id).await.unwrap();
}

#[sqlx::test(migrations = "../store/migrations")]
async fn an_lldap_outage_during_revoke_keeps_the_grant_for_a_retry(pool: PgPool) {
    let t = setup_with(pool, config(&[]), false).await;
    let a = hand_registered(&t, "homelab-agent", "svc-homelab-agent").await;
    let g = granted(&t.store, &t.p, a.id, &Authority::Homelab, "svc-gitea").await;
    // Unreachable-ish (503), then up but failing every query: neither is
    // "the user is gone", so the revoke fails and the grant stays ACTIVE
    // (expired now) for the expiry sweep to retry. The Python re-raised;
    // the port used to read both as "deleted" and end the grant with the
    // membership (and its Authelia access) still in place.
    for outage in [503, 200] {
        t.state.lock().unwrap().outage = Some(outage);
        let err = expire(&t.store, &t.p, g.id).await.unwrap_err();
        assert!(err.starts_with("LLDAP GraphQL error"), "{err}");
        assert_eq!(
            grant(&t.store, g.id).await.status,
            agent_auth_core::GrantStatus::Active
        );
        assert!(t.member("svc-homelab-agent", 4));
    }
    t.state.lock().unwrap().outage = None;
    revoke_due(&t.store, &t.p, g.id).await.unwrap();
    assert_eq!(t.removes(), [("svc-homelab-agent".to_owned(), 4)]);
    assert!(!t.member("svc-homelab-agent", 4));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_failed_lookup_of_a_listed_user_is_not_a_deletion(pool: PgPool) {
    let t = setup_with(pool, config(&[]), false).await;
    let a = hand_registered(&t, "homelab-agent", "svc-homelab-agent").await;
    let g = granted(&t.store, &t.p, a.id, &Authority::Homelab, "svc-gitea").await;
    // Removing and the user's lookups fail, but LLDAP still lists the
    // user: it exists, so the revoke must not count as done.
    let state = t.state.clone();
    t.fake.set(move |c| {
        let q = c.body["query"].as_str().unwrap_or("");
        if q.contains("RemoveUserFromGroup") || q.contains("UserGroups") || q.contains("UserExists")
        {
            gql_error()
        } else {
            lldap_handler(&state, c)
        }
    });
    let err = expire(&t.store, &t.p, g.id).await.unwrap_err();
    assert_eq!(err, "LLDAP GraphQL error (see broker logs)");
    assert_eq!(
        grant(&t.store, g.id).await.status,
        agent_auth_core::GrantStatus::Active
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_missing_group_fails_with_its_name(pool: PgPool) {
    let t = setup_with(pool, config(&[]), false).await;
    let a = hand_registered(&t, "homelab-agent", "svc-homelab-agent").await;
    let g = provisioning(&t.store, a.id, &Authority::Homelab, "nope", 3600).await;
    assert_eq!(
        provision(&t.store, &t.p, &g).await.unwrap_err(),
        "LLDAP group 'nope' does not exist"
    );
    // Logged in once; the JWT is reused.
    assert_eq!(t.state.lock().unwrap().logins, 1);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn concurrent_revokes_of_the_last_two_grants_remove_the_membership(pool: PgPool) {
    let t = setup_with(pool, config(&[]), false).await;
    let a = hand_registered(&t, "homelab-agent", "svc-homelab-agent").await;
    for _ in 0..5 {
        let g1 = granted(&t.store, &t.p, a.id, &Authority::Homelab, "svc-gitea").await;
        let g2 = granted(&t.store, &t.p, a.id, &Authority::Homelab, "svc-gitea").await;
        assert!(t.member("svc-homelab-agent", 4));
        // Both unexpired: each revoke alone would see the other as live.
        let (r1, r2) = tokio::join!(
            revoke_now(&t.store, &t.p, g1.id),
            revoke_now(&t.store, &t.p, g2.id)
        );
        r1.unwrap();
        r2.unwrap();
        assert!(
            !t.member("svc-homelab-agent", 4),
            "the membership outlived both grants"
        );
    }
}

/// Wait until some transaction waits on a lock (a condition, not a sleep).
async fn someone_waits(store: &Store) {
    for _ in 0..500 {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_locks WHERE NOT granted")
            .fetch_one(store.pool())
            .await
            .unwrap();
        if n > 0 {
            return;
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("nobody ever waited");
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_credential_fetch_during_a_first_provision_does_not_deadlock(pool: PgPool) {
    // Review: the finish held the grant and then locked the agent row for
    // the managed account, while `issuable` held the agent (share) and
    // waited for the grant: a deadlock. The account is now made before.
    let t = setup_with(pool, config(&[]), true).await;
    let a = agent(&t.store, "worker").await;
    let g = provisioning(&t.store, a.id, &Authority::Homelab, "svc-gitea", 3600).await;
    t.p.prepare(&t.store, &g, now()).await.unwrap();
    let tx = t.store.begin().await.unwrap();
    let nh = agent_auth_store::lockdown::check(&tx, a.id, now())
        .await
        .unwrap()
        .unwrap();
    let pg = agent_auth_store::grants::load_provisioning(&tx, g.id)
        .await
        .unwrap()
        .unwrap();
    let store = t.store.clone();
    let fetch = tokio::spawn(async move {
        let tx = store.begin().await.unwrap();
        let out = agent_auth_store::grants::issuable(&tx, a.id, g.id, now()).await;
        let ok = matches!(out, Ok(Ok(_)));
        drop(out);
        tx.rollback().await.unwrap();
        ok
    });
    someone_waits(&t.store).await;
    let state = t.p.provision(&tx, &pg, now()).await.unwrap();
    agent_auth_store::grants::activate(&tx, pg, &nh, &state)
        .await
        .unwrap()
        .unwrap();
    drop(nh);
    tx.commit().await.unwrap();
    assert!(fetch.await.unwrap(), "the fetch sees the active grant");
    assert_eq!(t.adds(), [("svc-worker".to_owned(), 4)]);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn concurrent_first_provisions_make_one_account(pool: PgPool) {
    let t = setup_with(pool, config(&[]), true).await;
    let a = agent(&t.store, "worker").await;
    let g1 = provisioning(&t.store, a.id, &Authority::Homelab, "svc-gitea", 3600).await;
    let g2 = provisioning(&t.store, a.id, &Authority::Homelab, "media", 3600).await;
    let (r1, r2) = tokio::join!(
        provision(&t.store, &t.p, &g1),
        provision(&t.store, &t.p, &g2)
    );
    r1.unwrap();
    r2.unwrap();
    assert_eq!(t.creates().len(), 1);
    assert_eq!(t.ldap.passwords.lock().unwrap().len(), 1);
    assert!(t.member("svc-worker", 4) && t.member("svc-worker", 5));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn the_credential_route_serves_accounts_and_groups(pool: PgPool) {
    let t = setup_with(pool, config(&[]), true).await;
    let hand = hand_registered(&t, "hand-agent", "svc-hand").await;
    let managed = agent(&t.store, "Worker").await;
    let group = granted(&t.store, &t.p, hand.id, &Authority::Homelab, "svc-gitea").await;
    let account = granted(&t.store, &t.p, managed.id, &Authority::Homelab, "svc-gitea").await;
    let (_, password) = t.ldap.last_password().unwrap();
    let out = credentials_over_http(
        &t.store,
        agent_auth_broker::provisioners::AnyProvisioner::Homelab(t.p),
        &[&group, &account],
    )
    .await;
    assert_eq!(out[0].0, axum::http::StatusCode::OK, "{}", out[0].1);
    assert_eq!(out[0].1["kind"], "lldap_group");
    assert_eq!(out[0].1["username"], "svc-hand");
    assert_eq!(out[1].0, axum::http::StatusCode::OK, "{}", out[1].1);
    assert_eq!(out[1].1["kind"], "lldap_account");
    assert_eq!(out[1].1["username"], "svc-worker");
    assert_eq!(out[1].1["value"], password.as_str());
}

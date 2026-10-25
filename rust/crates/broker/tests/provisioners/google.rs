//! The Google stub (provisioners spec §10).

use agent_auth_broker::provisioners::google::GoogleProvisioner;
use agent_auth_broker::provisioners::{ProvisionError, Provisioner};
use agent_auth_core::{Authority, Platform};
use agent_auth_store::Store;
use serde_json::json;
use sqlx::PgPool;

use crate::common::*;

#[sqlx::test(migrations = "../store/migrations")]
async fn decisions_are_recorded_and_nothing_is_issued(pool: PgPool) {
    let store = Store::from_pool(pool);
    let p = GoogleProvisioner;
    let a = agent(&store, "g-agent").await;
    assert_eq!(
        validate(
            &store,
            &p,
            &a,
            Platform::Google,
            "drive.write",
            json!({}),
            "*"
        )
        .await
        .unwrap_err(),
        "unknown google capability 'drive.write'; known: ['calendar.read', 'calendar.write', 'drive.read', 'gmail.read']"
    );
    let ok = validate(
        &store,
        &p,
        &a,
        Platform::Google,
        "calendar.read",
        json!({}),
        "primary",
    )
    .await
    .unwrap();
    assert_eq!(
        ok.notes,
        ["google provisioning is a stub: decision recorded, no credential minted"]
    );
    let g = granted(
        &store,
        &p,
        a.id,
        &Authority::Google {
            action: "calendar.read".into(),
        },
        "primary",
    )
    .await;
    assert_eq!(g.provisioner_state, json!({"stub": true}));
    match credential(&store, &p, &g).await {
        Err(CredErr::Provision(ProvisionError::NotImplemented)) => {}
        other => panic!("{other:?}"),
    }
    expire(&store, &p, g.id).await.unwrap();
    assert_eq!(
        p.catalog(&a).unwrap()["capabilities"],
        json!([
            "calendar.read",
            "calendar.write",
            "drive.read",
            "gmail.read"
        ])
    );
}

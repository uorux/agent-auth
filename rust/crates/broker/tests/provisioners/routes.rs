//! The credential route for the provisioners with no upstream to fake:
//! what an agent gets through `GET /v1/grants/{id}/credential` (the others
//! are checked in their own modules, `the_credential_route_serves_*`).

use agent_auth_broker::a2a::provisioner::A2aProvisioner;
use agent_auth_broker::provisioners::AnyProvisioner;
use agent_auth_broker::provisioners::google::GoogleStubProvisioner;
use agent_auth_core::Authority;
use agent_auth_store::Store;
use axum::http::StatusCode;
use sqlx::PgPool;

use crate::common::*;

#[sqlx::test(migrations = "../store/migrations")]
async fn an_a2a_grant_serves_its_note(pool: PgPool) {
    let store = Store::from_pool(pool);
    let a = agent(&store, "talker").await;
    let g = granted(
        &store,
        &A2aProvisioner,
        a.id,
        &Authority::A2a { topic: None },
        "peer",
    )
    .await;
    let out = credentials_over_http(&store, AnyProvisioner::A2a(A2aProvisioner), &[&g]).await;
    assert_eq!(out[0].0, StatusCode::OK, "{}", out[0].1);
    assert_eq!(out[0].1["kind"], "a2a_grant");
    assert_eq!(out[0].1["value"], serde_json::Value::Null);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_stub_google_grant_says_no_account_is_configured(pool: PgPool) {
    let store = Store::from_pool(pool);
    let a = agent(&store, "g-agent").await;
    let g = granted(
        &store,
        &GoogleStubProvisioner,
        a.id,
        &Authority::Google {
            action: "calendar.read".into(),
        },
        "main",
    )
    .await;
    let out = credentials_over_http(
        &store,
        AnyProvisioner::GoogleStub(GoogleStubProvisioner),
        &[&g],
    )
    .await;
    assert_eq!(out[0].0, StatusCode::NOT_IMPLEMENTED, "{}", out[0].1);
    assert_eq!(
        out[0].1["detail"],
        "no google account is configured on this broker"
    );
}

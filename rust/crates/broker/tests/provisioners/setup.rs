//! What `main` builds from the environment and the policy (spec §1.3).

use std::collections::BTreeMap;
use std::sync::Arc;

use agent_auth_broker::provisioners::setup::{Env, Keys, build, map_lookup};
use agent_auth_broker::provisioners::{AnyProvisioner, Provisioner};
use agent_auth_core::Platform;
use agent_auth_core::policy::Policy;
use agent_auth_crypto::daemon::SigningKey;
use serde_json::json;

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + Sync + use<> {
    map_lookup(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect::<BTreeMap<_, _>>(),
    )
}

fn platforms(b: &[AnyProvisioner]) -> Vec<Platform> {
    b.iter().map(Provisioner::platform).collect()
}

#[test]
fn only_configured_platforms_are_built() {
    let policy = Arc::new(Policy::default());
    let none = env(&[]);
    let b = build(
        &Env::new(&none),
        &policy,
        Keys {
            secret_box: None,
            signing_key: None,
        },
    )
    .unwrap();
    assert_eq!(platforms(&b.provisioners), [Platform::Google]);
    assert!(b.services.tokens.is_none() && b.services.wiki.is_none());

    let key = crate::github::key_file();
    let gh = env(&[
        ("GITHUB_APP_ID", "1"),
        ("GITHUB_APP_PRIVATE_KEY_FILE", key.to_str().unwrap()),
    ]);
    let err = build(
        &Env::new(&gh),
        &policy,
        Keys {
            secret_box: None,
            signing_key: None,
        },
    )
    .unwrap_err();
    assert_eq!(err.0, "ENCRYPTION_KEY is required when GitHub is enabled");

    let sb = crate::common::secret_box();
    let all = env(&[
        ("GITHUB_APP_ID", "1"),
        ("GITHUB_APP_PRIVATE_KEY_FILE", key.to_str().unwrap()),
        ("LLDAP_URL", "http://lldap"),
        ("KUBERNETES_API_URL", "https://a, https://b/"),
        ("KUBERNETES_TOKEN", "t"),
        ("LITELLM_MASTER_KEY", "sk"),
    ]);
    let policy = Arc::new(
        Policy::from_value(json!({
            "platforms": {
                "models": {"url": "https://llm"},
                "mcp": {"issuer": "https://broker", "servers": {"notes": {"url": "https://n"}}},
            },
            "wiki": {"repo": "jrt/wiki"},
        }))
        .unwrap(),
    );
    let signing = SigningKey::from_seed(&[1u8; 32]).unwrap();
    let b = build(
        &Env::new(&all),
        &policy,
        Keys {
            secret_box: Some(&sb),
            signing_key: Some(&signing),
        },
    )
    .unwrap();
    assert_eq!(
        platforms(&b.provisioners),
        [
            Platform::Google,
            Platform::Github,
            Platform::Homelab,
            Platform::Kubernetes,
            Platform::Models,
            Platform::Mcp
        ]
    );
    assert!(
        b.services.tokens.is_some() && b.services.wiki.is_some() && b.services.github.is_some()
    );

    let bad = env(&[("KUBERNETES_API_URL", " , ")]);
    assert_eq!(
        build(
            &Env::new(&bad),
            &policy,
            Keys {
                secret_box: None,
                signing_key: None
            }
        )
        .unwrap_err()
        .0,
        "kubernetes api_url is empty"
    );
}

//! Every manifest shipped under plugins/ parses and passes the permission
//! check against a registry policy that approves its network and secrets.

use ivar_contracts::{PluginManifest, PluginType};
use ivar_plugin_host::permissions::{check, RegistryPolicy};

fn plugins_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plugins")
}

#[test]
fn shipped_manifests_pass_permission_checks() {
    let mut seen = 0;
    for entry in std::fs::read_dir(plugins_dir()).unwrap() {
        let path = entry.unwrap().path().join("plugin.yaml");
        if !path.exists() {
            continue;
        }
        let m = PluginManifest::from_yaml(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(m.plugin_type, PluginType::Responder);
        let approved = RegistryPolicy { allowed_network: m.permissions.network.clone(), allowed_secrets: m.permissions.secrets.clone(), ..RegistryPolicy::default() };
        check(&m, &approved).unwrap_or_else(|v| panic!("{}: {v:?}", path.display()));
        assert!(check(&m, &RegistryPolicy::default()).is_err(), "{}: unapproved network and secrets must be refused", path.display());
        seen += 1;
    }
    assert_eq!(seen, 8);
}

#[test]
fn spec_manifest_is_unchanged() {
    let m = PluginManifest::from_yaml(&std::fs::read_to_string(plugins_dir().join("okta-responder/plugin.yaml")).unwrap()).unwrap();
    assert_eq!((m.name.as_str(), m.version.as_str(), m.api.as_str(), m.signature.as_str()), ("okta-responder", "1.4.0", "ivar.plugin/v1", "sigstore"));
    assert_eq!(m.permissions.actions, vec!["session.revoke", "user.suspend"]);
    assert_eq!(m.permissions.network, vec!["*.okta.com:443"]);
    assert_eq!(m.permissions.secrets, vec!["okta_api_token"]);
    assert_eq!((m.limits.memory_mb, m.limits.cpu_ms_per_call, m.limits.timeout_ms), (128, 50, 2000));
}

//! Network scoping for separate process plugins. A process cannot be
//! confined by the sandbox, so its manifest's network list is compiled into
//! a Kubernetes CiliumNetworkPolicy (FQDN egress) for the plugin's pod.

use ivar_contracts::PluginManifest;
use serde_json::{json, Value};

pub fn cilium_policy(m: &PluginManifest, namespace: &str) -> Value {
    let to_fqdns: Vec<Value> = m
        .permissions
        .network
        .iter()
        .map(|n| {
            let host = n.split(':').next().unwrap_or(n);
            if host.starts_with("*.") { json!({ "matchPattern": host }) } else { json!({ "matchName": host }) }
        })
        .collect();
    let ports: Vec<Value> = m
        .permissions
        .network
        .iter()
        .filter_map(|n| n.split(':').nth(1))
        .map(|p| json!({ "port": p, "protocol": "TCP" }))
        .collect();
    json!({
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": { "name": format!("ivar-plugin-{}", m.name), "namespace": namespace },
        "spec": {
            "endpointSelector": { "matchLabels": { "ivar.dev/plugin": m.name } },
            "egress": [
                { "toEndpoints": [{ "matchLabels": { "k8s:io.kubernetes.pod.namespace": "kube-system", "k8s-app": "kube-dns" } }],
                  "toPorts": [{ "ports": [{ "port": "53", "protocol": "ANY" }], "rules": { "dns": [{ "matchPattern": "*" }] } }] },
                { "toFQDNs": to_fqdns, "toPorts": [{ "ports": ports }] }
            ]
        }
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn okta_egress_only() {
        let m = ivar_contracts::PluginManifest::from_yaml("name: okta-responder\nversion: 1.4.0\ntype: responder\napi: ivar.plugin/v1\npermissions:\n  network: [\"*.okta.com:443\"]\nlimits: { memory_mb: 128, cpu_ms_per_call: 50, timeout_ms: 2000 }\nsignature: sigstore\n").unwrap();
        let p = super::cilium_policy(&m, "ivar");
        assert_eq!(p["spec"]["egress"][1]["toFQDNs"][0]["matchPattern"], "*.okta.com");
        assert_eq!(p["spec"]["egress"][1]["toPorts"][0]["ports"][0]["port"], "443");
    }
}

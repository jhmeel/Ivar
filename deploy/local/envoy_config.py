"""Writes the Envoy config for the local stack from the generated state.

The IVAR edge filter sits behind Coraza with the OWASP Core Rule Set when
CORAZA_WASM names a coraza-proxy-wasm build, as in deploy/envoy/envoy.yaml.
"""
import json
import os
import sys

state = sys.argv[1]
policy_ring = json.load(open(os.path.join(state, "policy-keyring.json")))
bundle = open(os.path.join(state, "policy.bundle")).read().strip()
redaction = open(os.path.join(state, "keys", "redaction.hex")).read().strip()

edge = {
    "sensor_id": "edge-local",
    "mode": os.environ.get("IVAR_MODE", "enforce"),
    "redaction_key_hex": redaction,
    "fail_open_budget_pct": 0.1,
    "admin_prefixes": ["/admin"],
    "max_body_bytes": 65536,
    "core_cluster": "ivar_core",
    "core_authority": "ivar-core",
    "control_cluster": "ivar_control",
    "control_authority": "ivar-control",
    "keyring": policy_ring,
    "policy_bundle_base64": bundle,
    "tick_ms": 500,
    "max_outbox": 10000,
}


def wasm_filter(name, path, config):
    return {
        "name": name,
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm",
            "config": {
                "name": name,
                "root_id": name,
                # Section 11.2: the edge fails open on a crash and alerts; admin
                # routes still fail closed inside the IVAR filter.
                "fail_open": True,
                "configuration": {"@type": "type.googleapis.com/google.protobuf.StringValue", "value": config},
                "vm_config": {"runtime": "envoy.wasm.runtime.v8", "code": {"local": {"filename": path}}},
            },
        },
    }


filters = []
if os.environ.get("CORAZA_WASM"):
    # The API declares PATCH, PUT and DELETE routes, so the Core Rule Set's
    # method allowlist (rule 911100) is widened to match; everything the
    # OpenAPI file does not declare is still refused by the IVAR filter.
    allowed = 'SecAction "id:900200,phase:1,nolog,pass,t:none,setvar:\'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE\'"'
    coraza = {"directives_map": {"default": ["Include @demo-conf", "Include @crs-setup-conf", allowed, "SecRuleEngine On", "Include @owasp_crs/*.conf"]}, "default_directives": "default"}
    filters.append(wasm_filter("coraza", "/etc/ivar/coraza.wasm", json.dumps(coraza)))
filters.append(wasm_filter("ivar", "/etc/ivar/ivar_edge_filter.wasm", json.dumps(edge)))
filters.append({"name": "envoy.filters.http.router", "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}})


def cluster(name, port):
    return {
        "name": name,
        "type": "STATIC",
        "connect_timeout": "1s",
        "load_assignment": {"cluster_name": name, "endpoints": [{"lb_endpoints": [{"endpoint": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": port}}}}]}]},
    }


config = {
    "admin": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": 9901}}},
    "static_resources": {
        "listeners": [{
            "name": "gateway",
            "address": {"socket_address": {"address": "127.0.0.1", "port_value": 10000}},
            "filter_chains": [{"filters": [{
                "name": "envoy.filters.network.http_connection_manager",
                "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                    "stat_prefix": "gateway",
                    "use_remote_address": True,
                    "xff_num_trusted_hops": 1,
                    "route_config": {"virtual_hosts": [{"name": "app", "domains": ["*"], "routes": [{"match": {"prefix": "/"}, "route": {"cluster": "app"}}]}]},
                    "http_filters": filters,
                },
            }]}],
        }],
        "clusters": [cluster("app", int(os.environ.get("APP_PORT", "9000"))), cluster("ivar_core", 8080), cluster("ivar_control", 8090)],
    },
}
print(json.dumps(config, indent=2))

"""Envoy for the enterprise test: one gateway listener per application, each
with Coraza and the OWASP Core Rule Set ahead of the IVAR edge filter, and a
round robin load balancer in front of the core shards, as a Kubernetes
Service would be.

    python3 envoy.py <state dir> > envoy.yaml
"""
import json
import os
import sys

state = sys.argv[1]
apps = json.load(open(os.path.join(state, "apps.json")))  # [{"name", "port", "gateway"}]
shards = json.load(open(os.path.join(state, "shards.json")))  # [port, ...]
policy_ring = json.load(open(os.path.join(state, "policy-keyring.json")))
redaction = open(os.path.join(state, "keys", "redaction.hex")).read().strip()
edge_token = open(os.path.join(state, "tokens", "edge.token")).read().strip()


def wasm(name, path, config):
    return {
        "name": name,
        "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm",
            "config": {
                "name": name,
                "root_id": name,
                "fail_open": True,
                "configuration": {"@type": "type.googleapis.com/google.protobuf.StringValue", "value": json.dumps(config)},
                "vm_config": {"runtime": "envoy.wasm.runtime.v8", "code": {"local": {"filename": path}}},
            },
        },
    }


allowed = "SecAction \"id:900200,phase:1,nolog,pass,t:none,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'\""
coraza = {"directives_map": {"default": ["Include @demo-conf", "Include @crs-setup-conf", allowed, "SecRuleEngine On", "Include @owasp_crs/*.conf"]}, "default_directives": "default"}


def edge(app):
    return {
        "sensor_id": f"edge-{app['name']}",
        "mode": "enforce",
        "redaction_key_hex": redaction,
        "fail_open_budget_pct": 0.1,
        "admin_prefixes": ["/admin"],
        "max_body_bytes": 65536,
        "core_cluster": "ivar_core",
        "core_authority": "ivar-core",
        "core_token": edge_token,
        "control_cluster": "ivar_control",
        "control_authority": "ivar-control",
        "keyring": policy_ring,
        "policy_bundle_base64": "",
        "tick_ms": 500,
        "max_outbox": 10000,
    }


def cluster(name, ports, lb="ROUND_ROBIN"):
    return {
        "name": name,
        "type": "STATIC",
        "connect_timeout": "1s",
        "lb_policy": lb,
        "load_assignment": {"cluster_name": name, "endpoints": [{"lb_endpoints": [
            {"endpoint": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": p}}}} for p in ports]}]},
    }


def hcm(prefix, cluster_name, filters, trust_client_xff):
    cfg = {
        "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
        "stat_prefix": prefix,
        "route_config": {"virtual_hosts": [{"name": prefix, "domains": ["*"], "routes": [{"match": {"prefix": "/"}, "route": {"cluster": cluster_name, "timeout": "10s"}}]}]},
        "http_filters": filters + [{"name": "envoy.filters.http.router", "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}}],
    }
    if trust_client_xff:
        # A CDN in front would set X-Forwarded-For; the campaign plays it, so
        # one hop the client sends is trusted and Envoy appends its own view.
        cfg.update({"use_remote_address": True, "xff_num_trusted_hops": 1})
    return {"name": "envoy.filters.network.http_connection_manager", "typed_config": cfg}


listeners = []
clusters = [cluster("ivar_core", [8080]), cluster("ivar_control", [8090]), cluster("core_shards", shards)]
for app in apps:
    filters = [wasm("coraza", os.path.join(state, "coraza.wasm"), coraza), wasm("ivar", os.path.join(state, "ivar_edge_filter.wasm"), edge(app))]
    listeners.append({"name": f"gw_{app['name']}", "address": {"socket_address": {"address": "127.0.0.1", "port_value": app["gateway"]}},
                      "filter_chains": [{"filters": [hcm(f"gw_{app['name']}", f"app_{app['name']}", filters, True)]}]})
    clusters.append(cluster(f"app_{app['name']}", [app["port"]]))
# The core's Service: every SDK and the edge send to 8080, spread over the shards.
listeners.append({"name": "core_lb", "address": {"socket_address": {"address": "127.0.0.1", "port_value": 8080}},
                  "filter_chains": [{"filters": [hcm("core_lb", "core_shards", [], False)]}]})

print(json.dumps({"admin": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": 9901}}},
                  "static_resources": {"listeners": listeners, "clusters": clusters}}, indent=1))

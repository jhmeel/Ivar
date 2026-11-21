package chartcheck

import (
	"encoding/json"
	"strings"
	"testing"
)

const chart = "../ivar"

var gateway = map[string]any{
	"keyringJson":     `{"keys":{"policy-a":[{"key_id":"policy-a","alg":"ed25519","bytes":"00"},["policy"]]}}`,
	"policyBundle":    "cG9saWN5\n",
	"redactionKeyHex": "abcd",
}

func render(t *testing.T, overrides map[string]any) []Manifest {
	t.Helper()
	ms, err := Render(chart, overrides)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.Object["apiVersion"] == nil || m.Kind() == "" || m.Name() == "" {
			t.Fatalf("%s: object without apiVersion, kind or name: %v", m.Source, m.Object)
		}
	}
	return ms
}

func find(ms []Manifest, kind, name string) map[string]any {
	for _, m := range ms {
		if m.Kind() == kind && m.Name() == name {
			return m.Object
		}
	}
	return nil
}

func TestGatewayNeedsSignedPolicy(t *testing.T) {
	if _, err := Render(chart, nil); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("the gateway must refuse to render without a keyring and bundle, got %v", err)
	}
}

func TestFullInstall(t *testing.T) {
	ms := render(t, map[string]any{
		"gateway":    gateway,
		"agent":      map[string]any{"mode": "tetragon"},
		"core":       map[string]any{"replicas": 3},
		"connectors": map[string]any{"okta": map[string]any{"enabled": true}, "cloud": map[string]any{"enabled": true}},
	})
	for _, want := range [][2]string{
		{"StatefulSet", "ivar-core"}, {"Service", "ivar-core"}, {"Deployment", "ivar-control"},
		{"DaemonSet", "ivar-agent"}, {"ClusterRole", "ivar-agent"}, {"WasmPlugin", "coraza"}, {"WasmPlugin", "ivar-edge"},
		{"Deployment", "ivar-connector-okta"}, {"Deployment", "ivar-connector-cloud"}, {"Deployment", "ivar-connector-k8s"},
		{"ValidatingWebhookConfiguration", "ivar-deploy-intent"}, {"NetworkPolicy", "ivar-core"}, {"PodDisruptionBudget", "ivar-core"},
	} {
		if find(ms, want[0], want[1]) == nil {
			t.Errorf("missing %s %s", want[0], want[1])
		}
	}
	if find(ms, "Deployment", "ivar-connector-entra") != nil {
		t.Error("disabled connectors must not render")
	}

	// Coraza runs ahead of the IVAR filter.
	coraza, edge := find(ms, "WasmPlugin", "coraza")["spec"].(map[string]any), find(ms, "WasmPlugin", "ivar-edge")["spec"].(map[string]any)
	if coraza["phase"] != "AUTHN" || edge["phase"] != "AUTHZ" {
		t.Errorf("coraza must run before ivar: %v %v", coraza["phase"], edge["phase"])
	}
	// The plugin config carries exactly the fields the Rust EdgeConfig reads.
	cfg := edge["pluginConfig"].(map[string]any)
	for _, k := range []string{"sensor_id", "mode", "redaction_key_hex", "fail_open_budget_pct", "admin_prefixes", "max_body_bytes", "core_cluster", "core_authority", "control_cluster", "control_authority", "keyring", "policy_bundle_base64", "tick_ms", "max_outbox"} {
		if _, ok := cfg[k]; !ok {
			t.Errorf("edge plugin config lacks %s", k)
		}
	}
	if cfg["mode"] != "observe" || cfg["policy_bundle_base64"] != "cG9saWN5" {
		t.Errorf("edge config: mode %v, bundle %q", cfg["mode"], cfg["policy_bundle_base64"])
	}
	if !strings.HasPrefix(cfg["core_cluster"].(string), "outbound|8080||ivar-core.ivar.svc") {
		t.Errorf("core cluster %v", cfg["core_cluster"])
	}

	// Each core replica derives its shard from its ordinal.
	sts := find(ms, "StatefulSet", "ivar-core")
	c := sts["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
	env, _ := json.Marshal(c["env"])
	if !strings.Contains(string(env), `"IVAR_SHARD","value":"ordinal"`) || !strings.Contains(string(env), `"IVAR_SHARDS","value":"3"`) {
		t.Errorf("core shard env: %s", env)
	}

	// The agent is not privileged and holds only the capabilities it uses.
	ds := find(ms, "DaemonSet", "ivar-agent")
	a := ds["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
	sc := a["securityContext"].(map[string]any)
	if sc["privileged"] != false {
		t.Error("agent must not be privileged")
	}
	args, _ := json.Marshal(a["args"])
	if !strings.Contains(string(args), "tetragon") {
		t.Errorf("tetragon mode args: %s", args)
	}
}

func TestEnvoyFilterVariant(t *testing.T) {
	g := map[string]any{"mode": "envoyfilter"}
	for k, v := range gateway {
		g[k] = v
	}
	ms := render(t, map[string]any{"gateway": g, "agent": map[string]any{"enabled": false}, "admission": map[string]any{"enabled": false}})
	ef := find(ms, "EnvoyFilter", "ivar-edge")
	if ef == nil {
		t.Fatal("missing EnvoyFilter")
	}
	patches := ef["spec"].(map[string]any)["configPatches"].([]any)
	if len(patches) != 2 {
		t.Fatalf("want coraza then ivar, got %d patches", len(patches))
	}
	first := patches[0].(map[string]any)["patch"].(map[string]any)["value"].(map[string]any)["name"]
	if first != "coraza" {
		t.Errorf("coraza must be inserted first, got %v", first)
	}
	value := patches[1].(map[string]any)["patch"].(map[string]any)["value"].(map[string]any)["typed_config"].(map[string]any)["config"].(map[string]any)["configuration"].(map[string]any)["value"].(string)
	var edge map[string]any
	if err := json.Unmarshal([]byte(value), &edge); err != nil || edge["control_cluster"] == nil {
		t.Errorf("edge configuration is not the EdgeConfig JSON: %v %s", err, value)
	}
	if find(ms, "DaemonSet", "ivar-agent") != nil || find(ms, "ValidatingWebhookConfiguration", "ivar-deploy-intent") != nil {
		t.Error("disabled components must not render")
	}
}

func TestNoGateway(t *testing.T) {
	ms := render(t, map[string]any{"gateway": map[string]any{"mode": "none"}})
	for _, m := range ms {
		if m.Kind() == "WasmPlugin" || m.Kind() == "EnvoyFilter" {
			t.Errorf("gateway mode none rendered %s", m.Kind())
		}
	}
}

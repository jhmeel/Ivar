package controlplane

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ivar "github.com/jhmeel/ivar/sdk/go"
)

func shippedDecisions(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../deploy/policy/operator-decisions.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func confirm(text string) string {
	return strings.ReplaceAll(text, `confirmed_by: ""`, `confirmed_by: "cto@example"`)
}

func TestShippedDecisionsAreUnconfirmed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "d.yaml")
	_ = os.WriteFile(p, []byte(shippedDecisions(t)), 0o644)
	_, err := LoadDecisions(p)
	if err == nil || !strings.Contains(err.Error(), "ai_autonomy is not confirmed") || !strings.Contains(err.Error(), "shared_indicator_network is not confirmed") {
		t.Fatalf("unconfirmed decisions must refuse the build, got %v", err)
	}
}

func TestJoiningTheIndicatorNetworkNeedsTheLegalWork(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "d.yaml")
	_ = os.WriteFile(p, []byte(strings.Replace(confirm(shippedDecisions(t)), "join: false", "join: true", 1)), 0o644)
	_, err := LoadDecisions(p)
	if err == nil || !strings.Contains(err.Error(), "legitimate_interest_assessment") || !strings.Contains(err.Error(), "counsel_review") {
		t.Fatalf("joining without the legal basis must be refused, got %v", err)
	}
}

func TestConfirmedDecisionsShapeThePolicy(t *testing.T) {
	rt, err := ivar.Shared()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "d.yaml"), []byte(confirm(shippedDecisions(t))), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "time-locks.yaml"), []byte("- action: payout\n  threshold: 25000\n  delay_secs: 1800\n  cancelling_owners: [user:cfo]\n"), 0o644)
	src := &Source{Version: 1, PolicyVersion: "d-1", OperatorDecisions: "d.yaml", IntentBinding: map[string]string{"payout": "enforce"}}
	content, err := Build(rt, src, dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Settings          map[string]any    `json:"settings"`
		IntentBinding     map[string]string `json:"intent_binding"`
		ProtectedEntities []map[string]any  `json:"protected_entities"`
		Invariants        []map[string]any  `json:"invariants"`
	}
	_ = json.Unmarshal(content, &p)
	if p.Settings["ai_autonomy"] != "advise" || p.Settings["auto_contain_max_users_pct"] != 0.5 || p.Settings["evidence_retention_days"] != 400.0 || p.Settings["shared_indicator_network"] != false {
		t.Fatalf("settings: %v", p.Settings)
	}
	if p.IntentBinding["payout"] != "enforce" || p.IntentBinding["role.grant"] != "observe" {
		t.Fatalf("intent binding: source wins where it is stricter for its own actions, decision covers the rest: %v", p.IntentBinding)
	}
	if len(p.ProtectedEntities) != 4 {
		t.Fatalf("protected entities: %v", p.ProtectedEntities)
	}
	locked := false
	for _, inv := range p.Invariants {
		if inv["action"] == "payout" && inv["time_lock"] != nil {
			locked = true
		}
	}
	if !locked {
		t.Fatal("the decided time locks file was applied")
	}
	// The core accepts the result.
	var out json.RawMessage
	if err := rt.Call("core.new", map[string]any{"policy": json.RawMessage(content), "redaction_key_hex": "00"}, 0, &out); err != nil {
		t.Fatalf("core refuses the policy: %v", err)
	}

	// A source that contradicts a decision is refused.
	bad := &Source{Version: 1, PolicyVersion: "d-1", OperatorDecisions: "d.yaml", Settings: map[string]any{"ai_autonomy": "bounded"}}
	if _, err := Build(rt, bad, dir, time.Now()); err == nil || !strings.Contains(err.Error(), "operator decided") {
		t.Fatalf("a source overriding a decision must fail, got %v", err)
	}
}

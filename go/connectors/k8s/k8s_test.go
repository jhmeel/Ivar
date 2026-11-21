package k8s

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	ivar "github.com/jhmeel/ivar/sdk/go"
)

func TestAuditMapping(t *testing.T) {
	var e AuditEvent
	_ = json.Unmarshal([]byte(`{"verb":"delete","stageTimestamp":"2026-11-01T02:00:00Z","user":{"username":"ops"},"objectRef":{"resource":"volumesnapshots","namespace":"prod","name":"db-snap-1"},"responseStatus":{"code":200}}`), &e)
	ev := FromAudit("k8s-1", e)
	if ev["activity_name"] != "snapshot.delete" || ev["ivar"].(map[string]any)["destructive"] != true {
		t.Fatal(ev)
	}
	v := FromVault("vault-1", map[string]any{"request": map[string]any{"path": "secret/data/payments", "operation": "read"}, "auth": map[string]any{"display_name": "ci"}})
	if v["activity_name"] != "secret.read" {
		t.Fatal(v["activity_name"])
	}
}

func TestDestructiveDeleteNeedsTwoApprovals(t *testing.T) {
	pub1, priv1, _ := ed25519.GenerateKey(nil)
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	w := &Webhook{Operators: map[string]string{"alice": hex.EncodeToString(pub1), "bob": hex.EncodeToString(pub2)}, Mode: "enforce"}
	sign := func(k ed25519.PrivateKey, op string) Approval {
		return Approval{Operator: op, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(k, []byte("namespaces//prod")))}
	}
	req := func(approvals []Approval) *AdmissionRequest {
		a, _ := json.Marshal(approvals)
		old, _ := json.Marshal(map[string]any{"metadata": map[string]any{"name": "prod", "annotations": map[string]string{"ivar.dev/approvals": string(a)}}})
		r := &AdmissionRequest{UID: "u", Operation: "DELETE", Name: "prod", OldObject: old}
		r.Resource.Resource = "namespaces"
		return r
	}
	if w.Review(req(nil)).Allowed {
		t.Fatal("delete without approvals allowed")
	}
	if w.Review(req([]Approval{sign(priv1, "alice"), sign(priv1, "alice")})).Allowed {
		t.Fatal("one operator twice counts once")
	}
	if !w.Review(req([]Approval{sign(priv1, "alice"), sign(priv2, "bob")})).Allowed {
		t.Fatal("two approvals refused")
	}
	w.Mode = "observe"
	if r := w.Review(req(nil)); !r.Allowed || len(r.Warnings) == 0 {
		t.Fatal("observe mode should warn, not deny")
	}
}

func TestDeployNeedsIntentChain(t *testing.T) {
	rt, err := ivar.Shared()
	if err != nil {
		t.Fatal(err)
	}
	steps := []string{"approved_change", "build_provenance", "deploy"}
	seeds := map[string]string{"approved_change": "22", "build_provenance": "33", "deploy": "44"}
	keys := map[string]string{}
	for s, b := range seeds {
		keys[s], _ = ivar.StepPublicKey(rt, repeat(b))
	}
	root := repeat("11")
	tok, rootPub, err := ivar.MintIntent(rt, root, "int_d1", "deploy", "payments/api", map[string]int64{}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		tok, _ = ivar.AttestStep(rt, repeat(seeds[s]), s, tok, rootPub)
	}
	sink, err := ivar.NewSink(rt, rootPub, keys, json.RawMessage("[]"), "enforce", nil)
	if err != nil {
		t.Fatal(err)
	}
	w := &Webhook{Protected: map[string]bool{"payments": true}, Mode: "enforce", Sink: sink}
	mk := func(image, token string) *AdmissionRequest {
		ann := map[string]string{}
		if token != "" {
			ann["ivar.dev/deploy-intent"] = token
		}
		obj, _ := json.Marshal(map[string]any{"metadata": map[string]any{"name": "api", "annotations": ann}, "spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"image": image}}}}}})
		r := &AdmissionRequest{UID: "d", Operation: "CREATE", Namespace: "payments", Object: obj}
		r.Resource.Resource = "deployments"
		return r
	}
	if w.Review(mk("ghcr.io/acme/api:latest", tok)).Allowed {
		t.Fatal("unpinned image allowed")
	}
	pinned := "ghcr.io/acme/api@sha256:" + repeat("ab")
	if w.Review(mk(pinned, "")).Allowed {
		t.Fatal("deploy without intent allowed")
	}
	if r := w.Review(mk(pinned, tok)); !r.Allowed {
		t.Fatalf("valid chain refused: %+v", r.Status)
	}
}

func repeat(b string) string {
	out := ""
	for i := 0; i < 32; i++ {
		out += b
	}
	return out
}

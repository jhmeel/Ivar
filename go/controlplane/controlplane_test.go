package controlplane

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ivar "github.com/ivar/ivar/sdk/go"
)

func key(id string, seed byte) PolicyKey {
	s := make([]byte, 32)
	for i := range s {
		s[i] = seed
	}
	return PolicyKey{ID: id, Priv: ed25519.NewKeyFromSeed(s)}
}

// Keyring in the Rust ivar_contracts::sign::Keyring JSON shape.
func keyring(keys ...PolicyKey) json.RawMessage {
	m := map[string]any{}
	for _, k := range keys {
		m[k.ID] = []any{map[string]any{"key_id": k.ID, "alg": "ed25519", "bytes": k.PublicHex()}, []string{"policy"}}
	}
	b, _ := json.Marshal(map[string]any{"keys": m})
	return b
}

func TestBuildSignAndVerifyInTheCore(t *testing.T) {
	rt, err := ivar.Shared()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "api.yaml"), []byte("openapi: 3.0.3\npaths:\n  /payouts:\n    post:\n      x-ivar-action: payout\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "time-locks.yaml"), []byte("- action: payout\n  threshold: 25000\n  delay_secs: 1800\n  cancelling_owners: [user:cfo]\n"), 0o644)
	src := &Source{Version: 7, PolicyVersion: "payments-2026.11.3", Profile: "payments", TimeLocksFile: "time-locks.yaml",
		Settings: map[string]any{"detection_mode": "enforce"}, IntentBinding: map[string]string{"payout": "enforce"},
		Declarations: []Declaration{{Kind: "openapi", File: "api.yaml"}}}
	content, err := Build(rt, src, dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var built struct {
		Declared map[string]json.RawMessage `json:"declared"`
	}
	_ = json.Unmarshal(content, &built)
	for k, v := range built.Declared {
		if string(v) == "null" {
			t.Fatalf("declared.%s written as null", k)
		}
	}
	a, b := key("policy-a", 1), key("policy-b", 2)
	bundle, err := Sign(content, []PolicyKey{a})
	if err != nil {
		t.Fatal(err)
	}
	arch, _ := bundle.ArchiveBase64()
	verified, err := ivar.VerifyPolicyBundle(rt, arch, keyring(a, b), 0)
	if err != nil {
		t.Fatalf("the core rejected a control plane bundle: %v", err)
	}
	var p map[string]any
	_ = json.Unmarshal(verified, &p)
	if p["policy_version"] != "payments-2026.11.3" || p["settings"].(map[string]any)["runtime_posture"] != "payments" {
		t.Fatal(p["settings"])
	}
	if !strings.Contains(string(verified), `"threshold":25000`) || !strings.Contains(string(verified), "/payouts") {
		t.Fatal("time lock or declarations missing")
	}
	if _, err := ivar.VerifyPolicyBundle(rt, arch, keyring(b), 0); err == nil {
		t.Fatal("a bundle signed by an untrusted key was accepted")
	}

	// Lowering intent binding weakens protection: two keys needed.
	src.IntentBinding["payout"] = "observe"
	src.Version = 8
	next, _ := Build(rt, src, dir, time.Now())
	marked, reasons, _ := MarkWeakening(content, next)
	if len(reasons) == 0 {
		t.Fatal("weakening not detected")
	}
	if _, err := Sign(marked, []PolicyKey{a}); err == nil {
		t.Fatal("weakening change signed with one key")
	}
	two, err := Sign(marked, []PolicyKey{a, b})
	if err != nil {
		t.Fatal(err)
	}
	arch2, _ := two.ArchiveBase64()
	if _, err := ivar.VerifyPolicyBundle(rt, arch2, keyring(a, b), 7); err != nil {
		t.Fatalf("two key weakening bundle rejected: %v", err)
	}
	if _, err := ivar.VerifyPolicyBundle(rt, arch, keyring(a, b), 8); err == nil {
		t.Fatal("rollback to version 7 accepted")
	}
}

func tufKeys(n int, seed byte) []ed25519.PrivateKey {
	var out []ed25519.PrivateKey
	for i := 0; i < n; i++ {
		s := make([]byte, 32)
		for j := range s {
			s[j] = seed + byte(i)
		}
		out = append(out, ed25519.NewKeyFromSeed(s))
	}
	return out
}

func TestTUFBlocksRollbackFreezeAndSingleKey(t *testing.T) {
	now := time.Now()
	keys := map[string][]ed25519.PrivateKey{"root": tufKeys(2, 10), "targets": tufKeys(2, 20), "snapshot": tufKeys(1, 30), "timestamp": tufKeys(1, 40)}
	repo, err := NewTUFRepo(keys, now)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := repo.Metadata("root")
	_ = repo.Publish("policy/payments.bundle", []byte("v1"), now)
	ts1, _ := repo.Metadata("timestamp")
	sn1, _ := repo.Metadata("snapshot")
	tg1, _ := repo.Metadata("targets")
	if err := VerifyTarget(root, ts1, sn1, tg1, "policy/payments.bundle", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if VerifyTarget(root, ts1, sn1, tg1, "policy/payments.bundle", []byte("tampered")) == nil {
		t.Fatal("tampered target accepted")
	}
	state := &ClientState{Root: root}
	if err := state.Update(ts1, sn1, tg1); err != nil {
		t.Fatal(err)
	}
	_ = repo.Publish("policy/payments.bundle", []byte("v2"), now)
	ts2, _ := repo.Metadata("timestamp")
	sn2, _ := repo.Metadata("snapshot")
	tg2, _ := repo.Metadata("targets")
	if err := state.Update(ts2, sn2, tg2); err != nil {
		t.Fatal(err)
	}
	if state.Update(ts1, sn1, tg1) == nil {
		t.Fatal("rollback to older metadata accepted")
	}
	// Freeze: metadata whose timestamp has expired is refused.
	frozen, _ := NewTUFRepo(keys, now.Add(-48*time.Hour))
	fr, _ := frozen.Metadata("root")
	fts, _ := frozen.Metadata("timestamp")
	fsn, _ := frozen.Metadata("snapshot")
	ftg, _ := frozen.Metadata("targets")
	if (&ClientState{Root: fr}).Update(fts, fsn, ftg) == nil {
		t.Fatal("expired timestamp (freeze) accepted")
	}
	// One compromised targets key cannot publish.
	one, _ := NewTUFRepo(keys, now)
	r1, _ := one.Metadata("root")
	one.keys["targets"] = keys["targets"][:1]
	_ = one.Publish("policy/evil.bundle", []byte("evil"), now)
	ots, _ := one.Metadata("timestamp")
	osn, _ := one.Metadata("snapshot")
	otg, _ := one.Metadata("targets")
	if VerifyTarget(r1, ots, osn, otg, "policy/evil.bundle", []byte("evil")) == nil {
		t.Fatal("targets signed by a single key accepted")
	}
}

func TestFlagsNeedTwoOperatorsForFleetWide(t *testing.T) {
	op1, op2 := key("alice", 5), key("bob", 6)
	ops := map[string]ed25519.PublicKey{"alice": op1.Priv.Public().(ed25519.PublicKey), "bob": op2.Priv.Public().(ed25519.PublicKey)}
	fs := NewFlagStore(key("flags-1", 9), ops)
	approve := func(k PolicyKey, op, msg string) OperatorApproval {
		return OperatorApproval{Operator: op, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(k.Priv, []byte(msg)))}
	}
	msg := "flag:RUNTIME_POSTURE=lockdown@1"
	if _, err := fs.Set("RUNTIME_POSTURE", "lockdown", []OperatorApproval{approve(op1, "alice", msg)}, time.Now()); err == nil {
		t.Fatal("fleet wide posture change with one approval")
	}
	f, err := fs.Set("RUNTIME_POSTURE", "lockdown", []OperatorApproval{approve(op1, "alice", msg), approve(op2, "bob", msg)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if VerifyFlag(f, key("flags-1", 9).Priv.Public().(ed25519.PublicKey)) != nil {
		t.Fatal("flag signature")
	}
	if want := fmt.Sprintf("ivar.flag.v1\nRUNTIME_POSTURE\nlockdown\n1\n%d", f.IssuedAt); string(flagBytes(f)) != want {
		t.Fatal("flag bytes differ from the Rust format")
	}
}

func TestRolloutAndRegistry(t *testing.T) {
	var r Rollout
	r.Propose(Release{Version: 1, Archive64: "v1"})
	r.Propose(Release{Version: 2, Archive64: "v2"})
	if r.For("s1").Version != 1 {
		t.Fatal("shadow must not reach sensors")
	}
	if _, err := r.Promote(false, false, 10); err == nil {
		t.Fatal("canary without the replay library")
	}
	_, _ = r.Promote(true, false, 10)
	canary := 0
	for i := 0; i < 1000; i++ {
		if r.For(fmt.Sprintf("sensor-%d", i)).Version == 2 {
			canary++
		}
	}
	if canary < 50 || canary > 150 {
		t.Fatalf("canary share %d of 1000", canary)
	}
	_, _ = r.Promote(true, true, 10)
	if r.For("s1").Version != 2 {
		t.Fatal("not active")
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	reg, err := NewRegistry([]string{string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))})
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte("name: okta-responder\nversion: 1.4.0\ntype: responder\napi: ivar.plugin/v1\nlimits: { memory_mb: 128, cpu_ms_per_call: 50, timeout_ms: 2000 }\nsignature: sigstore\n")
	art := []byte("binary")
	d := sha256.Sum256(SigningPayload(manifest, art))
	sig, _ := ecdsa.SignASN1(rand.Reader, priv, d[:])
	if _, err := reg.Submit(manifest, art, base64.StdEncoding.EncodeToString(sig)); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Submit(manifest, []byte("other"), base64.StdEncoding.EncodeToString(sig)); err == nil {
		t.Fatal("tampered artifact accepted")
	}
	_ = hex.EncodeToString
}

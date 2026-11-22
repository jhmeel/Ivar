package ivar

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", "policy", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func decoyAction(t *testing.T, m *Middleware) int {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })).ServeHTTP(rec, httptest.NewRequest("GET", "/v2-decoy", nil))
	return rec.Code
}

// A newer signed policy from the control plane applies while the app runs; a
// forged one changes nothing; a restart resumes at the saved policy.
func TestPolicyRefreshFromTheControlPlane(t *testing.T) {
	rt, err := Shared()
	if err != nil {
		t.Fatal(err)
	}
	keyring := []byte(fixture(t, "keyring.json"))
	v1, err := VerifyPolicyBundle(rt, fixture(t, "v1.bundle"), keyring, 0)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	serve := "v2.bundle"
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = w.Write([]byte(fixture(t, serve)))
	}))
	defer cp.Close()
	var alerts []string
	state := filepath.Join(t.TempDir(), "policy.state")

	plain, err := New(Options{Mode: "enforce", Policy: v1})
	if err != nil {
		t.Fatal(err)
	}
	if decoyAction(t, plain) == http.StatusForbidden {
		t.Fatal("v1 has no such decoy")
	}

	m, err := New(Options{Mode: "enforce", Policy: v1, ControlURL: cp.URL, PolicyKeyring: keyring, PolicyRefresh: 1 << 40, PolicyStateFile: state,
		OnAlert: func(k, _ string) { mu.Lock(); alerts = append(alerts, k); mu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	m.RefreshPolicy()
	if v := policyVersion(m.Policy()); v != 2 {
		t.Fatalf("policy version %d, want 2", v)
	}
	if code := decoyAction(t, m); code != http.StatusForbidden {
		t.Fatalf("the decoy route added in v2 is enforced: got %d", code)
	}
	mu.Lock()
	serve = "forged-v3.bundle"
	mu.Unlock()
	if m.RefreshPolicy() || policyVersion(m.Policy()) != 2 {
		t.Fatal("a forged bundle must change nothing")
	}
	mu.Lock()
	rejected := strings.Contains(strings.Join(alerts, ","), "policy_rejected")
	mu.Unlock()
	if !rejected {
		t.Fatal("the forged bundle raised no alert")
	}

	restarted, err := New(Options{Mode: "enforce", Policy: v1, PolicyKeyring: keyring, PolicyStateFile: state})
	if err != nil {
		t.Fatal(err)
	}
	if v := policyVersion(restarted.Policy()); v != 2 {
		t.Fatalf("a restart resumes at the saved policy: got %d", v)
	}
}

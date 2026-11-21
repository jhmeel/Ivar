package ivar

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"
)

func quiet(string, string) {}

func ok() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
}

func get(h http.Handler, path, ip string) int {
	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = ip + ":1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func TestObserveNeverAffectsRequests(t *testing.T) {
	m, err := New(Options{Mode: "observe", OnAlert: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if c := get(m.Handler(ok()), "/.env.backup", "203.0.113.4"); c != 200 {
		t.Fatalf("observe changed the response: %d", c)
	}
}

// enforcePolicy is the spec default policy with DETECTION_MODE enforce.
func enforcePolicy(t *testing.T) json.RawMessage {
	t.Helper()
	rt, err := Shared()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := DefaultPolicy(rt)
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	_ = json.Unmarshal(raw, &p)
	p["settings"].(map[string]any)["detection_mode"] = "enforce"
	out, _ := json.Marshal(p)
	return out
}

func TestSignedObservePolicyNeverBlocks(t *testing.T) {
	m, err := New(Options{Mode: "enforce", OnAlert: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if c := get(m.Handler(ok()), "/.env.backup", "203.0.113.6"); c != 200 {
		t.Fatalf("DETECTION_MODE observe in the signed policy must win: %d", c)
	}
}

func TestEnforceBlocksDecoyThenContainsSource(t *testing.T) {
	m, err := New(Options{Mode: "enforce", Policy: enforcePolicy(t), OnAlert: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	h := m.Handler(ok())
	if c := get(h, "/.env.backup", "203.0.113.5"); c != 403 {
		t.Fatalf("decoy not blocked: %d", c)
	}
	m.Flush(2 * time.Second)
	if c := get(h, "/hello", "203.0.113.5"); c != 403 {
		t.Fatalf("source not contained: %d", c)
	}
	if c := get(h, "/hello", "198.51.100.9"); c != 200 {
		t.Fatalf("other source affected: %d", c)
	}
}

func TestPayoutIntentChain(t *testing.T) {
	m, err := New(Options{Mode: "enforce", Identity: func(*http.Request) string { return "svc" }, Session: func(r *http.Request) string { return r.Header.Get("X-Session") }, OnAlert: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	steps := map[string]string{"authenticated_session": "2222222222222222222222222222222222222222222222222222222222222222", "ledger_entry": "3333333333333333333333333333333333333333333333333333333333333333", "payout_instruction": "4444444444444444444444444444444444444444444444444444444444444444"}
	keys := map[string]string{}
	order := []string{"authenticated_session", "ledger_entry", "payout_instruction"}
	for k, s := range steps {
		keys[k], _ = StepPublicKey(m.rt, s)
	}
	chain := func(id string, limit int64) (string, string) {
		tok, root, err := MintIntent(m.rt, "1111111111111111111111111111111111111111111111111111111111111111", id, "payout", "ses_1", map[string]int64{"amount": limit}, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range order {
			if tok, err = AttestStep(m.rt, steps[s], s, tok, root); err != nil {
				t.Fatal(err)
			}
		}
		return tok, root
	}
	tok, root := chain("i1", 5000)
	h, err := m.Guard("payout", root, keys, GuardOptions{IntentBinding: "enforce", Value: func(r *http.Request) float64 {
		if r.Header.Get("X-Amount") == "big" {
			return 60000
		}
		return 100
	}}, ok())
	if err != nil {
		t.Fatal(err)
	}
	pay := func(token, amount string) int {
		r := httptest.NewRequest("POST", "/payouts", nil)
		r.Header.Set("X-Session", "ses_1")
		r.Header.Set("X-Amount", amount)
		if token != "" {
			r.Header.Set(IntentHeader, token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if c := pay("", "small"); c != 403 {
		t.Fatalf("stolen credential: %d", c)
	}
	if c := pay(tok, "small"); c != 200 {
		t.Fatalf("full chain: %d", c)
	}
	big, _ := chain("i2", 100000)
	if c := pay(big, "big"); c != 202 {
		t.Fatalf("large payout not held: %d", c)
	}
}

func TestLocalDecisionLatency(t *testing.T) {
	m, err := New(Options{Mode: "enforce", OnAlert: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	r := httptest.NewRequest("GET", "/x", nil)
	var times []time.Duration
	for i := 0; i < 1000; i++ {
		s := time.Now()
		_, _ = m.sensor.Decide(m.Event(r, "http.request", 4002, 0, nil), nowMs())
		times = append(times, time.Since(s))
	}
	sort.Slice(times, func(a, b int) bool { return times[a] < times[b] })
	p99 := times[990]
	t.Logf("go local decision p99 %v", p99)
	if p99 > 5*time.Millisecond {
		t.Fatalf("p99 %v", p99)
	}
}

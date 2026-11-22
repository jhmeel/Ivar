// The test shop API in Go with net/http and the ivar SDK.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	ivar "github.com/jhmeel/ivar/sdk/go"
)

type user struct {
	ID       string
	Password string
	Roles    []string
	Balance  float64
}

var (
	mu       sync.Mutex
	users    = map[string]*user{}
	sessions = map[string]*user{}
)

func h(s string) string { b := sha256.Sum256([]byte(s)); return hex.EncodeToString(b[:]) }

func token(n int) string { b := make([]byte, n); _, _ = rand.Read(b); return hex.EncodeToString(b) }

func userOf(r *http.Request) *user {
	mu.Lock()
	defer mu.Unlock()
	return sessions[r.Header.Get("X-Session")]
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func body(r *http.Request) map[string]any {
	var m map[string]any
	_ = json.NewDecoder(r.Body).Decode(&m)
	return m
}

func main() {
	for i := 1; i <= 200; i++ {
		roles := []string{"customer"}
		if i == 1 {
			roles = []string{"admin"}
		}
		users[fmt.Sprintf("user%d@corp.test", i)] = &user{ID: fmt.Sprintf("u%d", i), Password: h(fmt.Sprintf("pw%d", i)), Roles: roles, Balance: 100000}
	}
	dir := os.Getenv("IVAR_DIR")
	read := func(f string) string {
		b, err := os.ReadFile(dir + "/" + f)
		if err != nil {
			log.Fatal(err)
		}
		return string(b)
	}
	rt, err := ivar.Shared()
	if err != nil {
		log.Fatal(err)
	}
	policy, err := ivar.VerifyPolicyBundle(rt, read("policy.bundle"), json.RawMessage(read("keyring.json")), 0)
	if err != nil {
		log.Fatal(err)
	}
	steps := map[string]string{"authenticated_session": os.Getenv("IVAR_STEP_SESSION"), "ledger_entry": os.Getenv("IVAR_STEP_LEDGER"), "payout_instruction": os.Getenv("IVAR_STEP_PAYOUT")}
	stepKeys := map[string]string{}
	for k, s := range steps {
		stepKeys[k], _ = ivar.StepPublicKey(rt, s)
	}
	root := os.Getenv("IVAR_ROOT_SEED")
	_, rootPub, _ := ivar.MintIntent(rt, root, "boot", "payout", "boot", map[string]int64{"amount": 1}, time.Minute)

	mode := os.Getenv("IVAR_MODE")
	if mode == "" {
		mode = "enforce"
	}
	mw, err := ivar.New(ivar.Options{
		Mode: mode,
		Identity: func(r *http.Request) string {
			if u := userOf(r); u != nil {
				return u.ID
			}
			return ""
		},
		Session: func(r *http.Request) string { return r.Header.Get("X-Session") },
		Roles: func(r *http.Request) []string {
			if u := userOf(r); u != nil {
				return u.Roles
			}
			return nil
		},
		CoreURL:   os.Getenv("IVAR_CORE_URL"),
		CoreToken: os.Getenv("IVAR_CORE_TOKEN"),
		// The gateway is the only peer; its X-Forwarded-For names the client.
		TrustedProxies: strings.Split(os.Getenv("IVAR_TRUSTED_PROXIES"), ","),
		Policy:         policy,
		RedactionKey:   strings.TrimSpace(read("keys/redaction.hex")),
		SensorID:       os.Getenv("SENSOR_ID"),
		OnAlert:        func(kind, msg string) { log.Printf(`{"ivar_alert":%q,"message":%q}`, kind, msg) },
		ControlURL:      os.Getenv("IVAR_CONTROL_URL"),
		PolicyKeyring:   json.RawMessage(read("keyring.json")),
		PolicyRefresh:   2 * time.Second,
		PolicyStateFile: os.Getenv("IVAR_DIR") + "/policy.state",
	})
	if err != nil {
		log.Fatal(err)
	}
	authed := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if userOf(r) == nil {
				reply(w, 401, map[string]string{"error": "login required"})
				return
			}
			next(w, r)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		b := body(r)
		email, _ := b["email"].(string)
		pw, _ := b["password"].(string)
		mu.Lock()
		u := users[email]
		mu.Unlock()
		ok := u != nil && u.Password == h(pw)
		mw.ReportLogin(r, ok, email)
		if !ok {
			reply(w, 401, map[string]string{"error": "invalid credentials"})
			return
		}
		sid := "ses_" + token(12)
		mu.Lock()
		sessions[sid] = u
		mu.Unlock()
		reply(w, 200, map[string]string{"session": sid})
	})
	mux.HandleFunc("GET /accounts/{id}", authed(func(w http.ResponseWriter, r *http.Request) {
		u := userOf(r)
		if u.ID != r.PathValue("id") {
			reply(w, 403, map[string]string{"error": "not your account"})
			return
		}
		reply(w, 200, map[string]any{"id": u.ID, "balance": u.Balance})
	}))
	mux.HandleFunc("PATCH /users/{id}", authed(func(w http.ResponseWriter, r *http.Request) {
		u := userOf(r)
		if role, _ := body(r)["role"].(string); role != "" {
			u.Roles = append(u.Roles, role)
		}
		reply(w, 200, map[string]any{"id": u.ID, "roles": u.Roles})
	}))
	mux.HandleFunc("POST /payouts/intent", authed(func(w http.ResponseWriter, r *http.Request) {
		amount, _ := body(r)["amount"].(float64)
		t, _, _ := ivar.MintIntent(rt, root, "int_"+token(6), "payout", r.Header.Get("X-Session"), map[string]int64{"amount": int64(amount)}, 5*time.Minute)
		for _, k := range []string{"authenticated_session", "ledger_entry", "payout_instruction"} {
			t, _ = ivar.AttestStep(rt, steps[k], k, t, rootPub)
		}
		reply(w, 200, map[string]string{"intent": t, "header": ivar.IntentHeader})
	}))
	amount := func(r *http.Request) float64 {
		// The guard reads the amount before the handler, so the body is
		// buffered and restored for it.
		raw, _ := readAll(r)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		v, _ := m["amount"].(float64)
		return v
	}
	payout, err := mw.Guard("payout", rootPub, stepKeys, ivar.GuardOptions{Value: amount}, authed(func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, map[string]bool{"sent": true})
	}))
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("POST /payouts", payout)
	mux.HandleFunc("GET /admin/users", authed(func(w http.ResponseWriter, r *http.Request) {
		for _, role := range userOf(r).Roles {
			if role == "admin" {
				reply(w, 200, map[string]int{"users": len(users)})
				return
			}
		}
		reply(w, 403, map[string]string{"error": "admins only"})
	}))
	port := os.Getenv("PORT")
	log.Fatal(http.ListenAndServe("127.0.0.1:"+port, mw.Handler(mux)))
}

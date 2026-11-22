package ivar

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// IntentHeader carries the intent token from origin to sink.
const IntentHeader = "Ivar-Intent"

// Options configure the middleware. Mode is "observe" or "enforce".
type Options struct {
	Mode          string
	Identity      func(*http.Request) string
	Session       func(*http.Request) string
	Roles         func(*http.Request) []string
	Tenant        func(*http.Request) string
	CoreURL       string
	Policy        json.RawMessage
	RedactionKey  string
	SensorID      string
	AdminPrefixes []string
	Budget        time.Duration
	OnAlert       func(kind, message string)
}

// Middleware is the net/http IVAR sensor.
type Middleware struct {
	opts   Options
	rt     *Runtime
	policy json.RawMessage
	sensor *LocalSensor
	core   *Core
	queue  chan map[string]any
	seq    atomic.Uint64
	done   chan struct{}
	idle   chan struct{}
}

// KeyedHash matches ivar_core::redact::keyed_hash.
func KeyedHash(keyHex, value string) string {
	key, err := hex.DecodeString(keyHex)
	if value == "" || strings.HasPrefix(value, "kh_") || keyHex == "" || err != nil {
		return value
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(value))
	return "kh_" + hex.EncodeToString(m.Sum(nil))[:24]
}

// New builds the middleware with the shared runtime.
func New(opts Options) (*Middleware, error) {
	if opts.Mode != "observe" && opts.Mode != "enforce" {
		return nil, fmt.Errorf("ivar: mode must be observe or enforce")
	}
	if opts.Identity == nil {
		opts.Identity = func(*http.Request) string { return "" }
	}
	if opts.SensorID == "" {
		opts.SensorID = "go-sdk"
	}
	if opts.AdminPrefixes == nil {
		opts.AdminPrefixes = []string{"/admin"}
	}
	if opts.Budget == 0 {
		opts.Budget = time.Millisecond
	}
	if opts.OnAlert == nil {
		opts.OnAlert = func(k, m string) { log.Printf("ivar %s: %s", k, m) }
	}
	rt, err := Shared()
	if err != nil {
		return nil, err
	}
	policy := opts.Policy
	if policy == nil {
		if policy, err = DefaultPolicy(rt); err != nil {
			return nil, err
		}
	}
	sensor, err := NewLocalSensor(rt, policy)
	if err != nil {
		return nil, err
	}
	warm(sensor)
	m := &Middleware{opts: opts, rt: rt, policy: policy, sensor: sensor, queue: make(chan map[string]any, 10_000), done: make(chan struct{}), idle: make(chan struct{}, 1)}
	if opts.CoreURL == "" {
		if m.core, err = NewCore(rt, policy, orDefault(opts.RedactionKey, "00")); err != nil {
			return nil, err
		}
	}
	go m.drain()
	return m, nil
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Event builds an OCSF SecurityEvent with the IVAR extension.
func (m *Middleware) Event(r *http.Request, activity string, classUID uint32, status int, ext map[string]any) map[string]any {
	user := map[string]any(nil)
	if id := m.opts.Identity(r); id != "" {
		user = map[string]any{"uid": KeyedHash(m.opts.RedactionKey, id), "type": "human"}
	}
	actor := map[string]any{"user": user}
	if m.opts.Session != nil {
		if s := m.opts.Session(r); s != "" {
			actor["session"] = map[string]any{"uid": s}
		}
	}
	if m.opts.Roles != nil {
		actor["authorizations"] = strings.Join(m.opts.Roles(r), ",")
	}
	ivarExt := map[string]any{"sensor_id": m.opts.SensorID, "sensor_type": "app_sdk", "observation_point": "app_sdk", "sensor_seq": m.seq.Add(1), "request_id": r.Header.Get("X-Request-Id")}
	if m.opts.Tenant != nil {
		ivarExt["tenant"] = m.opts.Tenant(r)
	}
	for k, v := range ext {
		ivarExt[k] = v
	}
	ev := map[string]any{
		"class_uid": classUID, "category_uid": classUID / 1000, "activity_id": 1, "time": nowMs(), "status_id": 1, "activity_name": activity,
		"metadata":     map[string]any{"version": "1.3.0", "extensions": []any{map[string]any{"name": "ivar", "uid": "999", "version": "1.0.0"}}},
		"actor":        actor,
		"src_endpoint": map[string]any{"ip": clientIP(r)},
		"http_request": map[string]any{"http_method": r.Method, "url_path": r.URL.Path, "user_agent": r.UserAgent()},
		"ivar":         ivarExt,
	}
	if status != 0 {
		ev["http_response"] = map[string]any{"code": status}
	}
	return ev
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// Handler wraps next with the IVAR check.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		admin := false
		for _, p := range m.opts.AdminPrefixes {
			admin = admin || strings.HasPrefix(r.URL.Path, p)
		}
		res, err := m.sensor.Decide(m.Event(r, "http.request", 4002, 0, nil), nowMs())
		if err != nil {
			if admin {
				m.opts.OnAlert("sdk_fault", "admin route failed closed: "+err.Error())
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "security check unavailable"})
				return
			}
			m.opts.OnAlert("fail_open", err.Error())
			next.ServeHTTP(w, r)
			return
		}
		if d := time.Since(started); d > m.opts.Budget {
			m.opts.OnAlert("budget_exceeded", "local decision took "+d.String())
		}
		sw := &statusWriter{ResponseWriter: w, code: 200}
		defer func() { m.submit(m.Event(r, "http.request", 4002, sw.code, nil)) }()
		if v := res.Verdict; v != nil && m.opts.Mode == "enforce" && v.Mode == "enforce" {
			switch v.Decision {
			case "block", "contain", "refuse":
				sw.code = 403
				writeJSON(w, 403, map[string]string{"error": "request blocked", "verdict_id": v.VerdictID})
				return
			case "challenge":
				sw.code = 401
				w.Header().Set("WWW-Authenticate", "step-up")
				writeJSON(w, 401, map[string]string{"error": "step up verification required", "verdict_id": v.VerdictID})
				return
			case "throttle":
				sw.code = 429
				writeJSON(w, 429, map[string]string{"error": "slow down", "verdict_id": v.VerdictID})
				return
			}
		}
		next.ServeHTTP(sw, r)
	})
}

// ReportLogin reports a login attempt for correlation.
func (m *Middleware) ReportLogin(r *http.Request, success bool, account string) {
	status := 1
	if !success {
		status = 2
	}
	ev := m.Event(r, "auth.login", 3002, 0, map[string]any{"target_entity": "user:" + KeyedHash(m.opts.RedactionKey, account)})
	ev["status_id"] = status
	m.submit(ev)
}

func (m *Middleware) submit(ev map[string]any) {
	select {
	case m.queue <- ev:
	default:
		m.opts.OnAlert("fail_open", "event buffer full")
	}
}

func (m *Middleware) drain() {
	client := &http.Client{Timeout: 2 * time.Second}
	for {
		select {
		case <-m.done:
			return
		case ev := <-m.queue:
			var verdicts []Verdict
			if m.core != nil {
				out, err := m.core.Process(ev, nowMs())
				if err != nil {
					m.opts.OnAlert("sdk_fault", err.Error())
				} else {
					verdicts = out.Verdicts
				}
			} else {
				body, _ := json.Marshal(map[string]any{"sensor_id": m.opts.SensorID, "events": []any{ev}})
				resp, err := client.Post(strings.TrimRight(m.opts.CoreURL, "/")+"/v1/events", "application/json", bytes.NewReader(body))
				if err == nil {
					var ack struct {
						Verdicts []Verdict `json:"verdicts"`
					}
					_ = json.NewDecoder(resp.Body).Decode(&ack)
					resp.Body.Close()
					verdicts = ack.Verdicts
				}
			}
			for _, v := range verdicts {
				_ = m.sensor.PushVerdict(v)
			}
			if len(m.queue) == 0 {
				select {
				case m.idle <- struct{}{}:
				default:
				}
			}
		}
	}
}

// Flush waits until queued events were scored.
func (m *Middleware) Flush(timeout time.Duration) {
	deadline := time.After(timeout)
	for len(m.queue) > 0 {
		select {
		case <-m.idle:
		case <-deadline:
			return
		case <-time.After(5 * time.Millisecond):
		}
	}
	time.Sleep(20 * time.Millisecond)
}

// Close stops the background worker.
func (m *Middleware) Close() { close(m.done) }

// GuardOptions configure an action sink.
type GuardOptions struct {
	IntentBinding string
	Value         func(*http.Request) float64
	Records       func(*http.Request) float64
	Destructive   bool
}

// Guard wraps a high consequence handler with the action sink. It fails closed.
func (m *Middleware) Guard(action, rootPublicKey string, stepKeys map[string]string, g GuardOptions, next http.Handler) (http.Handler, error) {
	var pol struct {
		Invariants    json.RawMessage   `json:"invariants"`
		IntentBinding map[string]string `json:"intent_binding"`
	}
	if err := json.Unmarshal(m.policy, &pol); err != nil {
		return nil, err
	}
	modes := map[string]string{}
	for k, v := range pol.IntentBinding {
		modes[k] = v
	}
	if g.IntentBinding != "" {
		modes[action] = g.IntentBinding
	}
	mode := orDefault(modes[action], "observe")
	sink, err := NewSink(m.rt, rootPublicKey, stepKeys, pol.Invariants, mode, modes)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject := m.opts.Identity(r)
		if m.opts.Session != nil && m.opts.Session(r) != "" {
			subject = m.opts.Session(r)
		}
		req := SinkRequest{Action: action, Subject: subject, Identity: m.opts.Identity(r), Destructive: g.Destructive}
		if g.Value != nil {
			req.ValueMoved = g.Value(r)
		}
		if g.Records != nil {
			req.RecordsRead = g.Records(r)
		}
		if t := r.Header.Get(IntentHeader); t != "" {
			req.IntentToken = &t
		}
		d, err := sink.Guard(req, nowMs())
		if err != nil {
			m.opts.OnAlert("sdk_fault", "action sink failed closed: "+err.Error())
			writeJSON(w, 503, map[string]string{"error": "action check unavailable"})
			return
		}
		m.submit(m.Event(r, "business.action", 6003, 0, map[string]any{"business_action": action, "value_moved": req.ValueMoved, "attributes": map[string]string{"sink_outcome": d.Outcome.Outcome}}))
		switch d.Outcome.Outcome {
		case "executes":
			if d.WouldRefuse != nil {
				m.opts.OnAlert("action_refused", "observe: would refuse "+action+": "+*d.WouldRefuse)
			}
			next.ServeHTTP(w, r)
		case "refused":
			m.opts.OnAlert("action_refused", d.Outcome.Reason)
			writeJSON(w, 403, map[string]string{"error": "no valid intent chain for this action"})
		case "blocked_alert":
			m.opts.OnAlert("invariant_breach", d.Outcome.InvariantID)
			writeJSON(w, 409, map[string]string{"error": "consequence limit reached", "invariant": d.Outcome.InvariantID})
		case "held":
			m.opts.OnAlert("time_lock", d.Outcome.Lock.LockID)
			writeJSON(w, 202, map[string]any{"status": "held", "lock_id": d.Outcome.Lock.LockID, "release_at": d.Outcome.Lock.ReleaseAt})
		}
	}), nil
}

// warm runs the fast path on a plain read and a write with body fields, so
// the first real request does not pay for the WebAssembly code's first run.
func warm(s *LocalSensor) {
	samples := []map[string]any{
		{"activity_name": "http.request", "http_request": map[string]any{"http_method": "GET", "url_path": "/"}, "src_endpoint": map[string]any{"ip": "192.0.2.1"}, "ivar": map[string]any{}},
		{"activity_name": "http.request", "http_request": map[string]any{"http_method": "POST", "url_path": "/login", "body_keys": []string{"email", "password"}},
			"actor": map[string]any{"user": map[string]any{"uid": "kh_warm"}}, "src_endpoint": map[string]any{"ip": "192.0.2.1"}, "ivar": map[string]any{}},
	}
	for i := 0; i < 200; i++ {
		_, _ = s.Decide(samples[i%len(samples)], time.Now().UnixMilli())
	}
}

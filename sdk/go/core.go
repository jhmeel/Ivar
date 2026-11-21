package ivar

import (
	"encoding/json"
	"time"
)

func nowMs() int64 { return time.Now().UnixMilli() }

// Verdict is the decision the core or a sensor returns (section 9).
type Verdict struct {
	VerdictID     string   `json:"verdict_id"`
	Decision      string   `json:"decision"`
	Risk          float64  `json:"risk"`
	Reasons       []string `json:"reasons"`
	Sources       []string `json:"sources"`
	PolicyVersion string   `json:"policy_version"`
	ExpiresAt     int64    `json:"expires_at"`
	Mode          string   `json:"mode"`
	LadderLevel   uint32   `json:"ladder_level"`
	Entity        *struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"entity,omitempty"`
}

// DefaultPolicy returns the spec default PolicyContent.
func DefaultPolicy(r *Runtime) (json.RawMessage, error) {
	var p json.RawMessage
	err := r.Call("policy.default", map[string]any{"now_ms": nowMs()}, 0, &p)
	return p, err
}

// VerifyPolicyBundle verifies a signed archive; rollback and expired bundles are refused.
func VerifyPolicyBundle(r *Runtime, archiveBase64 string, keyring json.RawMessage, currentVersion uint64) (json.RawMessage, error) {
	var p json.RawMessage
	err := r.Call("policy.verify", map[string]any{"archive_base64": archiveBase64, "keyring": keyring, "current_version": currentVersion, "now_ms": nowMs()}, 0, &p)
	return p, err
}

type handle struct {
	r *Runtime
	h uint64
}

func newHandle(r *Runtime, op string, args any) (handle, error) {
	var out struct {
		Handle uint64 `json:"handle"`
	}
	err := r.Call(op, args, 0, &out)
	return handle{r, out.Handle}, err
}

// Close frees the object inside the core.
func (h handle) Close() error { return h.r.Call("free", map[string]any{}, h.h, nil) }

// Core is the embedded decision core. Use it off the request path.
type Core struct{ handle }

func NewCore(r *Runtime, policy json.RawMessage, redactionKeyHex string) (*Core, error) {
	h, err := newHandle(r, "core.new", map[string]any{"policy": policy, "redaction_key_hex": redactionKeyHex})
	return &Core{h}, err
}

// Output of one Process call.
type Output struct {
	Decision   string    `json:"decision"`
	EvidenceID string    `json:"evidence_id"`
	Verdicts   []Verdict `json:"verdicts"`
	Incidents  []string  `json:"incidents"`
	Findings   []struct {
		Rule string `json:"rule"`
	} `json:"findings"`
}

func (c *Core) Process(event any, now int64) (*Output, error) {
	var out Output
	err := c.r.Call("core.process", map[string]any{"event": event, "now_ms": now}, c.h, &out)
	return &out, err
}

func (c *Core) Evidence() ([]json.RawMessage, error) {
	var out []json.RawMessage
	err := c.r.Call("core.evidence", map[string]any{}, c.h, &out)
	return out, err
}

// LocalSensor blocks known attacks with no round trip (section 7.1).
type LocalSensor struct{ handle }

func NewLocalSensor(r *Runtime, policy json.RawMessage) (*LocalSensor, error) {
	h, err := newHandle(r, "sensor.new", map[string]any{"policy": policy})
	return &LocalSensor{h}, err
}

// LocalResult says whether to block here, apply a cached verdict, or forward.
type LocalResult struct {
	Local   string   `json:"local"`
	Verdict *Verdict `json:"verdict"`
}

func (s *LocalSensor) Decide(event any, now int64) (*LocalResult, error) {
	var out LocalResult
	err := s.r.Call("sensor.decide", map[string]any{"event": event, "now_ms": now}, s.h, &out)
	return &out, err
}

func (s *LocalSensor) PushVerdict(v Verdict) error {
	return s.r.Call("sensor.push_verdict", map[string]any{"verdict": v}, s.h, nil)
}

// Sink is the action sink: intent binding, consequence invariants, time locks.
type Sink struct{ handle }

func NewSink(r *Runtime, rootPublicKey string, stepKeys map[string]string, invariants json.RawMessage, defaultMode string, modes map[string]string) (*Sink, error) {
	if modes == nil {
		modes = map[string]string{}
	}
	if stepKeys == nil {
		stepKeys = map[string]string{}
	}
	if len(invariants) == 0 {
		invariants = json.RawMessage("[]")
	}
	h, err := newHandle(r, "sink.new", map[string]any{"root_public_key": rootPublicKey, "step_keys": stepKeys, "invariants": invariants, "default_mode": defaultMode, "modes": modes})
	return &Sink{h}, err
}

// SinkRequest describes one high consequence action.
type SinkRequest struct {
	Action      string  `json:"action"`
	Subject     string  `json:"subject"`
	Identity    string  `json:"identity"`
	Business    string  `json:"business"`
	ValueMoved  float64 `json:"value_moved"`
	RecordsRead float64 `json:"records_read"`
	Destructive bool    `json:"destructive"`
	IntentToken *string `json:"intent_token"`
}

// SinkDecision is the sink's answer.
type SinkDecision struct {
	Outcome struct {
		Outcome     string  `json:"outcome"`
		Reason      string  `json:"reason"`
		InvariantID string  `json:"invariant_id"`
		Used        float64 `json:"used"`
		Limit       float64 `json:"limit"`
		Lock        *struct {
			LockID    string   `json:"lock_id"`
			ReleaseAt int64    `json:"release_at"`
			Owners    []string `json:"owners"`
		} `json:"lock"`
	} `json:"outcome"`
	IntentMode   string  `json:"intent_mode"`
	WouldRefuse  *string `json:"would_refuse"`
	OpenIncident bool    `json:"open_incident"`
}

func (s *Sink) Guard(req SinkRequest, now int64) (*SinkDecision, error) {
	var out SinkDecision
	err := s.r.Call("sink.guard", map[string]any{"request": req, "now_ms": now}, s.h, &out)
	return &out, err
}

// MintIntent mints an intent token where the business intent starts.
func MintIntent(r *Runtime, rootSeedHex, intentID, action, subject string, limits map[string]int64, ttl time.Duration) (token, rootPublicKey string, err error) {
	var out struct {
		Token         string `json:"token"`
		RootPublicKey string `json:"root_public_key"`
	}
	err = r.Call("intent.mint", map[string]any{"root_seed_hex": rootSeedHex, "intent_id": intentID, "action": action, "subject": subject, "limits": limits, "expiry_ms": nowMs() + ttl.Milliseconds()}, 0, &out)
	return out.Token, out.RootPublicKey, err
}

// AttestStep appends one step's attestation, signed with that step's key.
func AttestStep(r *Runtime, stepSeedHex, step, token, rootPublicKey string) (string, error) {
	var out struct {
		Token string `json:"token"`
	}
	err := r.Call("intent.attest", map[string]any{"step_seed_hex": stepSeedHex, "step": step, "token": token, "root_public_key": rootPublicKey, "narrowing": map[string]any{}}, 0, &out)
	return out.Token, err
}

// StepPublicKey returns the public key for a step seed.
func StepPublicKey(r *Runtime, stepSeedHex string) (string, error) {
	var out struct {
		PublicKey string `json:"public_key"`
	}
	err := r.Call("intent.step_public_key", map[string]any{"step_seed_hex": stepSeedHex}, 0, &out)
	return out.PublicKey, err
}

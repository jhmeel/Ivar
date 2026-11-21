package controlplane

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// SignedFlag matches ivar_core::config::SignedFlag; the signed bytes are
// "ivar.flag.v1\n{name}\n{value}\n{version}\n{issued_at}".
type SignedFlag struct {
	Name      string           `json:"name"`
	Value     string           `json:"value"`
	Version   uint64           `json:"version"`
	IssuedAt  int64            `json:"issued_at"`
	Signature *BundleSignature `json:"signature"`
}

func flagBytes(f SignedFlag) []byte {
	return []byte(fmt.Sprintf("ivar.flag.v1\n%s\n%s\n%d\n%d", f.Name, f.Value, f.Version, f.IssuedAt))
}

// FleetWide flags change the whole fleet and need two operator approvals.
var FleetWide = map[string]bool{"RUNTIME_POSTURE": true, "DETECTION_MODE": true, "PAYOUTS_ENABLED": true, "REGISTRATION_MODE": true, "SIGNING_ENABLED": true, "EXPORTS_ENABLED": true, "INTENT_BINDING": true}

// OperatorApproval is an operator's signature over "flag:{name}={value}@{version}".
type OperatorApproval struct {
	Operator  string `json:"operator"`
	Signature string `json:"signature"`
}

// FlagStore holds the signed runtime flags.
type FlagStore struct {
	mu        sync.Mutex
	flags     map[string]SignedFlag
	key       PolicyKey
	Operators map[string]ed25519.PublicKey
}

func NewFlagStore(key PolicyKey, operators map[string]ed25519.PublicKey) *FlagStore {
	return &FlagStore{flags: map[string]SignedFlag{}, key: key, Operators: operators}
}

// Set signs a new flag version after checking approvals. Fleet wide flags
// need two distinct operators; others one.
func (s *FlagStore) Set(name, value string, approvals []OperatorApproval, now time.Time) (SignedFlag, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.flags[name].Version + 1
	msg := []byte(fmt.Sprintf("flag:%s=%s@%d", name, value, next))
	ok := map[string]bool{}
	for _, a := range approvals {
		pk, has := s.Operators[a.Operator]
		sig, err := base64.StdEncoding.DecodeString(a.Signature)
		if has && err == nil && ed25519.Verify(pk, msg, sig) {
			ok[a.Operator] = true
		}
	}
	need := 1
	if FleetWide[name] {
		need = 2
	}
	if len(ok) < need {
		return SignedFlag{}, fmt.Errorf("%s needs %d operator approvals, has %d valid", name, need, len(ok))
	}
	f := SignedFlag{Name: name, Value: value, Version: next, IssuedAt: now.UnixMilli()}
	f.Signature = &BundleSignature{Alg: "ed25519", KeyID: s.key.ID, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(s.key.Priv, flagBytes(f)))}
	s.flags[name] = f
	return f, nil
}

// All returns the current signed flags.
func (s *FlagStore) All() map[string]SignedFlag {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]SignedFlag{}
	for k, v := range s.flags {
		out[k] = v
	}
	return out
}

// VerifyFlag checks a flag signature (as the Rust sensors do).
func VerifyFlag(f SignedFlag, pub ed25519.PublicKey) error {
	if f.Signature == nil {
		return errors.New("unsigned flag")
	}
	sig, err := base64.StdEncoding.DecodeString(f.Signature.Sig)
	if err != nil || !ed25519.Verify(pub, flagBytes(f), sig) {
		return errors.New("flag signature invalid")
	}
	return nil
}

// PublicHex of a policy key, for keyrings.
func (k PolicyKey) PublicHex() string { return hex.EncodeToString(k.Priv.Public().(ed25519.PublicKey)) }

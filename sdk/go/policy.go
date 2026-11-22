package ivar

// Signed policy from the control plane: polled, verified, applied while the
// application runs, and kept on local disk so a restart during a control
// plane outage resumes at the last verified policy (sections 11.2 and 15).

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var policyClient = &http.Client{Timeout: 5 * time.Second}

// Policy is the verified PolicyContent in force.
func (m *Middleware) Policy() json.RawMessage {
	m.policyMu.RLock()
	defer m.policyMu.RUnlock()
	return m.policy
}

func policyVersion(p json.RawMessage) uint64 {
	var v struct {
		Version uint64 `json:"version"`
	}
	_ = json.Unmarshal(p, &v)
	return v.Version
}

func (m *Middleware) refreshLoop() {
	every := m.opts.PolicyRefresh
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		m.RefreshPolicy()
		select {
		case <-m.done:
			return
		case <-t.C:
		}
	}
}

// RefreshPolicy polls the control plane once; true when a newer policy was
// applied. An unreachable control plane leaves the current policy in force.
func (m *Middleware) RefreshPolicy() bool {
	q := url.Values{"have": {fmt.Sprint(policyVersion(m.Policy()))}, "sensor": {m.opts.SensorID}}
	res, err := policyClient.Get(strings.TrimRight(m.opts.ControlURL, "/") + "/v1/policy/bundle?" + q.Encode())
	if err != nil {
		return false
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return false
	}
	return m.applyPolicy(string(body), "control_plane")
}

// applyPolicy verifies a signed bundle and adopts it when newer. A bundle
// that fails verification or is older changes nothing and raises an alert.
func (m *Middleware) applyPolicy(archive, source string) bool {
	m.policyMu.Lock()
	defer m.policyMu.Unlock()
	have := policyVersion(m.policy)
	next, err := VerifyPolicyBundle(m.rt, strings.TrimSpace(archive), m.opts.PolicyKeyring, have)
	if err != nil {
		m.opts.OnAlert("policy_rejected", fmt.Sprintf("signed policy from %s refused, current policy kept: %v", source, err))
		return false
	}
	version := policyVersion(next)
	if version <= have {
		return false
	}
	if err := m.sensor.UpdatePolicy(next); err != nil {
		m.opts.OnAlert("policy_rejected", fmt.Sprintf("policy %d refused by the engine, current policy kept: %v", version, err))
		return false
	}
	if m.core != nil {
		if err := m.core.UpdatePolicy(next, nowMs()); err != nil {
			m.opts.OnAlert("policy_rejected", fmt.Sprintf("policy %d refused by the embedded core: %v", version, err))
		}
	}
	m.policy = next
	if m.opts.PolicyStateFile != "" {
		tmp := m.opts.PolicyStateFile + ".tmp"
		if err := os.WriteFile(tmp, []byte(strings.TrimSpace(archive)), 0o600); err == nil {
			err = os.Rename(tmp, m.opts.PolicyStateFile)
		}
		if err != nil {
			m.opts.OnAlert("policy_state", fmt.Sprintf("policy %d applied but not saved: %v", version, err))
		}
	}
	m.opts.OnAlert("policy_applied", fmt.Sprintf("policy %d applied from %s", version, source))
	return true
}

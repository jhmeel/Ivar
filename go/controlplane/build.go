package controlplane

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	ivar "github.com/jhmeel/ivar/sdk/go"
	"gopkg.in/yaml.v3"
)

// Source is the operator's policy source (policy.yaml), in the same table
// shape as the hardening settings. Resolve order: profile default,
// environment override, hard limits and cross checks (checked by the core
// when the bundle loads), then signed runtime flags.
type Source struct {
	Version       uint64           `yaml:"version"`
	PolicyVersion string           `yaml:"policy_version"`
	Profile       string           `yaml:"profile"`
	ValidDays     int              `yaml:"valid_days"`
	Settings      map[string]any   `yaml:"settings"`
	Thresholds    map[string]any   `yaml:"thresholds"`
	Rules         []map[string]any `yaml:"rules"`
	Invariants    []map[string]any `yaml:"invariants"`
	TimeLocksFile string           `yaml:"time_locks_file"`
	// OperatorDecisions names operator-decisions.yaml (section 21).
	OperatorDecisions string                    `yaml:"operator_decisions_file"`
	Protected         []map[string]any          `yaml:"protected_entities"`
	Shared            []string                  `yaml:"shared_networks"`
	Decoys            []map[string]any          `yaml:"decoys"`
	DecoyTouchers     []map[string]any          `yaml:"decoy_touchers"`
	IntentBinding     map[string]string         `yaml:"intent_binding"`
	Declarations      []Declaration             `yaml:"declarations"`
	Plugins           map[string]string         `yaml:"plugin_versions"`
	Indicators        map[string]float64        `yaml:"-"`
	Extra             map[string]map[string]any `yaml:"rule_params"`
}

// Declaration is one declared intent file compiled by the core.
type Declaration struct {
	Kind   string `yaml:"kind"` // openapi, iam, kubernetes, github_workflow, npm_lockfile, terraform_plan
	File   string `yaml:"file"`
	Holder string `yaml:"holder"`
}

// LoadSource reads policy.yaml.
func LoadSource(path string) (*Source, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Source
	if err := yaml.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func merge(dst map[string]any, src map[string]any) {
	for k, v := range src {
		if m, ok := v.(map[string]any); ok {
			if d, ok := dst[k].(map[string]any); ok {
				merge(d, m)
				continue
			}
		}
		dst[k] = v
	}
}

// Build turns a source into PolicyContent JSON. The schema comes from the
// core itself (policy.default through the WebAssembly runtime), and
// declarations are compiled by the same core, so the control plane never
// produces a field the core does not understand.
func Build(rt *ivar.Runtime, s *Source, baseDir string, now time.Time) ([]byte, error) {
	raw, err := ivar.DefaultPolicy(rt)
	if err != nil {
		return nil, err
	}
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	days := s.ValidDays
	if days <= 0 {
		days = 30
	}
	p["version"] = s.Version
	p["policy_version"] = s.PolicyVersion
	p["issued_at"] = now.UnixMilli()
	p["expires_at"] = now.Add(time.Duration(days) * 24 * time.Hour).UnixMilli()
	settings := p["settings"].(map[string]any)
	switch s.Profile {
	case "payments":
		settings["runtime_posture"] = "payments"
	case "lockdown":
		settings["runtime_posture"] = "lockdown"
		settings["detection_mode"] = "enforce"
	}
	merge(settings, s.Settings)
	merge(p["thresholds"].(map[string]any), s.Thresholds)
	if s.OperatorDecisions != "" {
		d, err := LoadDecisions(filepath.Join(baseDir, s.OperatorDecisions))
		if err != nil {
			return nil, err
		}
		if s.TimeLocksFile == "" {
			s.TimeLocksFile = d.TimeLocks.Value
		}
		if err := d.Apply(p, s); err != nil {
			return nil, err
		}
	}
	if s.Rules != nil {
		p["rules"] = s.Rules
	}
	if s.Invariants != nil {
		p["invariants"] = s.Invariants
	}
	if s.TimeLocksFile != "" {
		if err := applyTimeLocks(p, filepath.Join(baseDir, s.TimeLocksFile)); err != nil {
			return nil, err
		}
	}
	if s.Protected != nil {
		p["protected_entities"] = s.Protected
	}
	if s.Shared != nil {
		p["shared_networks"] = s.Shared
	}
	if s.Decoys != nil {
		p["decoys"] = s.Decoys
	}
	if s.DecoyTouchers != nil {
		p["decoy_touchers"] = s.DecoyTouchers
	}
	for k, v := range s.IntentBinding {
		p["intent_binding"].(map[string]any)[k] = v
	}
	if s.Plugins != nil {
		p["plugin_versions"] = s.Plugins
	}
	declared := map[string]any{}
	for _, d := range s.Declarations {
		text, err := os.ReadFile(filepath.Join(baseDir, d.File))
		if err != nil {
			return nil, fmt.Errorf("declaration %s: %w", d.File, err)
		}
		var out map[string]any
		if err := rt.Call("declare.compile", map[string]any{"kind": d.Kind, "file": d.File, "text": string(text), "holder": d.Holder}, 0, &out); err != nil {
			return nil, fmt.Errorf("declaration %s: %w", d.File, err)
		}
		mergeDeclarations(declared, out)
	}
	if len(declared) > 0 {
		p["declared"] = declared
	}
	if len(s.Indicators) > 0 || s.Extra != nil {
		applyRuleParams(p, s)
	}
	return json.MarshalIndent(p, "", "  ")
}

func mergeDeclarations(dst, src map[string]any) {
	for k, v := range src {
		switch x := v.(type) {
		case []any:
			// Start from an empty list, not nil, so an empty section is
			// written as [] rather than null.
			cur, _ := dst[k].([]any)
			if cur == nil {
				cur = []any{}
			}
			dst[k] = append(cur, x...)
		case map[string]any:
			cur, ok := dst[k].(map[string]any)
			if !ok {
				cur = map[string]any{}
			}
			for kk, vv := range x {
				cur[kk] = vv
			}
			dst[k] = cur
		}
	}
}

// TimeLocks file: one entry per irreversible action (TIME_LOCKS setting).
type timeLock struct {
	Action    string   `yaml:"action"`
	Threshold float64  `yaml:"threshold"`
	DelaySecs uint64   `yaml:"delay_secs"`
	Owners    []string `yaml:"cancelling_owners"`
}

func applyTimeLocks(p map[string]any, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("TIME_LOCKS file: %w", err)
	}
	var locks []timeLock
	if err := yaml.Unmarshal(b, &locks); err != nil {
		return err
	}
	invs, _ := p["invariants"].([]any)
	for _, l := range locks {
		for _, inv := range invs {
			m := inv.(map[string]any)
			if m["action"] == l.Action {
				m["time_lock"] = map[string]any{"threshold": l.Threshold, "delay_secs": l.DelaySecs, "cancelling_owners": l.Owners}
			}
		}
	}
	return nil
}

func applyRuleParams(p map[string]any, s *Source) {
	rules, _ := p["rules"].([]any)
	for id, params := range s.Extra {
		rules = append(rules, map[string]any{"rule_id": id, "params": params, "_merge": true})
	}
	if len(s.Indicators) > 0 {
		rules = append(rules, map[string]any{"rule_id": "shared_indicator", "family": "intel.shared_indicator", "method": "signatures", "technique": "T1583", "attack_stage": "reconnaissance", "confidence": 0.6, "severity": 3, "enforce": true,
			"params": map[string]any{"network_key_hex": s.Settings["indicator_network_key_hex"], "hashes": s.Indicators}})
	}
	out := []any{}
	for _, r := range rules {
		if m, ok := r.(map[string]any); ok && m["_merge"] == true {
			continue
		}
		out = append(out, r)
	}
	p["rules"] = out
}

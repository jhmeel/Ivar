package controlplane

import (
	"encoding/json"
	"fmt"
)

// Weakens compares a new policy with the one in force and lists every way it
// lowers protection: a lower threshold, a larger blast radius budget, a new
// exemption (protected entity, shared network, decoy toucher), a rule set to
// observe, or a weaker intent binding or detection mode.
func Weakens(prev, next []byte) ([]string, error) {
	var a, b map[string]any
	if err := json.Unmarshal(prev, &a); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(next, &b); err != nil {
		return nil, err
	}
	var out []string
	ta, _ := a["thresholds"].(map[string]any)
	tb, _ := b["thresholds"].(map[string]any)
	for _, k := range []string{"throttle", "challenge", "contain", "slow_throttle", "slow_challenge", "slow_contain", "high_confidence"} {
		x, _ := ta[k].(float64)
		y, _ := tb[k].(float64)
		if y > x {
			out = append(out, fmt.Sprintf("threshold %s raised from %v to %v (acts later)", k, x, y))
		}
	}
	sa, _ := a["settings"].(map[string]any)
	sb, _ := b["settings"].(map[string]any)
	if x, y := sa["auto_contain_max_users_pct"], sb["auto_contain_max_users_pct"]; fmt.Sprint(x) != fmt.Sprint(y) {
		out = append(out, fmt.Sprintf("blast radius budget changed from %v to %v", x, y))
	}
	if sa["detection_mode"] == "enforce" && sb["detection_mode"] != "enforce" {
		out = append(out, "detection mode lowered to observe")
	}
	if sa["runtime_posture"] == "lockdown" && sb["runtime_posture"] != "lockdown" {
		out = append(out, "lockdown posture lifted")
	}
	rank := map[string]int{"off": 0, "observe": 1, "enforce": 2}
	ia, _ := a["intent_binding"].(map[string]any)
	ib, _ := b["intent_binding"].(map[string]any)
	for k, v := range ia {
		if rank[fmt.Sprint(ib[k])] < rank[fmt.Sprint(v)] {
			out = append(out, fmt.Sprintf("intent binding for %s lowered from %v to %v", k, v, ib[k]))
		}
	}
	for _, list := range []string{"protected_entities", "shared_networks", "decoy_touchers"} {
		la, _ := a[list].([]any)
		lb, _ := b[list].([]any)
		if len(lb) > len(la) {
			out = append(out, fmt.Sprintf("%d new %s exemption(s)", len(lb)-len(la), list))
		}
	}
	ra := map[string]bool{}
	for _, r := range asList(a["rules"]) {
		ra[fmt.Sprint(r["rule_id"])] = r["enforce"] != false
	}
	for _, r := range asList(b["rules"]) {
		if r["enforce"] == false && ra[fmt.Sprint(r["rule_id"])] {
			out = append(out, fmt.Sprintf("rule %v set to observe", r["rule_id"]))
		}
		if r["enforce"] == false {
			if _, known := ra[fmt.Sprint(r["rule_id"])]; !known {
				out = append(out, fmt.Sprintf("rule %v added in observe", r["rule_id"]))
			}
		}
	}
	for _, inv := range asList(a["invariants"]) {
		for _, nb := range asList(b["invariants"]) {
			if inv["invariant_id"] == nb["invariant_id"] {
				x, _ := inv["limit"].(float64)
				y, _ := nb["limit"].(float64)
				if y > x {
					out = append(out, fmt.Sprintf("invariant %v limit raised from %v to %v", inv["invariant_id"], x, y))
				}
			}
		}
	}
	return out, nil
}

func asList(v any) []map[string]any {
	l, _ := v.([]any)
	out := make([]map[string]any, 0, len(l))
	for _, x := range l {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// MarkWeakening sets weakens_protection in the content when the change weakens.
func MarkWeakening(prev, next []byte) ([]byte, []string, error) {
	reasons, err := Weakens(prev, next)
	if err != nil {
		return nil, nil, err
	}
	var p map[string]any
	_ = json.Unmarshal(next, &p)
	p["weakens_protection"] = len(reasons) > 0
	b, err := json.MarshalIndent(p, "", "  ")
	return b, reasons, err
}

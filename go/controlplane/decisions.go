package controlplane

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Decisions are the seven choices the operator confirms before build
// (section 21). Each records its value and who confirmed it; the build
// refuses a decisions file with an unconfirmed entry, so no deployment runs
// on defaults nobody agreed to.
type Decisions struct {
	AIAutonomy         Decision[string]           `yaml:"ai_autonomy"`
	FirstWavePlatforms Decision[[]string]         `yaml:"first_wave_platforms"`
	BlastRadius        Decision[BlastRadius]      `yaml:"blast_radius"`
	EvidenceRetention  Decision[int]              `yaml:"evidence_retention_days"`
	TimeLocks          Decision[string]           `yaml:"time_locks_file"`
	IntentBinding      Decision[IntentBinding]    `yaml:"intent_binding"`
	IndicatorNetwork   Decision[IndicatorNetwork] `yaml:"shared_indicator_network"`
}

// Decision is one confirmed choice.
type Decision[T any] struct {
	Value       T      `yaml:"value"`
	ConfirmedBy string `yaml:"confirmed_by"`
	ConfirmedOn string `yaml:"confirmed_on"`
	Note        string `yaml:"note"`
}

// BlastRadius is the automatic containment budget and the entities never
// contained automatically.
type BlastRadius struct {
	AutoContainMaxUsersPct float64          `yaml:"auto_contain_max_users_pct"`
	ProtectedEntities      []map[string]any `yaml:"protected_entities"`
}

// IntentBinding names the actions that require a valid intent chain in the
// first release and the mode they start in.
type IntentBinding struct {
	Actions []string `yaml:"actions"`
	Mode    string   `yaml:"mode"`
}

// IndicatorNetwork is the opt in to the shared indicator network. Keyed
// hashes are personal data under the NDPA 2023, so joining needs a lawful
// basis, a Legitimate Interest Assessment, a data sharing agreement and a
// review by Nigerian counsel (section 17).
type IndicatorNetwork struct {
	Join                 bool   `yaml:"join"`
	LawfulBasis          string `yaml:"lawful_basis"`
	LegitimateInterestAR string `yaml:"legitimate_interest_assessment"`
	DataSharingAgreement string `yaml:"data_sharing_agreement"`
	CounselReview        string `yaml:"counsel_review"`
	CrossBorderReview    string `yaml:"cross_border_review"`
}

// LoadDecisions reads and checks operator-decisions.yaml.
func LoadDecisions(path string) (*Decisions, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d Decisions
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("operator decisions: %w", err)
	}
	return &d, d.Validate()
}

// Validate refuses unconfirmed or out of range decisions.
func (d *Decisions) Validate() error {
	var problems []string
	confirmed := map[string]string{
		"ai_autonomy": d.AIAutonomy.ConfirmedBy, "first_wave_platforms": d.FirstWavePlatforms.ConfirmedBy,
		"blast_radius": d.BlastRadius.ConfirmedBy, "evidence_retention_days": d.EvidenceRetention.ConfirmedBy,
		"time_locks_file": d.TimeLocks.ConfirmedBy, "intent_binding": d.IntentBinding.ConfirmedBy,
		"shared_indicator_network": d.IndicatorNetwork.ConfirmedBy,
	}
	keys := make([]string, 0, len(confirmed))
	for k := range confirmed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.TrimSpace(confirmed[k]) == "" {
			problems = append(problems, k+" is not confirmed")
		}
	}
	switch d.AIAutonomy.Value {
	case "off", "advise", "propose", "bounded":
	default:
		problems = append(problems, "ai_autonomy must be off, advise, propose or bounded")
	}
	if p := d.BlastRadius.Value.AutoContainMaxUsersPct; !(p > 0 && p <= 5) {
		problems = append(problems, "blast_radius.auto_contain_max_users_pct must be above 0 and at most 5")
	}
	if d.EvidenceRetention.Value < 90 {
		problems = append(problems, "evidence_retention_days must keep evidence searchable well beyond 90 days")
	}
	switch d.IntentBinding.Value.Mode {
	case "off", "observe", "enforce":
	default:
		problems = append(problems, "intent_binding.mode must be off, observe or enforce")
	}
	if n := d.IndicatorNetwork.Value; n.Join {
		for name, v := range map[string]string{"lawful_basis": n.LawfulBasis, "legitimate_interest_assessment": n.LegitimateInterestAR, "data_sharing_agreement": n.DataSharingAgreement, "counsel_review": n.CounselReview} {
			if strings.TrimSpace(v) == "" {
				problems = append(problems, "joining the shared indicator network needs "+name)
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("operator decisions: %s", strings.Join(problems, "; "))
	}
	return nil
}

// Apply writes the decisions into the built policy. A policy source that
// sets a decided value to something else is refused: the decision was
// confirmed by a named person, so changing it means changing the decision.
func (d *Decisions) Apply(p map[string]any, s *Source) error {
	settings := p["settings"].(map[string]any)
	decided := map[string]any{
		"ai_autonomy":                d.AIAutonomy.Value,
		"auto_contain_max_users_pct": d.BlastRadius.Value.AutoContainMaxUsersPct,
		"evidence_retention_days":    d.EvidenceRetention.Value,
	}
	for k, v := range decided {
		if sv, set := s.Settings[k]; set && fmt.Sprint(sv) != fmt.Sprint(v) {
			return fmt.Errorf("policy source sets %s to %v but the operator decided %v", k, sv, v)
		}
		settings[k] = v
	}
	settings["rollout_platforms"] = d.FirstWavePlatforms.Value
	settings["shared_indicator_network"] = d.IndicatorNetwork.Value.Join
	if len(d.BlastRadius.Value.ProtectedEntities) > 0 {
		cur, _ := p["protected_entities"].([]any)
		for _, e := range d.BlastRadius.Value.ProtectedEntities {
			cur = append(cur, e)
		}
		p["protected_entities"] = cur
	}
	ib, _ := p["intent_binding"].(map[string]any)
	if ib == nil {
		ib = map[string]any{}
		p["intent_binding"] = ib
	}
	for _, a := range d.IntentBinding.Value.Actions {
		if _, set := s.IntentBinding[a]; !set {
			ib[a] = d.IntentBinding.Value.Mode
		}
	}
	if !d.IndicatorNetwork.Value.Join {
		// Not joined: no shared indicators enter the policy.
		s.Indicators = nil
	}
	return nil
}

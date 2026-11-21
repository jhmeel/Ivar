// Package telco provides SIM swap recency as an identity risk signal
// (section 17): through the CBN and NCC Telecom Identity Risk Management
// System (TIRMS) once licensed access is available, or through operator
// services such as MTN's Chenosis SIM swap checks. Operator APIs differ in
// shape, so each is wrapped behind one interface, with the response fields
// set in configuration rather than assumed.
package telco

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jhmeel/ivar/go/internal/coreclient"
	"github.com/jhmeel/ivar/go/internal/ocsf"
)

// Status of one phone number.
type Status struct {
	SwappedAt  time.Time
	Swapped    bool
	Reassigned bool
	Flagged    bool
	Source     string
}

// Provider is one SIM swap source.
type Provider interface {
	Name() string
	Check(ctx context.Context, msisdn string) (Status, error)
}

// HTTPProvider calls a JSON API. Request and response field names come from
// configuration, because TIRMS access terms and operator APIs set them.
type HTTPProvider struct {
	ProviderName string `json:"name"`
	URL          string `json:"url"`
	// Header and value for the credential, e.g. Authorization: Bearer ...
	AuthHeader string `json:"auth_header"`
	AuthValue  string `json:"-"`
	// Request body template; {msisdn} is replaced.
	RequestTemplate string `json:"request_template"`
	// Dotted paths into the response.
	SwappedAtField  string `json:"swapped_at_field"`
	SwappedField    string `json:"swapped_field"`
	ReassignedField string `json:"reassigned_field"`
	FlaggedField    string `json:"flagged_field"`
	HTTP            *http.Client `json:"-"`
}

func (p *HTTPProvider) Name() string { return p.ProviderName }

func lookup(m map[string]any, path string) any {
	if path == "" {
		return nil
	}
	var cur any = m
	for _, k := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true") || strings.EqualFold(x, "yes") || x == "1"
	case float64:
		return x != 0
	}
	return false
}

func (p *HTTPProvider) Check(ctx context.Context, msisdn string) (Status, error) {
	body := strings.ReplaceAll(p.RequestTemplate, "{msisdn}", msisdn)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, p.URL, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	if p.AuthHeader != "" {
		req.Header.Set(p.AuthHeader, p.AuthValue)
	}
	c := p.HTTP
	if c == nil {
		c = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return Status{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return Status{}, fmt.Errorf("%s returned %d: %s", p.ProviderName, resp.StatusCode, b)
	}
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return Status{}, err
	}
	st := Status{Source: p.ProviderName, Reassigned: truthy(lookup(m, p.ReassignedField)), Flagged: truthy(lookup(m, p.FlaggedField))}
	if s, ok := lookup(m, p.SwappedAtField).(string); ok && s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			st.SwappedAt, st.Swapped = t, true
		}
	}
	if !st.Swapped {
		st.Swapped = truthy(lookup(m, p.SwappedField))
	}
	return st, nil
}

// Checker answers SIM swap checks from SDKs and emits telco.sim_swap events,
// so the core can require step up for a reset or payout soon after a swap.
type Checker struct {
	Providers []Provider
	Core      *coreclient.Client
	SensorID  string
	// Deployment key for keyed hashes of phone numbers.
	KeyHex string
}

// Check asks each provider in order (TIRMS first when licensed) until one answers.
func (c *Checker) Check(ctx context.Context, msisdn string) (Status, error) {
	var last error
	for _, p := range c.Providers {
		st, err := p.Check(ctx, msisdn)
		if err == nil {
			subscriber := ocsf.KeyedHash(c.KeyHex, msisdn)
			if st.Swapped || st.Reassigned || st.Flagged {
				ev := ocsf.New(c.SensorID, "telco", ocsf.ClassAccountChange, "telco.sim_swap", time.Now()).
					Attr("subscriber", subscriber).Attr("source", st.Source).
					Attr("reassigned", fmt.Sprint(st.Reassigned)).Attr("flagged", fmt.Sprint(st.Flagged))
				if !st.SwappedAt.IsZero() {
					ev.Attr("swapped_at", fmt.Sprint(st.SwappedAt.UnixMilli()))
				}
				c.Core.Emit(ev)
			}
			return st, nil
		}
		last = err
	}
	return Status{}, fmt.Errorf("no SIM swap provider answered: %v", last)
}

// ServeHTTP: POST {"msisdn": "+234..."} returns {"swapped_within_hours": n | null, ...}.
func (c *Checker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		MSISDN string `json:"msisdn"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.MSISDN == "" {
		http.Error(w, "msisdn required", http.StatusBadRequest)
		return
	}
	st, err := c.Check(r.Context(), in.MSISDN)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	out := map[string]any{"swapped": st.Swapped, "reassigned": st.Reassigned, "flagged": st.Flagged, "source": st.Source, "subscriber": ocsf.KeyedHash(c.KeyHex, in.MSISDN)}
	if !st.SwappedAt.IsZero() {
		out["swapped_within_hours"] = time.Since(st.SwappedAt).Hours()
	}
	_ = json.NewEncoder(w).Encode(out)
}

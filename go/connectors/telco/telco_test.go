package telco

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ivar/ivar/go/internal/coreclient"
)

func TestFallsBackAndEmitsSwap(t *testing.T) {
	tirms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer tirms.Close()
	swapped := time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339)
	chenosis := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k" {
			w.WriteHeader(401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"lastSimSwapDate": swapped, "simSwapped": true}})
	}))
	defer chenosis.Close()
	core := coreclient.New("http://unused", "telco-1", "telco")
	c := &Checker{Core: core, SensorID: "telco-1", KeyHex: "0a0b", Providers: []Provider{
		&HTTPProvider{ProviderName: "tirms", URL: tirms.URL, RequestTemplate: `{"msisdn":"{msisdn}"}`},
		&HTTPProvider{ProviderName: "mtn_chenosis", URL: chenosis.URL, AuthHeader: "Authorization", AuthValue: "Bearer k", RequestTemplate: `{"phoneNumber":"{msisdn}"}`, SwappedAtField: "data.lastSimSwapDate", SwappedField: "data.simSwapped"},
	}}
	w := httptest.NewRecorder()
	c.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sim-swap/check", strings.NewReader(`{"msisdn":"+2348030000000"}`)))
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out["source"] != "mtn_chenosis" || out["swapped_within_hours"].(float64) < 2.9 {
		t.Fatalf("%v", out)
	}
	if n, _ := core.Pending(); n != 1 {
		t.Fatal("sim swap event not emitted")
	}
	_, _ = c.Check(context.Background(), "+2348030000000")
}

func TestChannels(t *testing.T) {
	e := AgentTransaction("agents-1", "0a", "agent-77", "356938035643809", "+2348030000000", "cash_out", 250000, time.Now())
	if e["ivar"].(map[string]any)["business_action"] != "payout" || e["ivar"].(map[string]any)["value_moved"] != 250000.0 {
		t.Fatal(e)
	}
}

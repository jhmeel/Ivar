package identity

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOktaPollMapAndRevoke(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "SSWS tok" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/api/v1/logs" {
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"published": "2026-11-19T02:15:00.000Z", "eventType": "user.session.start", "outcome": map[string]any{"result": "FAILURE"}, "actor": map[string]any{"alternateId": "ceo@acme"}, "client": map[string]any{"ipAddress": "203.0.113.5"}},
				{"published": "2026-11-19T02:16:00.000Z", "eventType": "system.api_token.create", "outcome": map[string]any{"result": "SUCCESS"}, "actor": map[string]any{"alternateId": "svc@acme"}},
			})
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	o := NewOkta("okta-1", srv.URL, "tok")
	evs, next, err := o.Poll(context.Background(), time.Unix(0, 0))
	if err != nil || len(evs) != 2 {
		t.Fatalf("poll: %v %d", err, len(evs))
	}
	if evs[0]["status_id"] != 2 || evs[0]["ivar"].(map[string]any)["target_entity"] != "user:ceo@acme" {
		t.Fatal("failed login must target the account, not act as it")
	}
	if evs[1]["activity_name"] != "app.secret_create" || !next.After(time.Unix(0, 0)) {
		t.Fatal("secret creation or cursor")
	}
	if res, _ := o.Execute(context.Background(), "session.revoke", "ceo@acme"); res != "done" || calls[len(calls)-1] != "DELETE /api/v1/users/ceo@acme/sessions" {
		t.Fatalf("revoke: %v", calls)
	}
}

func TestEntraAndGitHubMapping(t *testing.T) {
	g := &Entra{SensorID: "entra-1"}
	a := g.MapAudit(map[string]any{"activityDisplayName": "Add app role assignment to service principal", "initiatedBy": map[string]any{"app": map[string]any{"servicePrincipalId": "sp-backup"}}, "targetResources": []any{map[string]any{"id": "sp-backup"}}, "result": "success"})
	if a["activity_name"] != "iam.grant" {
		t.Fatal(a["activity_name"])
	}
	gh := &GitHub{SensorID: "gh-1"}
	z := gh.Map(map[string]any{"@timestamp": 1.7e12, "action": "repo.download_zip", "actor": "bob", "repo": "acme/core"})
	if z["ivar"].(map[string]any)["business_action"] != "bulk_export" {
		t.Fatal("bulk export")
	}
}

func TestEntraExecutesGraphCalls(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.Path+" "+string(b))
		w.WriteHeader(204)
	}))
	defer srv.Close()
	g := &Entra{SensorID: "e", API: api{base: srv.URL, auth: "Bearer x"}}
	g.Execute(context.Background(), "session.revoke", "alice@contoso")
	g.Execute(context.Background(), "user.suspend", "alice@contoso")
	if got[0] != "POST /users/alice@contoso/revokeSignInSessions " || !strings.Contains(got[1], `"accountEnabled":false`) {
		t.Fatal(got)
	}
}

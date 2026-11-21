package coreclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ivar/ivar/go/internal/ocsf"
)

func TestBuffersWhileCoreIsDown(t *testing.T) {
	up := false
	var got int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up {
			w.WriteHeader(503)
			return
		}
		var b struct {
			Events []map[string]any `json:"events"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		got += len(b.Events)
		_ = json.NewEncoder(w).Encode(map[string]any{"verdicts": []any{map[string]any{"decision": "contain"}}})
	}))
	defer srv.Close()
	c := New(srv.URL, "okta-1", "identity")
	var verdicts int
	c.OnVerdicts = func(v []map[string]any) { verdicts += len(v) }
	c.Emit(ocsf.New("okta-1", "identity", ocsf.ClassAuthentication, "auth.login", time.Now()))
	if err := c.Flush(context.Background()); err == nil {
		t.Fatal("expected failure while the core is down")
	}
	if n, _ := c.Pending(); n != 1 {
		t.Fatalf("event lost: %d", n)
	}
	up = true
	if err := c.Flush(context.Background()); err != nil || got != 1 || verdicts != 1 {
		t.Fatalf("flush: %v got=%d verdicts=%d", err, got, verdicts)
	}
}

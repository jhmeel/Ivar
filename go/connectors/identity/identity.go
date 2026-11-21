// Package identity holds the identity and SaaS connectors (sections 8 and
// 8.3): Okta, Entra ID and Microsoft 365, Google Workspace, Salesforce and
// GitHub. Each source polls the provider's audit API from a cursor and maps
// logins, risky sign ins, role grants, OAuth grants, app secrets and bulk
// exports to OCSF; each responder revokes through the provider's API.
package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ivar/ivar/go/internal/coreclient"
	"github.com/ivar/ivar/go/internal/ocsf"
)

// Source is one provider's audit feed.
type Source interface {
	Name() string
	Poll(ctx context.Context, since time.Time) ([]ocsf.Event, time.Time, error)
}

// Run polls a source and forwards events until ctx ends.
func Run(ctx context.Context, s Source, core *coreclient.Client, every time.Duration, since time.Time) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		evs, next, err := s.Poll(ctx, since)
		if err == nil {
			for _, e := range evs {
				core.Emit(e)
			}
			since = next
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type api struct {
	base  string
	auth  string
	http  *http.Client
	extra map[string]string
}

func (a api) get(ctx context.Context, path string, out any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(a.base, "/")+path, nil)
	req.Header.Set("Authorization", a.auth)
	req.Header.Set("Accept", "application/json")
	for k, v := range a.extra {
		req.Header.Set(k, v)
	}
	resp, err := a.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %d: %s", path, resp.StatusCode, b)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (a api) send(ctx context.Context, method, path string, body any) error {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = strings.NewReader(string(b))
	}
	req, _ := http.NewRequestWithContext(ctx, method, strings.TrimRight(a.base, "/")+path, r)
	req.Header.Set("Authorization", a.auth)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %s %d: %s", method, path, resp.StatusCode, b)
	}
	return nil
}

func (a api) client() *http.Client {
	if a.http != nil {
		return a.http
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func s(m map[string]any, path ...string) string {
	var cur any = m
	for _, p := range path {
		switch c := cur.(type) {
		case map[string]any:
			cur = c[p]
		case []any:
			if len(c) == 0 {
				return ""
			}
			cur = c[0].(map[string]any)[p]
		default:
			return ""
		}
	}
	switch v := cur.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprint(int64(v))
	case bool:
		return fmt.Sprint(v)
	}
	return ""
}

// Responder executes one action against a provider.
type Responder interface {
	Execute(ctx context.Context, action, subject string) (result, verification string)
}

package ivar

import (
	"io"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestBodyKeysAreReadAndTheBodyIsKept(t *testing.T) {
	r := httptest.NewRequest("PATCH", "/users/7", strings.NewReader(`{"name":"Ada","role":"admin"}`))
	r.Header.Set("Content-Type", "application/json")
	r = withBodyKeys(r)
	if got := bodyKeys(r); !reflect.DeepEqual(got, []string{"name", "role"}) {
		t.Fatalf("keys %v", got)
	}
	rest, _ := io.ReadAll(r.Body)
	if string(rest) != `{"name":"Ada","role":"admin"}` {
		t.Fatalf("the handler must still read the whole body, got %q", rest)
	}
	plain := withBodyKeys(httptest.NewRequest("POST", "/upload", strings.NewReader("not json")))
	if len(bodyKeys(plain)) != 0 {
		t.Fatal("non JSON bodies are not parsed")
	}
}

func TestClientIPTrustsOnlyConfiguredProxies(t *testing.T) {
	trustedProxies, _ := parseTrusted([]string{"127.0.0.1", "10.0.0.0/8"})
	m := &Middleware{trusted: trustedProxies}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.7, 10.1.2.3")
	if got := m.clientIP(r); got != "203.0.113.7" {
		t.Fatalf("nearest untrusted hop, got %s", got)
	}
	direct := httptest.NewRequest("GET", "/", nil)
	direct.RemoteAddr = "198.51.100.9:4000"
	direct.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := m.clientIP(direct); got != "198.51.100.9" {
		t.Fatalf("a client cannot pick its own address with X-Forwarded-For, got %s", got)
	}
	if got := (&Middleware{}).clientIP(r); got != "127.0.0.1" {
		t.Fatalf("with no trusted proxies the peer is the client, got %s", got)
	}
}

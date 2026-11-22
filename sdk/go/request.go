package ivar

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
)

// maxBodyBytes is the most of a JSON body read to learn its field names.
const maxBodyBytes = 64 << 10

type bodyKeysKey struct{}

// withBodyKeys reads the top level field names of a JSON request body, puts
// the body back for the handler, and keeps the names on the request so the
// event reported after the response carries them too. Values are never
// kept: only names leave the application (section 16).
func withBodyKeys(r *http.Request) *http.Request {
	if r.Body == nil || r.Body == http.NoBody || !strings.Contains(r.Header.Get("Content-Type"), "json") || r.ContentLength > maxBodyBytes {
		return r
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(raw), r.Body))
	if err != nil || len(raw) > maxBodyBytes {
		return r
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return r
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 64 {
		keys = keys[:64]
	}
	return r.WithContext(context.WithValue(r.Context(), bodyKeysKey{}, keys))
}

func bodyKeys(r *http.Request) []string {
	keys, _ := r.Context().Value(bodyKeysKey{}).([]string)
	if keys == nil {
		return []string{}
	}
	return keys
}

// parseTrusted turns TrustedProxies entries (addresses or CIDR prefixes)
// into prefixes.
func parseTrusted(entries []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, e := range entries {
		if strings.Contains(e, "/") {
			p, err := netip.ParsePrefix(e)
			if err != nil {
				return nil, err
			}
			out = append(out, p)
			continue
		}
		a, err := netip.ParseAddr(e)
		if err != nil {
			return nil, err
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func trusted(prefixes []netip.Prefix, ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// clientIP is the address of the client: the connection's peer, or, when
// the peer is a trusted proxy, the nearest X-Forwarded-For hop that is not
// itself a trusted proxy. Hops the client wrote itself are never believed.
func (m *Middleware) clientIP(r *http.Request) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	if !trusted(m.trusted, peer) {
		return peer
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if hop != "" && !trusted(m.trusted, hop) {
			return hop
		}
	}
	return peer
}

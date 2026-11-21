package controlplane

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Server is the control plane HTTP API.
type Server struct {
	Rollout  *Rollout
	TUF      *TUFRepo
	Flags    *FlagStore
	Registry *Registry
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("GET /v1/policy/bundle", func(w http.ResponseWriter, r *http.Request) {
		have, _ := strconv.ParseUint(r.URL.Query().Get("have"), 10, 64)
		rel := s.Rollout.For(r.URL.Query().Get("sensor"))
		if rel == nil || rel.Version <= have {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("X-Ivar-Stage", string(rel.Stage))
		_, _ = w.Write([]byte(rel.Archive64))
	})
	mux.HandleFunc("GET /tuf/{file}", func(w http.ResponseWriter, r *http.Request) {
		role := strings.TrimSuffix(r.PathValue("file"), ".json")
		b, err := s.TUF.Metadata(role)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /tuf/targets/{name...}", func(w http.ResponseWriter, r *http.Request) {
		if b, ok := s.TUF.Target(r.PathValue("name")); ok {
			_, _ = w.Write(b)
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("GET /v1/flags", func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(s.Flags.All()) })
	mux.HandleFunc("POST /v1/flags", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Ivar-Hardware-2fa") != "true" {
			http.Error(w, "hardware backed staff 2FA required", http.StatusUnauthorized)
			return
		}
		var req struct {
			Name      string             `json:"name"`
			Value     string             `json:"value"`
			Approvals []OperatorApproval `json:"approvals"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		f, err := s.Flags.Set(req.Name, req.Value, req.Approvals, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(f)
	})
	mux.HandleFunc("POST /v1/plugins", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Manifest  string `json:"manifest"`
			Artifact  string `json:"artifact_base64"`
			Signature string `json:"signature"`
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<20))
		if json.Unmarshal(body, &req) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		art, err := base64.StdEncoding.DecodeString(req.Artifact)
		if err != nil {
			http.Error(w, "bad artifact", http.StatusBadRequest)
			return
		}
		e, err := s.Registry.Submit([]byte(req.Manifest), art, req.Signature)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(e)
	})
	mux.HandleFunc("GET /v1/plugins", func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(s.Registry.List()) })
	return mux
}

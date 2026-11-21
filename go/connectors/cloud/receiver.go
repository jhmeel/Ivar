package cloud

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/jhmeel/ivar/go/internal/coreclient"
)

// Receiver accepts the three providers' event streams.
type Receiver struct {
	Core     *coreclient.Client
	SensorID string
	// Token is the shared secret each stream sends (EventBridge connection
	// API key, Event Grid delivery header, Pub/Sub push audience token).
	Token string
}

func (r *Receiver) authorized(req *http.Request) bool {
	got := req.Header.Get("X-Ivar-Token")
	if got == "" {
		got = req.URL.Query().Get("token")
	}
	return r.Token != "" && subtle.ConstantTimeCompare([]byte(got), []byte(r.Token)) == 1
}

// Handler routes /aws, /azure and /gcp.
func (r *Receiver) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /aws", func(w http.ResponseWriter, req *http.Request) {
		if !r.authorized(req) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var e map[string]any
		if json.NewDecoder(req.Body).Decode(&e) != nil {
			http.Error(w, "bad event", http.StatusBadRequest)
			return
		}
		r.Core.Emit(FromCloudTrail(r.SensorID, e))
		w.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc("POST /azure", func(w http.ResponseWriter, req *http.Request) {
		var events []map[string]any
		if json.NewDecoder(req.Body).Decode(&events) != nil {
			http.Error(w, "bad events", http.StatusBadRequest)
			return
		}
		// Event Grid subscription validation handshake.
		for _, e := range events {
			if str(e, "eventType") == "Microsoft.EventGrid.SubscriptionValidationEvent" {
				code := str(e, "data", "validationCode")
				_ = json.NewEncoder(w).Encode(map[string]string{"validationResponse": code})
				return
			}
		}
		if !r.authorized(req) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		for _, e := range events {
			r.Core.Emit(FromAzureActivity(r.SensorID, e))
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /gcp", func(w http.ResponseWriter, req *http.Request) {
		if !r.authorized(req) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var push struct {
			Message struct {
				Data string `json:"data"`
			} `json:"message"`
		}
		if json.NewDecoder(req.Body).Decode(&push) != nil {
			http.Error(w, "bad push", http.StatusBadRequest)
			return
		}
		raw, err := base64.StdEncoding.DecodeString(push.Message.Data)
		var entry map[string]any
		if err != nil || json.Unmarshal(raw, &entry) != nil {
			http.Error(w, "bad log entry", http.StatusBadRequest)
			return
		}
		r.Core.Emit(FromGCPAudit(r.SensorID, entry))
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

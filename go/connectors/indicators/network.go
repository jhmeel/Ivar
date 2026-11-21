// Package indicators is the shared indicator network (section 17).
//
// Participants exchange keyed hashes of attacker infrastructure, device
// fingerprints and token abuse patterns. Keyed hashes are pseudonymised
// rather than anonymous, so the network treats them as personal data under
// the Nigeria Data Protection Act 2023: every participant must record a
// lawful basis (legitimate interest backed by the Legitimate Interest
// Assessment the NDPC General Application and Implementation Directive
// requires), sign the data sharing agreement, and a participant outside
// Nigeria must also have a cross border transfer basis. Poisoning by a
// malicious participant is reduced by weighting each indicator by how many
// independent participants report it.
package indicators

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Participant is one member of the network.
type Participant struct {
	ID                   string `json:"id"`
	PublicKeyHex         string `json:"public_key"`
	LawfulBasis          string `json:"lawful_basis"`
	LIAReference         string `json:"lia_reference"`
	DataSharingAgreement bool   `json:"data_sharing_agreement"`
	Country              string `json:"country"`
	CrossBorderBasis     string `json:"cross_border_basis"`
	// Organisation group: participants in one group are not independent.
	Group string `json:"group"`
}

// Admit checks the legal preconditions for sharing.
func (p Participant) Admit() error {
	switch {
	case p.LawfulBasis != "legitimate_interest" && p.LawfulBasis != "legal_obligation" && p.LawfulBasis != "consent":
		return errors.New("a lawful basis under the NDPA is required")
	case p.LawfulBasis == "legitimate_interest" && p.LIAReference == "":
		return errors.New("legitimate interest needs a Legitimate Interest Assessment reference (NDPC GAID 2025)")
	case !p.DataSharingAgreement:
		return errors.New("the data sharing agreement must be signed")
	case p.Country != "NG" && p.CrossBorderBasis == "":
		return errors.New("participants outside Nigeria need a cross border transfer basis under the GAID")
	}
	return nil
}

// Indicator as submitted: the value is already a keyed hash.
type Indicator struct {
	Type       string  `json:"type"` // ip, device, token_pattern
	Hash       string  `json:"hash"`
	Confidence float64 `json:"confidence"`
	SeenAt     int64   `json:"seen_at"`
}

// Hash computes the keyed hash all participants share for a raw value.
func Hash(networkKeyHex, kind, value string) string {
	k, _ := hex.DecodeString(networkKeyHex)
	m := hmac.New(sha256.New, k)
	m.Write([]byte(kind + ":" + value))
	return "ni_" + hex.EncodeToString(m.Sum(nil))[:32]
}

type report struct {
	group      string
	confidence float64
	at         time.Time
}

// Network stores reports and publishes weighted indicators.
type Network struct {
	mu           sync.Mutex
	participants map[string]Participant
	reports      map[string]map[string]report // hash to participant to report
	kinds        map[string]string
	// MinIndependent participants before an indicator is published.
	MinIndependent int
	// MaxPerParticipant caps one participant's contribution.
	MaxPerParticipant float64
	TTL               time.Duration
}

func New() *Network {
	return &Network{participants: map[string]Participant{}, reports: map[string]map[string]report{}, kinds: map[string]string{}, MinIndependent: 2, MaxPerParticipant: 0.5, TTL: 30 * 24 * time.Hour}
}

func (n *Network) Join(p Participant) error {
	if err := p.Admit(); err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.participants[p.ID] = p
	return nil
}

// Submit verifies the participant's signature over the batch and records it.
func (n *Network) Submit(participant string, batch []byte, sigB64 string, now time.Time) (int, error) {
	n.mu.Lock()
	p, ok := n.participants[participant]
	n.mu.Unlock()
	if !ok {
		return 0, errors.New("unknown participant")
	}
	pk, _ := hex.DecodeString(p.PublicKeyHex)
	sig, _ := base64.StdEncoding.DecodeString(sigB64)
	if len(pk) != ed25519.PublicKeySize || !ed25519.Verify(pk, batch, sig) {
		return 0, errors.New("signature invalid")
	}
	var inds []Indicator
	if err := json.Unmarshal(batch, &inds); err != nil {
		return 0, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, i := range inds {
		if len(i.Hash) < 8 || i.Hash[:3] != "ni_" {
			continue // raw values are never accepted
		}
		if n.reports[i.Hash] == nil {
			n.reports[i.Hash] = map[string]report{}
		}
		group := p.Group
		if group == "" {
			group = p.ID
		}
		n.reports[i.Hash][participant] = report{group: group, confidence: math.Min(math.Max(i.Confidence, 0), 1), at: now}
		n.kinds[i.Hash] = i.Type
	}
	return len(inds), nil
}

// Published is one indicator in the feed.
type Published struct {
	Type        string  `json:"type"`
	Hash        string  `json:"hash"`
	Score       float64 `json:"score"`
	Independent int     `json:"independent_participants"`
}

// Feed returns indicators reported by enough independent participants,
// scored as 1 minus the product of (1 minus capped confidence) over groups.
func (n *Network) Feed(now time.Time) []Published {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []Published
	for h, rs := range n.reports {
		best := map[string]float64{}
		for _, r := range rs {
			if now.Sub(r.at) > n.TTL {
				continue
			}
			c := math.Min(r.confidence, n.MaxPerParticipant)
			if c > best[r.group] {
				best[r.group] = c
			}
		}
		if len(best) < n.MinIndependent {
			continue
		}
		prod := 1.0
		for _, c := range best {
			prod *= 1 - c
		}
		out = append(out, Published{Type: n.kinds[h], Hash: h, Score: math.Round((1-prod)*1000) / 1000, Independent: len(best)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hash < out[j].Hash })
	return out
}

// Handler: POST /v1/submit (X-Participant, X-Signature), GET /v1/feed.
func (n *Network) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/submit", func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 0, 1<<16)
		buf := make([]byte, 4096)
		for {
			k, err := r.Body.Read(buf)
			body = append(body, buf[:k]...)
			if err != nil || len(body) > 8<<20 {
				break
			}
		}
		c, err := n.Submit(r.Header.Get("X-Participant"), body, r.Header.Get("X-Signature"), time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]int{"accepted": c})
	})
	mux.HandleFunc("GET /v1/feed", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := n.participants[r.Header.Get("X-Participant")]; !ok {
			http.Error(w, "participants only", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(n.Feed(time.Now()))
	})
	return mux
}

package indicators

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

type member struct {
	p    Participant
	priv ed25519.PrivateKey
}

func newMember(id, group string) member {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return member{Participant{ID: id, PublicKeyHex: hex.EncodeToString(pub), LawfulBasis: "legitimate_interest", LIAReference: "LIA-2026-" + id, DataSharingAgreement: true, Country: "NG", Group: group}, priv}
}

func (m member) submit(t *testing.T, n *Network, inds []Indicator) error {
	b, _ := json.Marshal(inds)
	_, err := n.Submit(m.p.ID, b, base64.StdEncoding.EncodeToString(ed25519.Sign(m.priv, b)), time.Now())
	return err
}

func TestLegalPreconditions(t *testing.T) {
	n := New()
	m := newMember("a", "")
	m.p.LIAReference = ""
	if n.Join(m.p) == nil {
		t.Fatal("legitimate interest without an LIA admitted")
	}
	m = newMember("b", "")
	m.p.Country = "GH"
	if n.Join(m.p) == nil {
		t.Fatal("cross border participant without a transfer basis admitted")
	}
}

func TestWeightingResistsPoisoning(t *testing.T) {
	n := New()
	a, b, c := newMember("bank-a", ""), newMember("bank-b", ""), newMember("bank-c-subsidiary", "bank-b")
	for _, m := range []member{a, b, c} {
		if err := n.Join(m.p); err != nil {
			t.Fatal(err)
		}
	}
	key := "00112233"
	h := Hash(key, "ip", "203.0.113.9")
	if a.submit(t, n, []Indicator{{Type: "ip", Hash: h, Confidence: 0.99}}) != nil {
		t.Fatal("submit")
	}
	if len(n.Feed(time.Now())) != 0 {
		t.Fatal("one participant alone must not publish")
	}
	_ = c.submit(t, n, []Indicator{{Type: "ip", Hash: h, Confidence: 0.9}})
	_ = b.submit(t, n, []Indicator{{Type: "ip", Hash: h, Confidence: 0.9}})
	f := n.Feed(time.Now())
	if len(f) != 1 || f[0].Independent != 2 || f[0].Score != 0.75 {
		t.Fatalf("feed: %+v", f)
	}
	if a.submit(t, n, []Indicator{{Type: "ip", Hash: "203.0.113.9", Confidence: 1}}); len(n.Feed(time.Now())) != 1 {
		t.Fatal("raw values must be refused")
	}
	b2, _ := json.Marshal([]Indicator{{Type: "ip", Hash: h}})
	if _, err := n.Submit("bank-a", b2, base64.StdEncoding.EncodeToString(ed25519.Sign(b.priv, b2)), time.Now()); err == nil {
		t.Fatal("forged submission accepted")
	}
}

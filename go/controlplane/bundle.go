// Package controlplane distributes signed policy and rules, security
// profiles and runtime flags, and the plugin registry (section 7). Updates
// go out through The Update Framework (section 16), which blocks rollback to
// an older signed policy, freeze attacks that withhold updates, and misuse of
// any single compromised signing key. A policy change that weakens
// protection needs signatures from at least two named policy keys.
package controlplane

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// PolicyKey is a named policy signing key.
type PolicyKey struct {
	ID   string
	Priv ed25519.PrivateKey
}

// BundleSignature matches ivar_contracts::BundleSignature.
type BundleSignature struct {
	Alg   string `json:"alg"`
	KeyID string `json:"key_id"`
	Sig   string `json:"sig"`
}

// Bundle is a signed policy archive: policy.json and signatures.json.
type Bundle struct {
	Content    []byte
	Signatures []BundleSignature
}

// Archive writes the tar archive the sensors and the core read.
func (b Bundle) Archive() ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	sigs, _ := json.MarshalIndent(b.Signatures, "", "  ")
	for _, f := range []struct {
		name string
		data []byte
	}{{"policy.json", b.Content}, {"signatures.json", sigs}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.data)), ModTime: time.Unix(0, 0), Format: tar.FormatGNU}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ArchiveBase64 is the form served to sensors.
func (b Bundle) ArchiveBase64() (string, error) {
	a, err := b.Archive()
	return base64.StdEncoding.EncodeToString(a), err
}

// ReadArchive parses an archive.
func ReadArchive(data []byte) (Bundle, error) {
	var b Bundle
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return b, err
		}
		body, _ := io.ReadAll(tr)
		switch h.Name {
		case "policy.json":
			b.Content = body
		case "signatures.json":
			_ = json.Unmarshal(body, &b.Signatures)
		}
	}
	if b.Content == nil {
		return b, errors.New("archive has no policy.json")
	}
	return b, nil
}

// Sign signs policy content. A weakening change needs two distinct keys.
func Sign(content []byte, keys []PolicyKey) (Bundle, error) {
	var p struct {
		Weakens bool `json:"weakens_protection"`
	}
	if err := json.Unmarshal(content, &p); err != nil {
		return Bundle{}, err
	}
	ids := map[string]bool{}
	b := Bundle{Content: content}
	for _, k := range keys {
		ids[k.ID] = true
		b.Signatures = append(b.Signatures, BundleSignature{Alg: "ed25519", KeyID: k.ID, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(k.Priv, content))})
	}
	if len(ids) == 0 {
		return Bundle{}, errors.New("at least one policy key is required")
	}
	if p.Weakens && len(ids) < 2 {
		return Bundle{}, errors.New("this change weakens protection and needs signatures from at least two named policy keys")
	}
	return b, nil
}

// Verify checks every signature against trusted keys and the two key rule.
func Verify(b Bundle, trusted map[string]ed25519.PublicKey) error {
	ids := map[string]bool{}
	for _, s := range b.Signatures {
		pk, ok := trusted[s.KeyID]
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if !ok || err != nil || s.Alg != "ed25519" || !ed25519.Verify(pk, b.Content, sig) {
			return fmt.Errorf("signature by %s does not verify", s.KeyID)
		}
		ids[s.KeyID] = true
	}
	var p struct {
		Weakens bool `json:"weakens_protection"`
	}
	_ = json.Unmarshal(b.Content, &p)
	if len(ids) == 0 || (p.Weakens && len(ids) < 2) {
		return errors.New("not enough policy signatures")
	}
	return nil
}

package controlplane

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"

	"gopkg.in/yaml.v3"
)

// PluginEntry is one submitted plugin.
type PluginEntry struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Type     string `json:"type"`
	Manifest string `json:"manifest"`
	Digest   string `json:"artifact_sha256"`
	Stage    Stage  `json:"stage"`
}

// Registry verifies plugin signatures (Sigstore cosign, key mode) before
// listing a plugin; the plugin host verifies again when it loads one.
type Registry struct {
	mu      sync.Mutex
	keys    []*ecdsa.PublicKey
	entries map[string]PluginEntry
	blobs   map[string][]byte
}

func NewRegistry(cosignPEMs []string) (*Registry, error) {
	r := &Registry{entries: map[string]PluginEntry{}, blobs: map[string][]byte{}}
	for _, p := range cosignPEMs {
		b, _ := pem.Decode([]byte(p))
		if b == nil {
			return nil, errors.New("bad cosign public key")
		}
		k, err := x509.ParsePKIXPublicKey(b.Bytes)
		if err != nil {
			return nil, err
		}
		ek, ok := k.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("cosign key must be ECDSA P-256")
		}
		r.keys = append(r.keys, ek)
	}
	return r, nil
}

// SigningPayload matches ivar_plugin_host::signature::signing_payload.
func SigningPayload(manifest, artifact []byte) []byte {
	m := sha256.Sum256(manifest)
	a := sha256.Sum256(artifact)
	return []byte(fmt.Sprintf("ivar.plugin.v1\nmanifest sha256:%s\nartifact sha256:%s\n", hex.EncodeToString(m[:]), hex.EncodeToString(a[:])))
}

func (r *Registry) Submit(manifest, artifact []byte, sigB64 string) (PluginEntry, error) {
	var m struct {
		Name      string `yaml:"name"`
		Version   string `yaml:"version"`
		Type      string `yaml:"type"`
		API       string `yaml:"api"`
		Signature string `yaml:"signature"`
	}
	if err := yaml.Unmarshal(manifest, &m); err != nil {
		return PluginEntry{}, err
	}
	if m.Signature != "sigstore" || m.API != "ivar.plugin/v1" {
		return PluginEntry{}, errors.New("manifest must use signature: sigstore and api: ivar.plugin/v1")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return PluginEntry{}, err
	}
	digest := sha256.Sum256(SigningPayload(manifest, artifact))
	valid := false
	for _, k := range r.keys {
		if ecdsa.VerifyASN1(k, digest[:], sig) {
			valid = true
		}
	}
	if !valid {
		return PluginEntry{}, errors.New("no trusted cosign key verifies this plugin")
	}
	a := sha256.Sum256(artifact)
	e := PluginEntry{Name: m.Name, Version: m.Version, Type: m.Type, Manifest: string(manifest), Digest: hex.EncodeToString(a[:]), Stage: Shadow}
	r.mu.Lock()
	r.entries[m.Name+"@"+m.Version] = e
	r.blobs[e.Digest] = artifact
	r.mu.Unlock()
	return e, nil
}

func (r *Registry) List() []PluginEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]PluginEntry, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e)
	}
	return out
}

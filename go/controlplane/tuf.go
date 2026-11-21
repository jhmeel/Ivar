package controlplane

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/repository"
)

// TUFRepo publishes policy bundles and rule packs as TUF targets. Root and
// targets each need two signatures, so one compromised key cannot publish;
// snapshot and timestamp pin versions and expire quickly, which defeats
// rollback and freeze attacks.
type roleSet interface {
	Root() *metadata.Metadata[metadata.RootType]
	SetRoot(*metadata.Metadata[metadata.RootType])
	Snapshot() *metadata.Metadata[metadata.SnapshotType]
	SetSnapshot(*metadata.Metadata[metadata.SnapshotType])
	Timestamp() *metadata.Metadata[metadata.TimestampType]
	SetTimestamp(*metadata.Metadata[metadata.TimestampType])
	Targets(string) *metadata.Metadata[metadata.TargetsType]
	SetTargets(string, *metadata.Metadata[metadata.TargetsType])
}

var _ roleSet = repository.New()

type TUFRepo struct {
	mu       sync.Mutex
	roles    roleSet
	keys     map[string][]ed25519.PrivateKey
	files    map[string][]byte
	TTL      map[string]time.Duration
	consumed map[string]int64
}

// RoleKeys: root and targets need at least two keys each.
func NewTUFRepo(keys map[string][]ed25519.PrivateKey, now time.Time) (*TUFRepo, error) {
	if len(keys["root"]) < 2 || len(keys["targets"]) < 2 || len(keys["snapshot"]) < 1 || len(keys["timestamp"]) < 1 {
		return nil, fmt.Errorf("root and targets need two keys each; snapshot and timestamp one")
	}
	r := &TUFRepo{roles: repository.New(), keys: keys, files: map[string][]byte{}, consumed: map[string]int64{},
		TTL: map[string]time.Duration{"root": 365 * 24 * time.Hour, "targets": 30 * 24 * time.Hour, "snapshot": 7 * 24 * time.Hour, "timestamp": 24 * time.Hour}}
	root := metadata.Root(now.Add(r.TTL["root"]))
	r.roles.SetRoot(root)
	for role, ks := range keys {
		for _, k := range ks {
			pub, err := metadata.KeyFromPublicKey(k.Public())
			if err != nil {
				return nil, err
			}
			if err := root.Signed.AddKey(pub, role); err != nil {
				return nil, err
			}
		}
	}
	root.Signed.Roles["root"].Threshold = 2
	root.Signed.Roles["targets"].Threshold = 2
	r.roles.SetTargets("targets", metadata.Targets(now.Add(r.TTL["targets"])))
	r.roles.SetSnapshot(metadata.Snapshot(now.Add(r.TTL["snapshot"])))
	r.roles.SetTimestamp(metadata.Timestamp(now.Add(r.TTL["timestamp"])))
	if err := r.signAll(); err != nil {
		return nil, err
	}
	return r, nil
}

func sign[T metadata.Roles](m *metadata.Metadata[T], keys []ed25519.PrivateKey) error {
	m.ClearSignatures()
	for _, k := range keys {
		s, err := signature.LoadSigner(k, crypto.Hash(0))
		if err != nil {
			return err
		}
		if _, err := m.Sign(s); err != nil {
			return err
		}
	}
	return nil
}

func (r *TUFRepo) signAll() error {
	if err := sign(r.roles.Root(), r.keys["root"]); err != nil {
		return err
	}
	return r.signTop()
}

func (r *TUFRepo) signTop() error {
	t := r.roles.Targets("targets")
	if err := sign(t, r.keys["targets"]); err != nil {
		return err
	}
	snap := r.roles.Snapshot()
	snap.Signed.Meta["targets.json"] = metadata.MetaFile(t.Signed.Version)
	if err := sign(snap, r.keys["snapshot"]); err != nil {
		return err
	}
	ts := r.roles.Timestamp()
	ts.Signed.Meta["snapshot.json"] = metadata.MetaFile(snap.Signed.Version)
	return sign(ts, r.keys["timestamp"])
}

// Publish adds or replaces a target and bumps targets, snapshot and timestamp.
func (r *TUFRepo) Publish(name string, data []byte, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	tf, err := metadata.TargetFile().FromBytes(name, data, "sha256")
	if err != nil {
		return err
	}
	t := r.roles.Targets("targets")
	t.Signed.Targets[name] = tf
	t.Signed.Version++
	t.Signed.Expires = now.Add(r.TTL["targets"])
	r.roles.Snapshot().Signed.Version++
	r.roles.Snapshot().Signed.Expires = now.Add(r.TTL["snapshot"])
	r.roles.Timestamp().Signed.Version++
	r.roles.Timestamp().Signed.Expires = now.Add(r.TTL["timestamp"])
	r.files[name] = data
	return r.signTop()
}

// Refresh re signs the timestamp so clients can tell the repository is live
// (a frozen repository lets the timestamp expire).
func (r *TUFRepo) Refresh(now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	ts := r.roles.Timestamp()
	ts.Signed.Version++
	ts.Signed.Expires = now.Add(r.TTL["timestamp"])
	return sign(ts, r.keys["timestamp"])
}

// Metadata returns role metadata as JSON.
func (r *TUFRepo) Metadata(role string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch role {
	case "root":
		return r.roles.Root().ToBytes(true)
	case "targets":
		return r.roles.Targets("targets").ToBytes(true)
	case "snapshot":
		return r.roles.Snapshot().ToBytes(true)
	case "timestamp":
		return r.roles.Timestamp().ToBytes(true)
	}
	return nil, fmt.Errorf("unknown role %s", role)
}

// Target returns a published file.
func (r *TUFRepo) Target(name string) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.files[name]
	return b, ok
}

package controlplane

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
)

// Stage of a bundle or rule pack: signed content can still be faulty content
// (CrowdStrike, July 2024), so policy goes through shadow and canary like plugins.
type Stage string

const (
	Shadow Stage = "shadow"
	Canary Stage = "canary"
	Active Stage = "active"
)

// Release is one bundle version moving through the stages.
type Release struct {
	Version   uint64
	Archive64 string
	Stage     Stage
	CanaryPct uint32
}

// Rollout chooses the bundle each sensor receives.
type Rollout struct {
	mu        sync.Mutex
	active    *Release
	candidate *Release
}

// Propose starts a new version in shadow: sensors keep the active bundle.
func (r *Rollout) Propose(rel Release) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rel.Stage = Shadow
	if r.active == nil {
		rel.Stage = Active
		r.active = &rel
		return
	}
	r.candidate = &rel
}

// Promote moves the candidate on. The replay library must pass before canary,
// and the canary must show no legitimate workflow blocked before activation.
func (r *Rollout) Promote(replayLibraryPassed, canaryClean bool, canaryPct uint32) (Stage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.candidate
	if c == nil {
		return "", errors.New("no candidate")
	}
	switch c.Stage {
	case Shadow:
		if !replayLibraryPassed {
			return c.Stage, errors.New("attack replay library must pass before canary")
		}
		c.Stage, c.CanaryPct = Canary, canaryPct
	case Canary:
		if !canaryClean {
			return c.Stage, errors.New("canary blocked legitimate traffic")
		}
		c.Stage = Active
		r.active, r.candidate = c, nil
	}
	return c.Stage, nil
}

// Rollback drops the candidate; sensors on canary return to the active bundle.
func (r *Rollout) Rollback() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.candidate = nil
}

func bucket(sensorID string) uint32 {
	h := sha256.Sum256([]byte(sensorID))
	return binary.BigEndian.Uint32(h[:4]) % 100
}

// For returns the release a sensor should run.
func (r *Rollout) For(sensorID string) *Release {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.candidate != nil && r.candidate.Stage == Canary && bucket(sensorID) < r.candidate.CanaryPct {
		return r.candidate
	}
	return r.active
}

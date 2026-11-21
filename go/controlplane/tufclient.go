package controlplane

import (
	"fmt"

	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

// VerifyTarget runs the TUF client workflow over fetched metadata: a trusted
// root, then timestamp, snapshot and targets, checking signatures,
// thresholds, versions (no rollback) and expiry (no freeze), then the
// target's length and hash.
func VerifyTarget(trustedRoot, timestamp, snapshot, targets []byte, name string, data []byte) error {
	tm, err := trustedmetadata.New(trustedRoot)
	if err != nil {
		return fmt.Errorf("root: %w", err)
	}
	if _, err := tm.UpdateTimestamp(timestamp); err != nil {
		return fmt.Errorf("timestamp: %w", err)
	}
	if _, err := tm.UpdateSnapshot(snapshot, false); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	t, err := tm.UpdateTargets(targets)
	if err != nil {
		return fmt.Errorf("targets: %w", err)
	}
	tf, ok := t.Signed.Targets[name]
	if !ok {
		return fmt.Errorf("target %s is not published", name)
	}
	return tf.VerifyLengthHashes(data)
}

// ClientState keeps the last trusted versions so a later fetch of older
// metadata is refused even across restarts.
type ClientState struct {
	Root, Timestamp, Snapshot, Targets []byte
}

// Update verifies new metadata against the state and keeps it on success.
func (c *ClientState) Update(timestamp, snapshot, targets []byte) error {
	tm, err := trustedmetadata.New(c.Root)
	if err != nil {
		return err
	}
	if c.Timestamp != nil {
		if _, err := tm.UpdateTimestamp(c.Timestamp); err != nil {
			return err
		}
	}
	if _, err := tm.UpdateTimestamp(timestamp); err != nil {
		return fmt.Errorf("timestamp: %w", err)
	}
	if _, err := tm.UpdateSnapshot(snapshot, false); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	if _, err := tm.UpdateTargets(targets); err != nil {
		return fmt.Errorf("targets: %w", err)
	}
	c.Timestamp, c.Snapshot, c.Targets = timestamp, snapshot, targets
	return nil
}

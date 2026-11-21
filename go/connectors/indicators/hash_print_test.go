package indicators

import "testing"

// The core computes the same hash (ivar_core::detect::signatures::indicator_hash).
func TestHashVector(t *testing.T) {
	if got := Hash("00112233", "ip", "203.0.113.9"); got != "ni_"+HashVector {
		t.Fatalf("got %s", got)
	}
}

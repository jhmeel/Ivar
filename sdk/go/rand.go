package ivar

import "crypto/rand"

// cryptoRand feeds the core's random source (used only to mint and attest
// intent tokens) from the operating system.
type cryptoRand struct{}

func (cryptoRand) Read(p []byte) (int, error) { return rand.Read(p) }

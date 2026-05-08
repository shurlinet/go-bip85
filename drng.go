package bip85

import (
	"strconv"

	"golang.org/x/crypto/sha3"
)

// DRNG is a deterministic random number generator seeded with BIP85 entropy.
// It implements io.Reader by wrapping SHAKE256 (FIPS 202).
//
// BIP85-DRNG-SHAKE256 seeds a SHAKE256 XOF with the 64-byte HMAC-SHA512
// output and produces an unlimited deterministic byte stream.
//
// DRNG is forward-only: once bytes are read, they cannot be re-read.
// Create a new DRNG from the same entropy to restart the sequence.
//
// A DRNG instance must not be shared between goroutines. Each goroutine
// must create its own instance.
type DRNG struct {
	xof sha3.ShakeHash
}

// NewDRNG creates a BIP85-DRNG-SHAKE256 from 64 bytes of BIP85 entropy.
// The entropy is consumed immediately; the caller may zero it afterward.
//
// Panics if entropy is not exactly 64 bytes (the caller has a bug).
func NewDRNG(entropy []byte) *DRNG {
	if len(entropy) != 64 {
		panic("bip85: DRNG requires exactly 64 bytes of entropy")
	}
	xof := sha3.NewShake256()
	n, err := xof.Write(entropy)
	if err != nil {
		panic("bip85: SHAKE256 write failed: " + err.Error())
	}
	if n != 64 {
		panic("bip85: SHAKE256 write accepted only " + strconv.Itoa(n) + " of 64 bytes")
	}
	return &DRNG{xof: xof}
}

// Read fills p with deterministic bytes from the SHAKE256 stream.
// It always returns len(p), nil. DRNG never returns io.EOF.
//
// Read is not safe for concurrent use. Each goroutine must use its own
// DRNG instance.
//
// Read is suitable as a rand source for crypto/rsa.GenerateKey and
// similar functions that accept an io.Reader.
func (d *DRNG) Read(p []byte) (int, error) {
	// SHAKE256 Read never errors and always fills the buffer completely.
	// We call ReadFull-style: sha3.ShakeHash.Read is documented to
	// always return len(p), nil.
	n, err := d.xof.Read(p)
	if err != nil {
		// Should never happen with SHAKE256, but don't silently swallow.
		panic("bip85: SHAKE256 read failed: " + err.Error())
	}
	return n, nil
}

package bip85

import (
	"encoding/hex"
	"fmt"
)

const (
	// HexMinBytes is the minimum byte count for the HEX application (16).
	HexMinBytes = 16
	// HexMaxBytes is the maximum byte count for the HEX application (64).
	HexMaxBytes = 64
)

// DeriveHex derives a hex-encoded entropy string from BIP85 entropy.
// numBytes (16-64) controls how many bytes are kept from the entropy
// before hex encoding. Per the spec, "truncate trailing (least significant)
// bytes" means keeping the first numBytes.
//
// The returned string is secret material (raw key entropy in hex form).
// Do not log it, include it in error messages, or pass it to tracing
// frameworks. Go strings cannot be zeroed after use.
//
// The entropy slice must be at least numBytes long.
//
// Path: m/83696968'/128169'/{numBytes}'/{index}'.
func DeriveHex(entropy []byte, numBytes int) (string, error) {
	if numBytes < HexMinBytes || numBytes > HexMaxBytes {
		return "", fmt.Errorf("%w: hex num_bytes must be %d-%d, got %d", ErrInvalidLength, HexMinBytes, HexMaxBytes, numBytes)
	}
	if len(entropy) < numBytes {
		return "", fmt.Errorf("%w: entropy too short for hex length %d", ErrInvalidLength, numBytes)
	}

	// Work on a copy to avoid modifying the caller's entropy slice.
	truncated := make([]byte, numBytes)
	copy(truncated, entropy[:numBytes])
	defer ZeroBytes(truncated)

	return hex.EncodeToString(truncated), nil
}

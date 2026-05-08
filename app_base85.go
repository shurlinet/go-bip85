package bip85

import "fmt"

const (
	// Base85MinLen is the minimum password length for the BASE85 application.
	Base85MinLen = 10
	// Base85MaxLen is the maximum password length for the BASE85 application.
	Base85MaxLen = 80
)

// DeriveBase85 derives an RFC 1924 Base85-encoded password from BIP85 entropy.
// pwdLen (10-80) controls the length of the output password string.
//
// The returned string is a secret password derived from key material.
// Do not log it or pass it to tracing frameworks.
//
// All 64 bytes of entropy are encoded using the RFC 1924 Base85 alphabet
// (NOT Adobe Ascii85, NOT Go's encoding/ascii85), then the result is
// truncated to pwdLen characters. 64 bytes -> 80 Base85 characters,
// so the maximum pwd_len of 80 uses the full encoding.
//
// Path: m/83696968'/707785'/{pwdLen}'/{index}'.
func DeriveBase85(entropy []byte, pwdLen int) (string, error) {
	if pwdLen < Base85MinLen || pwdLen > Base85MaxLen {
		return "", fmt.Errorf("%w: base85 pwd_len must be %d-%d, got %d", ErrInvalidLength, Base85MinLen, Base85MaxLen, pwdLen)
	}
	if len(entropy) < 64 {
		return "", fmt.Errorf("%w: entropy too short for base85 password", ErrInvalidLength)
	}

	// Work on a copy to avoid modifying the caller's entropy slice.
	ent := make([]byte, 64)
	copy(ent, entropy[:64])
	defer ZeroBytes(ent)

	// RFC 1924 Base85 encoding. 64 bytes is a multiple of 4.
	encoded := encodeBase85RFC1924(ent)

	// Don't trust: verify output length.
	if len(encoded) != 80 {
		return "", fmt.Errorf("bip85: base85 encoding produced %d chars, expected 80", len(encoded))
	}

	// Truncate to pwdLen characters.
	return encoded[:pwdLen], nil
}

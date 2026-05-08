package bip85

import (
	"encoding/base64"
	"fmt"
)

const (
	// Base64MinLen is the minimum password length for the BASE64 application.
	Base64MinLen = 20
	// Base64MaxLen is the maximum password length for the BASE64 application.
	Base64MaxLen = 86
)

// DeriveBase64 derives a Base64-encoded password from BIP85 entropy.
// pwdLen (20-86) controls the length of the output password string.
//
// All 64 bytes of entropy are Base64-encoded using standard RFC 4648
// encoding (NOT URL-safe), then the result is truncated to pwdLen
// characters. Passwords up to 86 characters never contain padding
// because 64 bytes encode to 86 data characters plus 2 padding
// characters (88 total), and the maximum pwdLen of 86 stops before
// any padding.
//
// Path: m/83696968'/707764'/{pwdLen}'/{index}'.
func DeriveBase64(entropy []byte, pwdLen int) (string, error) {
	if pwdLen < Base64MinLen || pwdLen > Base64MaxLen {
		return "", fmt.Errorf("%w: base64 pwd_len must be %d-%d, got %d", ErrInvalidLength, Base64MinLen, Base64MaxLen, pwdLen)
	}
	if len(entropy) < 64 {
		return "", fmt.Errorf("%w: entropy too short for base64 password", ErrInvalidLength)
	}

	// Work on a copy to avoid modifying the caller's entropy slice.
	ent := make([]byte, 64)
	copy(ent, entropy[:64])
	defer ZeroBytes(ent)

	// Standard Base64 encoding (RFC 4648), NOT URL-safe.
	encoded := base64.StdEncoding.EncodeToString(ent)

	// Truncate to pwdLen characters.
	if len(encoded) < pwdLen {
		return "", fmt.Errorf("bip85: base64 encoding produced %d chars, need %d", len(encoded), pwdLen)
	}
	return encoded[:pwdLen], nil
}

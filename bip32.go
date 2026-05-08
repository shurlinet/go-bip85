package bip85

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

// hmacKeyBIP85 is the HMAC key specified by BIP85: "bip-entropy-from-k".
var hmacKeyBIP85 = []byte("bip-entropy-from-k")

// hmacKeyBIP85Expected is the byte-level expected value for tamper detection.
var hmacKeyBIP85Expected = []byte{
	0x62, 0x69, 0x70, 0x2d, 0x65, 0x6e, 0x74, 0x72, 0x6f,
	0x70, 0x79, 0x2d, 0x66, 0x72, 0x6f, 0x6d, 0x2d, 0x6b,
}

func init() {
	if len(hmacKeyBIP85) != 18 {
		panic("bip85: HMAC key length mismatch")
	}
	for i := range hmacKeyBIP85 {
		if hmacKeyBIP85[i] != hmacKeyBIP85Expected[i] {
			panic("bip85: HMAC key content mismatch (possible tampering)")
		}
	}
}

// ParseKey parses a base58check-encoded extended private key (xprv/tprv).
// Whitespace is trimmed automatically. Public keys are rejected.
//
// The returned key can be reused across multiple derivations without
// re-parsing. It is safe for concurrent use from multiple goroutines
// since derivation creates new child keys at each level.
//
// Security: the returned ExtendedKey's String() method outputs the full
// xprv in base58. Do not pass the key to loggers, fmt.Print, or any
// framework that auto-serializes function arguments.
func ParseKey(xprv string) (*hdkeychain.ExtendedKey, error) {
	xprv = strings.TrimSpace(xprv)
	if xprv == "" {
		return nil, ErrInvalidKey
	}

	key, err := hdkeychain.NewKeyFromString(xprv)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}

	if !key.IsPrivate() {
		return nil, ErrPublicKeyNotAllowed
	}

	return key, nil
}

// deriveChild performs the BIP32 hardened derivation for all path components,
// extracts the 32-byte private key from the final child, and applies
// HMAC-SHA512 to produce 64 bytes of BIP85 entropy.
//
// All intermediate keys are zeroed after use.
func deriveChild(root *hdkeychain.ExtendedKey, path Path, hmacKey []byte) (derivedKey []byte, entropy []byte, err error) {
	if root == nil {
		return nil, nil, ErrNilKey
	}

	components := path.Components()
	if len(components) == 0 {
		return nil, nil, ErrIncompletePath
	}

	// Derive through each hardened level, zeroing intermediates.
	current := root
	for i, idx := range components {
		if idx > hardenedMax {
			return nil, nil, fmt.Errorf("%w: component %d (%d) exceeds maximum %d", ErrInvalidPath, i, idx, hardenedMax)
		}
		hardenedIdx := hdkeychain.HardenedKeyStart + idx
		child, dErr := current.Derive(hardenedIdx)
		if dErr != nil {
			if current != root {
				current.Zero()
			}
			return nil, nil, fmt.Errorf("%w: at component %d (%d'): %v", ErrInvalidKeyRange, i, idx, dErr)
		}

		// Zero the intermediate (but not the root - caller owns that).
		if current != root {
			current.Zero()
		}
		current = child
	}
	defer current.Zero()

	// Extract the 32-byte raw private key scalar.
	privKey, err := current.ECPrivKey()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidKeyRange, err)
	}
	defer privKey.Zero() // Zero the EC private key's internal ModNScalar.
	keyBytes := privKey.Serialize()
	defer ZeroBytes(keyBytes) // Zero on ALL exit paths, including early error returns.
	if len(keyBytes) != 32 {
		return nil, nil, fmt.Errorf("%w: expected 32-byte private key, got %d bytes", ErrInvalidKeyRange, len(keyBytes))
	}

	// Keep a copy of the derived key for callers that need it
	// (spec vectors include the intermediate derived key).
	derivedKeyCopy := make([]byte, 32)
	copy(derivedKeyCopy, keyBytes)

	// HMAC-SHA512(key="bip-entropy-from-k", msg=k) -> 64 bytes of entropy.
	mac := hmac.New(sha512.New, hmacKey)
	nw, err := mac.Write(keyBytes)
	if err != nil {
		ZeroBytes(derivedKeyCopy)
		return nil, nil, fmt.Errorf("bip85: HMAC write failed: %w", err)
	}
	if nw != len(keyBytes) {
		ZeroBytes(derivedKeyCopy)
		return nil, nil, fmt.Errorf("bip85: HMAC write accepted %d of %d bytes", nw, len(keyBytes))
	}
	entropyOut := mac.Sum(nil)

	if len(entropyOut) != 64 {
		ZeroBytes(derivedKeyCopy)
		ZeroBytes(entropyOut)
		return nil, nil, fmt.Errorf("%w: HMAC-SHA512 produced %d bytes, expected 64", ErrInvalidKeyRange, len(entropyOut))
	}

	return derivedKeyCopy, entropyOut, nil
}

package bip85

import "errors"

// Sentinel errors returned by the BIP85 derivation pipeline.
// Callers can use errors.Is to match these.
var (
	// ErrInvalidPath indicates a malformed or non-BIP85 derivation path.
	ErrInvalidPath = errors.New("bip85: invalid derivation path")

	// ErrIncompletePath indicates a path with too few segments for the
	// target application.
	ErrIncompletePath = errors.New("bip85: incomplete derivation path")

	// ErrNonHardenedComponent indicates a path component that is not hardened.
	// BIP85 requires ALL path components to be hardened.
	ErrNonHardenedComponent = errors.New("bip85: all path components must be hardened")

	// ErrPublicKeyNotAllowed indicates the caller passed a public extended key
	// (xpub/tpub). BIP85 requires a private extended key (xprv/tprv).
	ErrPublicKeyNotAllowed = errors.New("bip85: private extended key required, got public key")

	// ErrInvalidKey indicates the extended key string could not be parsed.
	ErrInvalidKey = errors.New("bip85: invalid extended key")

	// ErrInvalidKeyRange indicates a derived private key is zero or exceeds
	// the secp256k1 curve order. The caller should try the next index.
	ErrInvalidKeyRange = errors.New("bip85: derived key out of valid range, try next index")

	// ErrNilKey indicates a nil key was passed to a function.
	ErrNilKey = errors.New("bip85: nil key")

	// ErrInvalidHMACKey indicates the custom HMAC key option is nil or empty.
	ErrInvalidHMACKey = errors.New("bip85: HMAC key must not be nil or empty")

	// ErrEmptyKeyMaterial indicates nil or empty key material was provided,
	// either from a custom deriver or directly to EntropyFromRawKey.
	ErrEmptyKeyMaterial = errors.New("bip85: empty key material")

	// ErrPostProcessorShort indicates a post-processor returned fewer than
	// 64 bytes, which is insufficient for BIP85 applications.
	ErrPostProcessorShort = errors.New("bip85: post-processor must return at least 64 bytes")

	// ErrInvalidLength indicates a length parameter is out of the allowed
	// range for the target application.
	ErrInvalidLength = errors.New("bip85: invalid length parameter")
)

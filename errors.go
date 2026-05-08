package bip85

import "errors"

// Sentinel errors returned by the BIP85 derivation pipeline.
// Callers can use errors.Is to match these. Grouped by subsystem.
var (
	// Path errors

	// ErrInvalidPath indicates a malformed or non-BIP85 derivation path.
	ErrInvalidPath = errors.New("bip85: invalid derivation path")

	// ErrIncompletePath indicates a path with too few segments for the
	// target application.
	ErrIncompletePath = errors.New("bip85: incomplete derivation path")

	// ErrNonHardenedComponent indicates a path component that is not hardened.
	// BIP85 requires ALL path components to be hardened.
	ErrNonHardenedComponent = errors.New("bip85: all path components must be hardened")

	// Key errors

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

	// ErrEmptyKeyMaterial indicates nil or empty key material was provided,
	// either from a custom deriver or directly to EntropyFromRawKey.
	ErrEmptyKeyMaterial = errors.New("bip85: empty key material")

	// Pipeline option errors

	// ErrInvalidHMACKey indicates the custom HMAC key option is nil or empty.
	ErrInvalidHMACKey = errors.New("bip85: HMAC key must not be nil or empty")

	// ErrPostProcessorShort indicates a post-processor returned fewer than
	// 64 bytes, which is insufficient for BIP85 applications.
	ErrPostProcessorShort = errors.New("bip85: post-processor must return at least 64 bytes")

	// Application errors

	// ErrInvalidLength indicates a length parameter is out of the allowed
	// range for the target application.
	ErrInvalidLength = errors.New("bip85: invalid length parameter")

	// BIP39 application errors

	// ErrCorruptedWordlist indicates an embedded BIP39 wordlist failed
	// SHA256 integrity verification. This likely indicates a tampered binary.
	ErrCorruptedWordlist = errors.New("bip85: corrupted BIP39 wordlist (SHA256 mismatch)")

	// ErrInvalidWordCount indicates the requested word count is not valid
	// for BIP39. Valid counts: 12, 15, 18, 21, 24.
	ErrInvalidWordCount = errors.New("bip85: invalid word count")

	// ErrInvalidLanguage indicates an unsupported BIP39 language code.
	// Valid codes: 0 (English) through 9 (Portuguese).
	ErrInvalidLanguage = errors.New("bip85: invalid language code")

	// DICE application errors

	// ErrInvalidDiceSides indicates the sides parameter is out of the
	// allowed range for the DICE application. Valid: 2 to 2^32-1.
	ErrInvalidDiceSides = errors.New("bip85: invalid dice sides")

	// ErrInvalidDiceRolls indicates the rolls parameter is less than 1.
	ErrInvalidDiceRolls = errors.New("bip85: invalid dice rolls")

	// RSA application errors

	// ErrInvalidRSAKeyBits indicates the RSA key size is out of the
	// allowed range. Valid: 1024 to 16384.
	ErrInvalidRSAKeyBits = errors.New("bip85: invalid RSA key size")
)

// Package bip85 implements BIP85 (Deterministic Entropy From BIP32 Keychains),
// version 2.0.0 of the specification.
//
// BIP85 derives deterministic entropy from a BIP32 HD keychain master key.
// The derived entropy can be used to generate BIP39 mnemonics, WIF keys,
// extended private keys, passwords, dice rolls, and other cryptographic
// material - all from a single master backup.
//
// This is a pure library with no CLI, no file I/O, and no network access.
// It takes an extended private key (xprv/tprv) as input and produces
// deterministic entropy as output.
//
// # Security
//
// Memory zeroing: This library makes a best-effort attempt to zero secret
// key material after use. However, the Go garbage collector may copy data
// before zeroing occurs. For hardware-grade security, use a hardware wallet.
//
// Master key security: All derived outputs are only as secure as the master
// key. A weak or compromised master key compromises all derived entropy.
//
// Logging: Do not pass ExtendedKey values or entropy byte slices to loggers
// or tracing frameworks. ExtendedKey.String() outputs the full xprv.
// Entropy printed via fmt produces the raw secret bytes.
//
// # Specification
//
// BIP85: https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki
package bip85

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

// DeriveEntropy derives BIP85 entropy from the given pre-parsed master key
// and derivation path. It returns the 64-byte HMAC-SHA512 output.
//
// The returned entropy slice is a fresh allocation owned by the caller.
// Call ZeroBytes on it when done to clear secret material.
//
// For batch derivation, parse the key once with ParseKey and reuse it
// across multiple calls.
func DeriveEntropy(key *hdkeychain.ExtendedKey, path Path, opts ...Option) ([]byte, error) {
	dk, entropy, err := derive(key, path, opts)
	if err != nil {
		return nil, err
	}
	// Zero the derived key - DeriveEntropy callers don't need it,
	// but the shared derive() always produces it.
	ZeroBytes(dk)
	return entropy, nil
}

// DeriveEntropyFromString is a convenience wrapper that parses the xprv string
// and calls DeriveEntropy. For batch derivation, prefer ParseKey + DeriveEntropy
// to avoid repeated parsing.
func DeriveEntropyFromString(xprv string, path Path, opts ...Option) ([]byte, error) {
	key, err := ParseKey(xprv)
	if err != nil {
		return nil, err
	}
	defer key.Zero()
	return DeriveEntropy(key, path, opts...)
}

// DeriveKeyAndEntropy derives both the BIP85 intermediate key and entropy.
//
// The derivedKey is the 32-byte private key at the final path depth
// (the "k" in the BIP85 spec). The entropy is the 64-byte HMAC-SHA512 output.
// Both are secret material - call ZeroBytes on each when no longer needed.
func DeriveKeyAndEntropy(key *hdkeychain.ExtendedKey, path Path, opts ...Option) (derivedKey, entropy []byte, err error) {
	return derive(key, path, opts)
}

// derive is the shared implementation for DeriveEntropy and DeriveKeyAndEntropy.
func derive(key *hdkeychain.ExtendedKey, path Path, opts []Option) (derivedKey, entropy []byte, err error) {
	if key == nil {
		return nil, nil, ErrNilKey
	}
	if !key.IsPrivate() {
		return nil, nil, ErrPublicKeyNotAllowed
	}

	cfg := applyOptions(opts)

	if len(cfg.hmacKey) == 0 {
		return nil, nil, ErrInvalidHMACKey
	}

	if cfg.customDeriver != nil {
		return deriveCustom(key, path, cfg)
	}
	return deriveStandard(key, path, cfg)
}

// deriveStandard performs standard BIP32 derivation + HMAC-SHA512.
func deriveStandard(key *hdkeychain.ExtendedKey, path Path, cfg derivationConfig) (derivedKey, entropy []byte, err error) {
	dk, ent, err := deriveChild(key, path, cfg.hmacKey)
	if err != nil {
		return nil, nil, err
	}

	ent, err = applyPostProcessor(ent, cfg)
	if err != nil {
		ZeroBytes(dk)
		return nil, nil, err
	}

	return dk, ent, nil
}

// deriveCustom performs custom derivation + HMAC-SHA512.
func deriveCustom(key *hdkeychain.ExtendedKey, path Path, cfg derivationConfig) (derivedKey, entropy []byte, err error) {
	rawKey, err := cfg.customDeriver(key, path)
	if err != nil {
		return nil, nil, fmt.Errorf("bip85: custom deriver: %w", err)
	}
	if len(rawKey) == 0 {
		return nil, nil, ErrCustomDeriverEmpty
	}

	dk := make([]byte, len(rawKey))
	copy(dk, rawKey)

	mac := hmac.New(sha512.New, cfg.hmacKey)
	mac.Write(rawKey)
	ent := mac.Sum(nil)
	ZeroBytes(rawKey)

	ent, err = applyPostProcessor(ent, cfg)
	if err != nil {
		ZeroBytes(dk)
		return nil, nil, err
	}

	return dk, ent, nil
}

// applyPostProcessor runs the optional post-processor on entropy.
// On success it zeros the original entropy and returns the new one.
// On failure it zeros both and returns an error.
//
// Handles the case where the post-processor returns a slice aliasing the
// input: the original is copied to a safe buffer before zeroing.
func applyPostProcessor(entropy []byte, cfg derivationConfig) ([]byte, error) {
	if cfg.postProcessor == nil {
		return entropy, nil
	}

	// Snapshot the original entropy before handing it to the post-processor,
	// in case the processor returns a slice backed by the same array.
	original := make([]byte, len(entropy))
	copy(original, entropy)

	processed, err := cfg.postProcessor(entropy)
	if err != nil {
		ZeroBytes(original)
		ZeroBytes(entropy)
		return nil, fmt.Errorf("bip85: post-processor: %w", err)
	}
	if len(processed) < 64 {
		ZeroBytes(original)
		ZeroBytes(entropy)
		ZeroBytes(processed)
		return nil, ErrPostProcessorShort
	}

	// If processed aliases entropy, rebuild from our safe snapshot.
	if &processed[0] == &entropy[0] {
		result := make([]byte, len(original))
		copy(result, original)
		ZeroBytes(original)
		ZeroBytes(entropy)
		return result, nil
	}

	ZeroBytes(original)
	ZeroBytes(entropy)
	return processed, nil
}

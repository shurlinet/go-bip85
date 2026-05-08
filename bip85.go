// Package bip85 implements BIP85 (Deterministic Entropy From BIP32 Keychains),
// version 2.0.0 of the specification.
//
// BIP85 derives deterministic entropy from a BIP32 master key using
// HMAC-SHA512. A single master backup recovers all derived material:
// mnemonics, private keys, passwords, symmetric keys, and dice rolls.
// The derivation is one-way and hardened - knowledge of any derived output
// reveals nothing about the master key or other derived outputs.
//
// Basic usage (BIP32 master key to BIP39 mnemonic):
//
//	key, _ := bip85.ParseKey("xprv9s21ZrQH143K...")
//	defer key.Zero()
//
//	path := bip85.BIP39Path(bip85.LangEnglish, 12, 0)
//	entropy, _ := bip85.DeriveEntropy(key, path)
//	defer bip85.ZeroBytes(entropy)
//
//	mnemonic, _ := bip85.DeriveBIP39(entropy, bip85.LangEnglish, 12)
//
// # Derivation Pipeline
//
// The BIP85 derivation pipeline has three stages:
//
//  1. Key derivation: BIP32 hardened child derivation to a leaf key,
//     or custom derivation via [WithCustomDeriver], or direct key input
//     via [EntropyFromRawKey].
//  2. Entropy extraction: HMAC-SHA512(key="bip-entropy-from-k", msg=leafKey)
//     produces 64 bytes of deterministic entropy.
//  3. Application: the 64-byte entropy is transformed into the target
//     format (mnemonic, WIF, XPRV, hex, password, dice rolls, or
//     unlimited DRNG stream).
//
// # Applications
//
// The following BIP85 applications are supported:
//   - BIP39: Mnemonic derivation via [DeriveBIP39] (10 languages, 12-24 words)
//   - WIF: Compressed private key via [DeriveWIF] (secp256k1, network-aware)
//   - XPRV: Extended private key via [DeriveXPRV] (reversed field order per spec)
//   - HEX: Raw hex entropy via [DeriveHex] (16-64 bytes)
//   - BASE64: Password via [DeriveBase64] (20-86 characters, RFC 4648)
//   - BASE85: Password via [DeriveBase85] (10-80 characters, RFC 1924)
//   - DICE: Dice rolls via [DeriveDice] (rejection sampling, 2 to 2^32-1 sides)
//   - DRNG: Unlimited byte stream via [NewDRNG] (SHAKE256 XOF, io.Reader)
//
// RSA key generation is not provided because Go 1.24+ mixes system entropy
// into crypto/rsa for FIPS 140-3, making output non-deterministic. Use the
// DRNG directly with a deterministic RSA implementation. See [RSAPath] and
// [GPGCreationTimestamp].
//
// # Two-Tier API
//
// The library provides two entry points for entropy derivation:
//
// BIP32-native (Bitcoin and compatible chains):
//
//	entropy, err := bip85.DeriveEntropy(parsedKey, path)
//
// Chain-agnostic (Solana, Cardano, Polkadot, or any key bytes):
//
//	entropy, err := bip85.EntropyFromRawKey(myDerivedKeyBytes)
//
// Application functions ([DeriveBIP39], [DeriveHex], [DeriveWIF], [DeriveXPRV],
// [DeriveBase64], [DeriveBase85], [DeriveDice]) accept raw entropy bytes and
// are independent of the derivation method. Network parameters for WIF and
// XPRV are configurable via chaincfg.Params; pass nil for Bitcoin mainnet.
//
// # Concurrency
//
// [ParseKey] returns an [*hdkeychain.ExtendedKey] that is safe for concurrent
// use from multiple goroutines. Each derivation allocates fresh child keys
// internally. [DeriveEntropy], [DeriveKeyAndEntropy], and [EntropyFromRawKey]
// are safe for concurrent use with the same parsed key.
//
// [DRNG] instances are NOT safe for concurrent use. Each goroutine must
// create its own instance via [NewDRNG].
//
// # Security
//
// All returned byte slices (entropy, derived keys) are fresh allocations
// owned by the caller. Call [ZeroBytes] on them when no longer needed.
// Internally, all intermediate key material is zeroed via defer. The Go
// garbage collector may copy data before zeroing occurs; for hardware-grade
// security, use a hardware wallet.
//
// All functions that return secret strings ([DeriveBIP39], [DeriveWIF],
// [DeriveXPRV], [DeriveHex], [DeriveBase64], [DeriveBase85]) document the
// output as secret material. Do not log, trace, or serialize these values.
// [*hdkeychain.ExtendedKey].String() outputs the full xprv in base58 -
// do not pass parsed keys to loggers or fmt.Print.
//
// All derived outputs are only as secure as the master key. A weak or
// compromised master key compromises all derived entropy.
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
// and calls DeriveEntropy. The parsed key is zeroed automatically on return.
// For batch derivation, prefer ParseKey + DeriveEntropy to avoid repeated
// parsing.
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

// EntropyFromRawKey applies the BIP85 HMAC-SHA512 entropy extraction to a raw
// private key of any length. This is the chain-agnostic foundation of BIP85:
// HMAC-SHA512(key="bip-entropy-from-k", msg=privateKey) -> 64 bytes.
//
// Use this when you have your own key derivation (SLIP-10, Ed25519, Sr25519,
// or any non-BIP32 scheme) and want to apply the BIP85 entropy extraction step.
// The privateKey can be any length - the HMAC accepts arbitrary input.
//
// For standard BIP32 derivation, use DeriveEntropy instead.
//
// The caller is responsible for zeroing the input privateKey after use.
// The returned entropy is a fresh allocation owned by the caller.
func EntropyFromRawKey(privateKey []byte, opts ...Option) ([]byte, error) {
	if len(privateKey) == 0 {
		return nil, ErrEmptyKeyMaterial
	}

	cfg := applyOptions(opts)
	if len(cfg.hmacKey) == 0 {
		return nil, ErrInvalidHMACKey
	}
	if cfg.customDeriver != nil {
		return nil, fmt.Errorf("bip85: WithCustomDeriver is not compatible with EntropyFromRawKey (key material is already derived)")
	}

	mac := hmac.New(sha512.New, cfg.hmacKey)
	nw, wErr := mac.Write(privateKey)
	if wErr != nil {
		return nil, fmt.Errorf("bip85: HMAC write failed: %w", wErr)
	}
	if nw != len(privateKey) {
		return nil, fmt.Errorf("bip85: HMAC write accepted %d of %d bytes", nw, len(privateKey))
	}
	entropy := mac.Sum(nil)

	if len(entropy) != 64 {
		ZeroBytes(entropy)
		return nil, fmt.Errorf("%w: HMAC-SHA512 produced %d bytes, expected 64", ErrInvalidKeyRange, len(entropy))
	}

	entropy, err := applyPostProcessor(entropy, cfg)
	if err != nil {
		return nil, err
	}

	return entropy, nil
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
		return nil, nil, ErrEmptyKeyMaterial
	}
	defer ZeroBytes(rawKey) // Zero on ALL exit paths.

	dk := make([]byte, len(rawKey))
	copy(dk, rawKey)

	mac := hmac.New(sha512.New, cfg.hmacKey)
	nw, wErr := mac.Write(rawKey)
	if wErr != nil {
		ZeroBytes(dk)
		return nil, nil, fmt.Errorf("bip85: HMAC write failed: %w", wErr)
	}
	if nw != len(rawKey) {
		ZeroBytes(dk)
		return nil, nil, fmt.Errorf("bip85: HMAC write accepted %d of %d bytes", nw, len(rawKey))
	}
	ent := mac.Sum(nil)

	if len(ent) != 64 {
		ZeroBytes(dk)
		ZeroBytes(ent)
		return nil, nil, fmt.Errorf("%w: HMAC-SHA512 produced %d bytes, expected 64", ErrInvalidKeyRange, len(ent))
	}

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
// The post-processor may return a slice aliasing the input (same backing
// array at any offset). To handle this safely, the result is always
// copied to a fresh allocation before the original entropy is zeroed.
func applyPostProcessor(entropy []byte, cfg derivationConfig) ([]byte, error) {
	if cfg.postProcessor == nil {
		return entropy, nil
	}

	processed, err := cfg.postProcessor(entropy)
	if err != nil {
		ZeroBytes(entropy)
		return nil, fmt.Errorf("bip85: post-processor: %w", err)
	}
	if len(processed) < 64 {
		ZeroBytes(entropy)
		ZeroBytes(processed)
		return nil, ErrPostProcessorShort
	}

	// Always copy to a fresh allocation. If processed aliases entropy
	// (at any offset, not just the start), zeroing entropy would corrupt
	// processed. A fresh copy eliminates all aliasing concerns.
	result := make([]byte, len(processed))
	copy(result, processed)

	ZeroBytes(entropy)
	ZeroBytes(processed)
	return result, nil
}

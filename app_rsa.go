package bip85

import (
	"crypto/rsa"
	"fmt"
)

const (
	// RSAMinBits is the minimum RSA key size accepted by DeriveRSA.
	RSAMinBits = 1024
	// RSAMaxBits is the maximum RSA key size accepted by DeriveRSA.
	RSAMaxBits = 16384

	// GPGCreationTimestamp is the UNIX epoch timestamp that MUST be used as
	// the creation date for GPG keys derived from BIP85 RSA. This is the
	// Bitcoin genesis block timestamp (2009-01-03 18:15:05 UTC).
	//
	// BIP85 spec: "the creation date MUST be fixed to UNIX Epoch timestamp
	// 1231006505 [...] because the key fingerprint is affected by the
	// creation date."
	//
	// This library does not generate GPG keys directly. Consumers building
	// GPG keys from BIP85 RSA output must use this constant as the key
	// creation timestamp.
	GPGCreationTimestamp int64 = 1231006505
)

// DeriveRSA generates an RSA private key from BIP85 entropy.
//
// WARNING: The generated key is NOT recoverable from your BIP85 seed alone.
// Go's crypto/rsa (since Go 1.24) mixes system randomness into prime
// generation for FIPS 140-3 compliance, making the output non-deterministic.
// The same entropy produces a DIFFERENT key on each call. If you need the
// key again, you must store it separately - re-deriving from your seed
// backup will NOT reproduce it. For deterministic key derivation, use
// DeriveHex or the DRNG directly with your own key generation code.
//
// Cross-implementation reproducibility is also NOT guaranteed. Different
// RSA implementations (Go, Python, Rust) and even different Go versions
// produce different keys from the same DRNG stream. This is explicitly
// acknowledged in the BIP85 specification.
//
// keyBits must be in [1024, 16384]. Common values: 2048, 4096.
// Key sizes below 2048 are considered insecure for production use.
//
// RSA GPG sub-key derivation (BIP85 spec section "RSA GPG") is not
// implemented. Use GPGCreationTimestamp for the GPG key creation date.
//
// Path: m/83696968'/828365'/{keyBits}'/{keyIndex}'.
func DeriveRSA(entropy []byte, keyBits int) (*rsa.PrivateKey, error) {
	if keyBits < RSAMinBits || keyBits > RSAMaxBits {
		return nil, fmt.Errorf("%w: RSA key_bits must be %d-%d, got %d", ErrInvalidRSAKeyBits, RSAMinBits, RSAMaxBits, keyBits)
	}
	if len(entropy) < 64 {
		return nil, fmt.Errorf("%w: entropy too short for RSA key generation", ErrInvalidLength)
	}

	// Work on a copy to avoid modifying the caller's entropy slice.
	ent := make([]byte, 64)
	copy(ent, entropy[:64])
	defer ZeroBytes(ent)

	drng := NewDRNG(ent)

	// crypto/rsa.GenerateKey accepts an io.Reader for randomness.
	// Our DRNG implements io.Reader with deterministic SHAKE256 output.
	privKey, err := rsa.GenerateKey(drng, keyBits)
	if err != nil {
		return nil, fmt.Errorf("bip85: RSA key generation: %w", err)
	}

	// Don't trust: verify the generated key is valid.
	if vErr := privKey.Validate(); vErr != nil {
		return nil, fmt.Errorf("bip85: RSA key validation: %w", vErr)
	}

	// Don't trust: verify the key has the requested bit length.
	if privKey.N.BitLen() != keyBits {
		return nil, fmt.Errorf("bip85: RSA key size mismatch: requested %d bits, got %d", keyBits, privKey.N.BitLen())
	}

	return privKey, nil
}

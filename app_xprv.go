package bip85

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

// DeriveXPRV derives a BIP32 extended private key from the given
// 64-byte BIP85 entropy.
//
// The returned string is a secret extended private key. Do not log it
// or pass it to tracing frameworks.
//
// The net parameter controls the version bytes in the serialized key.
// Pass &chaincfg.MainNetParams for Bitcoin mainnet (xprv prefix),
// &chaincfg.TestNet3Params for testnet (tprv prefix), or custom
// chaincfg.Params for other BIP32-compatible chains. If nil, defaults
// to Bitcoin mainnet.
//
// Per the BIP85 spec, the field ordering is REVERSED from BIP32 convention:
//   - First 32 bytes of entropy = chain code
//   - Second 32 bytes of entropy = private key
//
// The private key is validated against the secp256k1 curve order.
// If invalid, ErrInvalidKeyRange is returned and the caller should try
// the next index.
//
// Depth, parent fingerprint, and child number are forced to zero per spec.
func DeriveXPRV(entropy []byte, net *chaincfg.Params) (string, error) {
	if len(entropy) < 64 {
		return "", fmt.Errorf("%w: entropy too short for XPRV", ErrInvalidKeyRange)
	}
	if net == nil {
		net = &chaincfg.MainNetParams
	}

	// Work on copies to avoid modifying the caller's entropy slice.
	chainCode := make([]byte, 32)
	copy(chainCode, entropy[:32]) // First 32 = chain code (REVERSED from BIP32)
	defer ZeroBytes(chainCode)

	keyBytes := make([]byte, 32)
	copy(keyBytes, entropy[32:64]) // Second 32 = private key (REVERSED from BIP32)
	defer ZeroBytes(keyBytes)

	// Validate private key against secp256k1 curve order.
	if err := ValidateSecp256k1Key(keyBytes); err != nil {
		return "", err
	}

	// Construct the extended key via hdkeychain. Depth, parent fingerprint,
	// and child number are all zero per BIP85 XPRV spec.
	// hdkeychain handles BIP32 serialization and base58check encoding.
	extKey := hdkeychain.NewExtendedKey(
		net.HDPrivateKeyID[:], // 4-byte version from network params
		keyBytes,
		chainCode,
		[]byte{0, 0, 0, 0}, // parent fingerprint (zero)
		0,                   // depth (zero)
		0,                   // child number (zero)
		true,                // isPrivate
	)
	defer extKey.Zero()

	// Don't trust: verify the serialized key round-trips through the parser.
	// This catches structural corruption in the serialization.
	result := extKey.String()
	parsed, err := hdkeychain.NewKeyFromString(result)
	if err != nil {
		return "", fmt.Errorf("bip85: XPRV serialization produced unparseable output (check network version bytes): %w", err)
	}
	parsed.Zero()

	return result, nil
}

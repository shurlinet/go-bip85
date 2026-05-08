package bip85

import (
	"fmt"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

// DeriveWIF derives a compressed WIF-encoded private key from BIP85 entropy.
// The first 32 bytes of entropy are used as the private key.
//
// The returned string is a secret private key. Do not log it or pass it
// to tracing frameworks.
//
// The net parameter controls the version byte in the WIF encoding.
// Pass &chaincfg.MainNetParams for Bitcoin mainnet (prefix K/L),
// &chaincfg.TestNet3Params for testnet (prefix c), or custom
// chaincfg.Params for other BIP32-compatible chains. If nil, defaults
// to Bitcoin mainnet.
//
// The key is validated against the secp256k1 curve order. If invalid
// (probability < 1 in 2^127), ErrInvalidKeyRange is returned and the
// caller should try the next index.
func DeriveWIF(entropy []byte, net *chaincfg.Params) (string, error) {
	if len(entropy) < 32 {
		return "", fmt.Errorf("%w: entropy too short for WIF", ErrInvalidKeyRange)
	}
	if net == nil {
		net = &chaincfg.MainNetParams
	}

	// Work on a copy to avoid modifying the caller's entropy slice.
	keyBytes := make([]byte, 32)
	copy(keyBytes, entropy[:32])
	defer ZeroBytes(keyBytes)

	// Validate against secp256k1 curve order.
	if err := ValidateSecp256k1Key(keyBytes); err != nil {
		return "", err
	}

	// Parse as secp256k1 private key via btcec.
	privKey, _ := btcec.PrivKeyFromBytes(keyBytes)
	if privKey == nil {
		return "", fmt.Errorf("%w: btcec rejected validated key", ErrInvalidKeyRange)
	}
	defer privKey.Zero()

	// btcutil handles version byte, compression flag, base58check encoding.
	wif, err := btcutil.NewWIF(privKey, net, true)
	if err != nil {
		return "", fmt.Errorf("bip85: WIF encoding: %w", err)
	}

	return wif.String(), nil
}

// DecodeWIF decodes a WIF string and returns the 32-byte raw private key
// and whether it was compressed. The returned key is a fresh allocation;
// call ZeroBytes on it when done.
//
// If net is non-nil, the WIF is verified to match the given network.
// If net is nil, the network check is skipped.
func DecodeWIF(wif string, net *chaincfg.Params) (key []byte, compressed bool, err error) {
	decoded, err := btcutil.DecodeWIF(wif)
	if err != nil {
		return nil, false, fmt.Errorf("bip85: WIF decode: %w", err)
	}
	defer decoded.PrivKey.Zero()

	if net != nil && !decoded.IsForNet(net) {
		return nil, false, fmt.Errorf("bip85: WIF is not for the specified network")
	}

	compressed = decoded.CompressPubKey

	keyBytes := decoded.PrivKey.Serialize()
	key = make([]byte, 32)
	copy(key, keyBytes)
	ZeroBytes(keyBytes)

	return key, compressed, nil
}

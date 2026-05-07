package bip85

import "math/big"

// secp256k1Order is the order of the secp256k1 elliptic curve group.
// Any valid private key must satisfy: 0 < key < order.
var secp256k1Order = mustParseBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

func mustParseBigInt(hex string) *big.Int {
	n, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		panic("bip85: failed to parse secp256k1 curve order constant")
	}
	return n
}

// ZeroBytes overwrites buf with zeros. Use this to clear secret material
// (entropy, derived keys) returned by DeriveEntropy and DeriveKeyAndEntropy.
//
// This is a best-effort measure. The Go garbage collector may have already
// copied the data to another location, so this is not a guarantee against
// memory forensics.
//
//go:noinline
func ZeroBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

// ValidatePrivateKey checks whether a 32-byte value is a valid secp256k1
// private key (non-zero and less than the curve order). Returns nil if valid.
//
// BIP85 applications that use raw entropy as an EC private key (WIF, XPRV)
// must call this before encoding. If the key is invalid, the caller should
// try the next BIP85 index.
func ValidatePrivateKey(key []byte) error {
	if len(key) != 32 {
		return ErrInvalidKeyRange
	}
	k := new(big.Int).SetBytes(key)
	valid := k.Sign() != 0 && k.Cmp(secp256k1Order) < 0
	k.SetUint64(0) // clear secret from big.Int internal limbs
	if !valid {
		return ErrInvalidKeyRange
	}
	return nil
}

// Command multichain demonstrates go-bip85's chain-agnostic design using
// EntropyFromRawKey. This entry point accepts any raw private key bytes,
// regardless of how they were derived, and applies the BIP85 HMAC-SHA512
// entropy extraction step.
//
// This makes go-bip85 usable with chains that do NOT use BIP32:
//   - Solana (Ed25519 via SLIP-10)
//   - Cardano (Ed25519-BIP32)
//   - Polkadot (Sr25519)
//   - Any custom derivation scheme
package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/shurlinet/go-bip85"
)

func main() {
	// Scenario: you have a 32-byte Ed25519 private key derived via SLIP-10
	// (Solana's derivation scheme). You want BIP85 entropy from it.
	//
	// In a real application, this key would come from your SLIP-10 derivation.
	// Here we use a dummy key for demonstration.
	solanaKey, _ := hex.DecodeString("cca20ccb0e9a90feb0912870c3323b24874b0ca3d8018c4b96d0b97c0e82ded0")
	defer bip85.ZeroBytes(solanaKey)

	// EntropyFromRawKey applies HMAC-SHA512("bip-entropy-from-k", key) directly.
	// No BIP32, no btcsuite types, no Bitcoin assumptions.
	entropy, err := bip85.EntropyFromRawKey(solanaKey)
	if err != nil {
		log.Fatal(err)
	}
	defer bip85.ZeroBytes(entropy)

	fmt.Printf("Chain-agnostic entropy (first 16 bytes): %s...\n", hex.EncodeToString(entropy[:16]))
	fmt.Printf("Entropy length: %d bytes\n", len(entropy))

	// Use the entropy for any BIP85 application.
	// These application functions work identically regardless of how the
	// entropy was produced.

	// HEX: raw 32 bytes for a symmetric key.
	hexKey, err := bip85.DeriveHex(entropy, 32)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Derived HEX (32 bytes):", hexKey)

	// BIP39: 12-word English mnemonic.
	mnemonic, err := bip85.DeriveBIP39(entropy, bip85.LangEnglish, 12)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Derived mnemonic:", mnemonic)

	// The same EntropyFromRawKey works with keys of any length.
	// Here is a hypothetical 48-byte key from a different scheme:
	customKey := make([]byte, 48)
	for i := range customKey {
		customKey[i] = byte(i + 1)
	}
	defer bip85.ZeroBytes(customKey)

	entropy2, err := bip85.EntropyFromRawKey(customKey)
	if err != nil {
		log.Fatal(err)
	}
	defer bip85.ZeroBytes(entropy2)
	fmt.Printf("48-byte key entropy (first 16 bytes): %s...\n", hex.EncodeToString(entropy2[:16]))
}

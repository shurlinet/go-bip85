// Command password demonstrates generating Base64 and Base85 passwords
// from BIP85 entropy. Both password types are derived deterministically
// from a single master key.
package main

import (
	"fmt"
	"log"

	"github.com/shurlinet/go-bip85"
)

func main() {
	key, err := bip85.ParseKey("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb")
	if err != nil {
		log.Fatal(err)
	}
	defer key.Zero()

	// --- Base64 password (RFC 4648 standard encoding) ---
	// Length 21 characters, index 0.
	b64Path := bip85.Base64Path(21, 0)
	b64Entropy, err := bip85.DeriveEntropy(key, b64Path)
	if err != nil {
		log.Fatal(err)
	}
	defer bip85.ZeroBytes(b64Entropy)

	b64Pwd, err := bip85.DeriveBase64(b64Entropy, 21)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Base64 password (21 chars):", b64Pwd)

	// --- Base85 password (RFC 1924 encoding) ---
	// Length 12 characters, index 0.
	b85Path := bip85.Base85Path(12, 0)
	b85Entropy, err := bip85.DeriveEntropy(key, b85Path)
	if err != nil {
		log.Fatal(err)
	}
	defer bip85.ZeroBytes(b85Entropy)

	b85Pwd, err := bip85.DeriveBase85(b85Entropy, 12)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Base85 password (12 chars):", b85Pwd)

	// --- Generate multiple passwords at different indexes ---
	fmt.Println("\nMultiple Base64 passwords (length 30):")
	for idx := uint32(0); idx < 5; idx++ {
		path := bip85.Base64Path(30, idx)
		entropy, err := bip85.DeriveEntropy(key, path)
		if err != nil {
			log.Fatal(err)
		}
		pwd, err := bip85.DeriveBase64(entropy, 30)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("  index %d: %s\n", idx, pwd)
		bip85.ZeroBytes(entropy)
	}
}

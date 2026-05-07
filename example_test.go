package bip85_test

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/shurlinet/go-bip85"
)

func Example() {
	// Parse a BIP32 master private key.
	key, err := bip85.ParseKey("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb")
	if err != nil {
		log.Fatal(err)
	}
	defer key.Zero()

	// Derive 64 bytes of entropy at path m/83696968'/0'/0'.
	path, err := bip85.ParsePath("m/83696968'/0'/0'")
	if err != nil {
		log.Fatal(err)
	}

	entropy, err := bip85.DeriveEntropy(key, path)
	if err != nil {
		log.Fatal(err)
	}
	defer bip85.ZeroBytes(entropy)

	fmt.Println(hex.EncodeToString(entropy[:8]) + "...")
	// Output: efecfbccffea3132...
}

func ExampleDeriveEntropyFromString() {
	xprv := "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
	path, _ := bip85.ParsePath("m/83696968'/0'/0'")

	entropy, err := bip85.DeriveEntropyFromString(xprv, path)
	if err != nil {
		log.Fatal(err)
	}
	defer bip85.ZeroBytes(entropy)

	fmt.Println(len(entropy), "bytes")
	// Output: 64 bytes
}

func ExampleBIP39Path() {
	// Build a path for deriving a 12-word English BIP39 mnemonic at index 0.
	path := bip85.BIP39Path(0, 12, 0)
	fmt.Println(path.String())
	// Output: m/83696968'/39'/0'/12'/0'
}

func ExampleParsePath() {
	// All hardened marker styles are accepted and normalized.
	p1, _ := bip85.ParsePath("m/83696968'/0'/0'")
	p2, _ := bip85.ParsePath("m/83696968h/0h/0h")
	fmt.Println(p1.String())
	fmt.Println(p2.String())
	// Output:
	// m/83696968'/0'/0'
	// m/83696968'/0'/0'
}

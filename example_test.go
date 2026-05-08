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

func ExampleDeriveDice() {
	key, err := bip85.ParseKey("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb")
	if err != nil {
		log.Fatal(err)
	}
	defer key.Zero()

	// Roll a 6-sided die 10 times at index 0.
	path := bip85.DicePath(6, 10, 0)
	entropy, err := bip85.DeriveEntropy(key, path)
	if err != nil {
		log.Fatal(err)
	}
	defer bip85.ZeroBytes(entropy)

	values, formatted, err := bip85.DeriveDice(entropy, 6, 10)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(formatted)
	fmt.Println(len(values), "rolls")
	// Output:
	// 1,0,0,2,0,1,5,5,2,4
	// 10 rolls
}

func ExampleDeriveRSA() {
	key, err := bip85.ParseKey("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb")
	if err != nil {
		log.Fatal(err)
	}
	defer key.Zero()

	// Generate a 2048-bit RSA key at index 0.
	path := bip85.RSAPath(2048, 0)
	entropy, err := bip85.DeriveEntropy(key, path)
	if err != nil {
		log.Fatal(err)
	}
	defer bip85.ZeroBytes(entropy)

	privKey, err := bip85.DeriveRSA(entropy, 2048)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(privKey.N.BitLen(), "bits")
	fmt.Println("valid:", privKey.Validate() == nil)
	// Output:
	// 2048 bits
	// valid: true
}

// Command basic demonstrates deriving a BIP39 mnemonic from a BIP32 master key
// using go-bip85. This is the standard Bitcoin use case: master key in, child
// mnemonic out.
package main

import (
	"fmt"
	"log"

	"github.com/shurlinet/go-bip85"
)

func main() {
	// Step 1: parse a BIP32 extended private key.
	//
	// In a real application, this would come from your wallet or key manager.
	// Never hardcode real master keys. This is the BIP85 spec test vector key.
	key, err := bip85.ParseKey("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb")
	if err != nil {
		log.Fatal(err)
	}
	defer key.Zero() // Zero the master key when done.

	// Step 2: build a derivation path.
	//
	// BIP39Path(language, words, index):
	//   language: LangEnglish (0)
	//   words:    12 = 12-word mnemonic
	//   index:    0 = first derived mnemonic
	path := bip85.BIP39Path(bip85.LangEnglish, 12, 0)
	fmt.Println("Path:", path.String())

	// Step 3: derive the 64-byte entropy at this path.
	entropy, err := bip85.DeriveEntropy(key, path)
	if err != nil {
		log.Fatal(err)
	}
	defer bip85.ZeroBytes(entropy) // Zero entropy when done.

	// Step 4: convert entropy to a BIP39 mnemonic.
	mnemonic, err := bip85.DeriveBIP39(entropy, bip85.LangEnglish, 12)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Mnemonic:", mnemonic)

	// Derive a second mnemonic at index 1 - completely independent.
	path2 := bip85.BIP39Path(bip85.LangEnglish, 12, 1)
	entropy2, err := bip85.DeriveEntropy(key, path2)
	if err != nil {
		log.Fatal(err)
	}
	defer bip85.ZeroBytes(entropy2)

	mnemonic2, err := bip85.DeriveBIP39(entropy2, bip85.LangEnglish, 12)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Mnemonic (index 1):", mnemonic2)
}

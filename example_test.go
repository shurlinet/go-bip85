package bip85_test

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"

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
	path := bip85.BIP39Path(bip85.LangEnglish, 12, 0)
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

func ExampleDeriveBIP39() {
	key, err := bip85.ParseKey("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb")
	if err != nil {
		log.Fatal(err)
	}
	defer key.Zero()

	path := bip85.BIP39Path(bip85.LangEnglish, 12, 0)
	entropy, err := bip85.DeriveEntropy(key, path)
	if err != nil {
		log.Fatal(err)
	}
	defer bip85.ZeroBytes(entropy)

	mnemonic, err := bip85.DeriveBIP39(entropy, bip85.LangEnglish, 12)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(mnemonic)
	fmt.Println(strings.Count(mnemonic, " ")+1, "words")
	// Output:
	// girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose
	// 12 words
}

func ExampleDeriveWIF() {
	key, err := bip85.ParseKey("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb")
	if err != nil {
		log.Fatal(err)
	}
	defer key.Zero()

	path := bip85.WIFPath(0)
	entropy, err := bip85.DeriveEntropy(key, path)
	if err != nil {
		log.Fatal(err)
	}
	defer bip85.ZeroBytes(entropy)

	wif, err := bip85.DeriveWIF(entropy, nil) // nil = Bitcoin mainnet
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(wif)
	// Output: Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp
}

func ExampleDeriveXPRV() {
	key, err := bip85.ParseKey("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb")
	if err != nil {
		log.Fatal(err)
	}
	defer key.Zero()

	path := bip85.XPRVPath(0)
	entropy, err := bip85.DeriveEntropy(key, path)
	if err != nil {
		log.Fatal(err)
	}
	defer bip85.ZeroBytes(entropy)

	xprv, err := bip85.DeriveXPRV(entropy, nil) // nil = Bitcoin mainnet
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(xprv)
	// Output: xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX
}

func ExampleDeriveHex() {
	key, err := bip85.ParseKey("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb")
	if err != nil {
		log.Fatal(err)
	}
	defer key.Zero()

	path := bip85.HexPath(32, 0)
	entropy, err := bip85.DeriveEntropy(key, path)
	if err != nil {
		log.Fatal(err)
	}
	defer bip85.ZeroBytes(entropy)

	hexStr, err := bip85.DeriveHex(entropy, 32)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(hexStr)
	fmt.Println(len(hexStr)/2, "bytes")
	// Output:
	// ea3ceb0b02ee8e587779c63f4b7b3a21e950a213f1ec53cab608d13e8796e6dc
	// 32 bytes
}

func ExampleNewDRNG() {
	key, err := bip85.ParseKey("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb")
	if err != nil {
		log.Fatal(err)
	}
	defer key.Zero()

	// Derive entropy and create a DRNG (deterministic random number generator).
	path, _ := bip85.ParsePath("m/83696968'/0'/0'")
	entropy, err := bip85.DeriveEntropy(key, path)
	if err != nil {
		log.Fatal(err)
	}
	defer bip85.ZeroBytes(entropy)

	drng := bip85.NewDRNG(entropy)

	// Read 16 bytes of deterministic output.
	buf := make([]byte, 16)
	drng.Read(buf)
	fmt.Println(hex.EncodeToString(buf))
	// Output: b78b1ee6b345eae6836c2d53d33c64cd
}

func ExampleEntropyFromRawKey() {
	// Chain-agnostic: apply BIP85 HMAC extraction to any raw private key.
	// No BIP32 types needed. Works with Ed25519, Sr25519, or any key bytes.
	rawKey, _ := hex.DecodeString("cca20ccb0e9a90feb0912870c3323b24874b0ca3d8018c4b96d0b97c0e82ded0")
	defer bip85.ZeroBytes(rawKey)

	entropy, err := bip85.EntropyFromRawKey(rawKey)
	if err != nil {
		log.Fatal(err)
	}
	defer bip85.ZeroBytes(entropy)

	fmt.Println(len(entropy), "bytes")
	fmt.Println(hex.EncodeToString(entropy[:8]) + "...")
	// Output:
	// 64 bytes
	// efecfbccffea3132...
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

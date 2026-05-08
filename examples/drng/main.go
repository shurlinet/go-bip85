// Command drng demonstrates using the BIP85-DRNG-SHAKE256 as an io.Reader
// for custom key generation. The DRNG produces an unlimited deterministic
// byte stream from 64 bytes of BIP85 entropy.
package main

import (
	"encoding/hex"
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

	// Derive entropy at the DRNG path.
	path, _ := bip85.ParsePath("m/83696968'/0'/0'")
	entropy, err := bip85.DeriveEntropy(key, path)
	if err != nil {
		log.Fatal(err)
	}
	defer bip85.ZeroBytes(entropy)

	// Create a DRNG from the entropy.
	drng := bip85.NewDRNG(entropy)

	// The DRNG implements io.Reader. Read any number of bytes.
	buf := make([]byte, 32)
	n, err := drng.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("DRNG output (%d bytes): %s\n", n, hex.EncodeToString(buf))

	// The stream is deterministic: same entropy always produces the same
	// sequence. Creating a new DRNG with the same entropy restarts from
	// the beginning.
	drng2 := bip85.NewDRNG(entropy)
	buf2 := make([]byte, 32)
	drng2.Read(buf2)
	fmt.Printf("Same entropy, new DRNG: %s\n", hex.EncodeToString(buf2))
	fmt.Printf("Identical: %v\n", hex.EncodeToString(buf) == hex.EncodeToString(buf2))

	// Continue reading from the first DRNG to get MORE bytes from the
	// same stream. These are different from buf (the stream advanced).
	buf3 := make([]byte, 16)
	drng.Read(buf3)
	defer bip85.ZeroBytes(buf3)
	fmt.Printf("Next 16 bytes from first DRNG: %s\n", hex.EncodeToString(buf3))

	// The DRNG can also be passed to crypto/rsa.GenerateKey or any function
	// that accepts an io.Reader as a randomness source. Note: on Go 1.24+,
	// crypto/rsa mixes system entropy for FIPS compliance, so RSA output
	// will NOT be deterministic. See the package documentation for details.
}

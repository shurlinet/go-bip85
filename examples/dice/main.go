// Command dice demonstrates using BIP85 DICE for deterministic PIN generation
// and alphanumeric password generation via dice-to-alphabet mapping.
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

	// --- 4-digit PIN ---
	// 10-sided die (digits 0-9), 4 rolls, index 0.
	pinPath := bip85.DicePath(10, 4, 0)
	pinEntropy, err := bip85.DeriveEntropy(key, pinPath)
	if err != nil {
		log.Fatal(err)
	}
	defer bip85.ZeroBytes(pinEntropy)

	pinValues, _, err := bip85.DeriveDice(pinEntropy, 10, 4)
	if err != nil {
		log.Fatal(err)
	}

	pin := ""
	for _, v := range pinValues {
		pin += fmt.Sprintf("%d", v)
	}
	fmt.Println("4-digit PIN:", pin)

	// --- Alphanumeric password via 62-sided die ---
	// 62 sides maps to: 0-9 (digits), A-Z (uppercase), a-z (lowercase).
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	pwdLen := 16

	pwdPath := bip85.DicePath(62, uint32(pwdLen), 0)
	pwdEntropy, err := bip85.DeriveEntropy(key, pwdPath)
	if err != nil {
		log.Fatal(err)
	}
	defer bip85.ZeroBytes(pwdEntropy)

	pwdValues, _, err := bip85.DeriveDice(pwdEntropy, 62, pwdLen)
	if err != nil {
		log.Fatal(err)
	}

	password := make([]byte, pwdLen)
	for i, v := range pwdValues {
		password[i] = alphabet[v]
	}
	fmt.Printf("Alphanumeric password (%d chars): %s\n", pwdLen, string(password))
	bip85.ZeroBytes(password) // Zero derived password material.

	// --- Standard 6-sided die ---
	dicePath := bip85.DicePath(6, 10, 0)
	diceEntropy, err := bip85.DeriveEntropy(key, dicePath)
	if err != nil {
		log.Fatal(err)
	}
	defer bip85.ZeroBytes(diceEntropy)

	_, formatted, err := bip85.DeriveDice(diceEntropy, 6, 10)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("6-sided die (10 rolls):", formatted)
}

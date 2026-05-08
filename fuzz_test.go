package bip85

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// specEntropyHex is the spec vector 1 entropy used as seed for fuzz targets
// that need valid 64-byte entropy input.
const specEntropyHex = "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"

func FuzzParsePath(f *testing.F) {
	// Seed corpus: valid paths, edge cases, and known-invalid inputs.
	f.Add("m/83696968'/0'/0'")
	f.Add("m/83696968'/39'/0'/12'/0'")
	f.Add("m/83696968h/0h/0h")
	f.Add("m/83696968H/0H/0H")
	f.Add("m/83696968p/0p/0p")
	f.Add("m/83696968'/128169'/64'/0'")
	f.Add("m/83696968'/128169'/32'/2147483647'")
	f.Add("m/83696968'/707764'/21'/0'")
	f.Add("m/83696968'/707785'/12'/0'")
	f.Add("m/83696968'/89101'/6'/10'/0'")
	f.Add("m/83696968'/828365'/2048'/0'")
	f.Add("")
	f.Add("m/")
	f.Add("m/83696968'")
	f.Add("m/44'/0'/0'")
	f.Add("m/83696968'/0'/0")
	f.Add("garbage")

	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParsePath(s)
		if err != nil {
			return
		}
		// Valid parse: verify round-trip consistency.
		str := p.String()
		p2, err := ParsePath(str)
		if err != nil {
			t.Fatalf("round-trip failed: ParsePath(%q) -> %q -> error: %v", s, str, err)
		}
		if p2.String() != str {
			t.Fatalf("round-trip inconsistent: %q -> %q -> %q", s, str, p2.String())
		}
		if p.Len() != p2.Len() {
			t.Fatalf("round-trip length mismatch: %d vs %d", p.Len(), p2.Len())
		}
	})
}

func FuzzDeriveEntropy(f *testing.F) {
	// Seed: valid xprv + valid path combinations.
	f.Add(specMasterXprv, "m/83696968'/0'/0'")
	f.Add(specMasterXprv, "m/83696968'/39'/0'/12'/0'")
	f.Add(specMasterXprv, "m/83696968'/2'/0'")
	f.Add(specMasterXprv, "m/83696968'/32'/0'")
	f.Add(specMasterXprv, "m/83696968'/128169'/64'/0'")
	f.Add("", "m/83696968'/0'/0'")
	f.Add("xprv_invalid", "m/83696968'/0'/0'")
	f.Add(specMasterXprv, "")
	f.Add(specMasterXprv, "garbage")

	f.Fuzz(func(t *testing.T, xprv, pathStr string) {
		key, err := ParseKey(xprv)
		if err != nil {
			return
		}
		defer key.Zero()

		path, err := ParsePath(pathStr)
		if err != nil {
			return
		}

		entropy, err := DeriveEntropy(key, path)
		if err != nil {
			return
		}
		defer ZeroBytes(entropy)

		if len(entropy) != 64 {
			t.Fatalf("entropy length %d, want 64", len(entropy))
		}

		// Determinism: same input must produce same output.
		entropy2, err := DeriveEntropy(key, path)
		if err != nil {
			t.Fatalf("second derivation failed: %v", err)
		}
		defer ZeroBytes(entropy2)
		if !bytes.Equal(entropy, entropy2) {
			t.Fatal("not deterministic: same input produced different output")
		}
	})
}

func FuzzDRNG(f *testing.F) {
	// Seed: spec entropy with various read sizes.
	entropy, _ := hex.DecodeString(specEntropyHex)
	f.Add(entropy, 1)
	f.Add(entropy, 10)
	f.Add(entropy, 64)
	f.Add(entropy, 80)
	f.Add(entropy, 100)
	f.Add(entropy, 1000)
	f.Add(make([]byte, 64), 10)

	f.Fuzz(func(t *testing.T, seed []byte, readSize int) {
		if len(seed) != 64 {
			return
		}
		if readSize < 0 || readSize > 10000 {
			return
		}

		drng := NewDRNG(seed)
		buf := make([]byte, readSize)
		n, err := drng.Read(buf)
		if err != nil {
			t.Fatalf("DRNG Read(%d): %v", readSize, err)
		}
		if n != readSize {
			t.Fatalf("DRNG Read: got %d, want %d", n, readSize)
		}

		// Determinism: same seed must produce same stream.
		drng2 := NewDRNG(seed)
		buf2 := make([]byte, readSize)
		drng2.Read(buf2)
		if !bytes.Equal(buf, buf2) {
			t.Fatal("same seed produced different DRNG output")
		}
	})
}

// rfc1924Set is a precomputed lookup table for O(1) alphabet membership checks
// in fuzz targets. Built once per process, not per iteration.
var rfc1924Set = func() [256]bool {
	var s [256]bool
	for i := 0; i < len(rfc1924Alphabet); i++ {
		s[rfc1924Alphabet[i]] = true
	}
	return s
}()

func FuzzBase85Encode(f *testing.F) {
	// Seed: various 4-byte-aligned inputs.
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{0x00, 0x00, 0x00, 0x01})
	f.Add([]byte{0x00, 0x00, 0x00, 0x54})
	entropy, _ := hex.DecodeString(specEntropyHex)
	f.Add(entropy) // 64 bytes

	f.Fuzz(func(t *testing.T, src []byte) {
		if len(src) == 0 || len(src)%4 != 0 {
			return
		}
		if len(src) > 1024 {
			return
		}

		result := encodeBase85RFC1924(src)

		// Output must be exactly (len/4)*5 characters.
		expectedLen := (len(src) / 4) * 5
		if len(result) != expectedLen {
			t.Fatalf("encode(%d bytes): got %d chars, want %d", len(src), len(result), expectedLen)
		}

		// All characters must be in the RFC 1924 alphabet.
		for i := 0; i < len(result); i++ {
			if !rfc1924Set[result[i]] {
				t.Fatalf("char %d %q not in RFC 1924 alphabet", i, string(result[i]))
			}
		}
	})
}

func FuzzBIP39EntropyToWords(f *testing.F) {
	// Seed: valid entropy lengths for each word count.
	f.Add(make([]byte, 64), uint32(0), 12)
	f.Add(make([]byte, 64), uint32(0), 15)
	f.Add(make([]byte, 64), uint32(0), 18)
	f.Add(make([]byte, 64), uint32(0), 21)
	f.Add(make([]byte, 64), uint32(0), 24)
	f.Add(make([]byte, 64), uint32(1), 12) // Japanese
	f.Add(make([]byte, 64), uint32(9), 12) // Portuguese
	entropy, _ := hex.DecodeString(specEntropyHex)
	f.Add(entropy, uint32(0), 12)

	f.Fuzz(func(t *testing.T, ent []byte, lang uint32, words int) {
		if len(ent) < 16 || len(ent) > 64 {
			return
		}
		if lang > 9 {
			return
		}
		if words != 12 && words != 15 && words != 18 && words != 21 && words != 24 {
			return
		}

		mnemonic, err := DeriveBIP39(ent, lang, words)
		if err != nil {
			return
		}

		// Verify word count using the same separator logic as the source.
		sep := " "
		if lang == LangJapanese {
			sep = "\u3000"
		}
		parts := strings.Split(mnemonic, sep)
		if len(parts) != words {
			t.Fatalf("word count: got %d, want %d", len(parts), words)
		}
	})
}

func FuzzDiceRolls(f *testing.F) {
	entropy, _ := hex.DecodeString(specEntropyHex)
	f.Add(entropy, uint32(6), 10)
	f.Add(entropy, uint32(2), 20)
	f.Add(entropy, uint32(100), 10)
	f.Add(entropy, uint32(3), 100)
	f.Add(make([]byte, 64), uint32(6), 10)

	f.Fuzz(func(t *testing.T, ent []byte, sides uint32, rolls int) {
		if len(ent) != 64 {
			return
		}
		if sides < 2 || sides > 10000 {
			return
		}
		if rolls < 1 || rolls > 1000 {
			return
		}

		values, err := DeriveRolls(ent, sides, rolls)
		if err != nil {
			return
		}

		if len(values) != rolls {
			t.Fatalf("roll count: got %d, want %d", len(values), rolls)
		}
		for i, v := range values {
			if v < 0 || v >= int(sides) {
				t.Fatalf("value[%d] = %d out of range [0, %d)", i, v, sides)
			}
		}
	})
}

func FuzzWIF(f *testing.F) {
	// Seed: valid 32-byte keys.
	validKey, _ := hex.DecodeString("cca20ccb0e9a90feb0912870c3323b24874b0ca3d8018c4b96d0b97c0e82ded0")
	f.Add(validKey)
	f.Add(make([]byte, 32))
	entropy, _ := hex.DecodeString(specEntropyHex)
	f.Add(entropy[:32])

	f.Fuzz(func(t *testing.T, keyBytes []byte) {
		if len(keyBytes) < 32 {
			return
		}

		// DeriveWIF reads first 32 bytes. Pass a slice of exactly that.
		wif, err := DeriveWIF(keyBytes[:32], nil)
		if err != nil {
			return
		}

		// Valid WIF: verify round-trip.
		decoded, compressed, err := DecodeWIF(wif, nil)
		if err != nil {
			t.Fatalf("WIF round-trip failed: %v", err)
		}
		if !compressed {
			t.Fatal("expected compressed WIF")
		}
		// Round-trip: decoded key must match input.
		if !bytes.Equal(decoded, keyBytes[:32]) {
			t.Fatal("WIF round-trip key mismatch")
		}
		ZeroBytes(decoded)
	})
}

func FuzzXPRV(f *testing.F) {
	entropy, _ := hex.DecodeString(specEntropyHex)
	f.Add(entropy)
	f.Add(make([]byte, 64))
	// Entropy from spec XPRV vector.
	xprvEntropy, _ := hex.DecodeString("52405cd0dd21c5be78314a7c1a3c65ffd8d896536cc7dee3157db5824f0c92e2ead0b33988a616cf6a497f1c169d9e92562604e38305ccd3fc96f2252c177682")
	f.Add(xprvEntropy)

	f.Fuzz(func(t *testing.T, ent []byte) {
		if len(ent) < 64 {
			return
		}

		xprv, err := DeriveXPRV(ent[:64], nil)
		if err != nil {
			return
		}

		// Valid XPRV: verify it parses back.
		parsed, err := ParseKey(xprv)
		if err != nil {
			t.Fatalf("XPRV round-trip parse failed: %v", err)
		}
		parsed.Zero()
	})
}

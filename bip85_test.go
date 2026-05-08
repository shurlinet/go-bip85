package bip85

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

// specMasterXprv is the master key used for ALL BIP85 spec test vectors.
const specMasterXprv = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"

// --- Spec vector tests (GATE) ---

func TestSpecVector1_CoreHMAC(t *testing.T) {
	key, err := ParseKey(specMasterXprv)
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	defer key.Zero()

	path, err := ParsePath("m/83696968'/0'/0'")
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}

	dk, entropy, err := DeriveKeyAndEntropy(key, path)
	if err != nil {
		t.Fatalf("DeriveKeyAndEntropy: %v", err)
	}

	wantKey := "cca20ccb0e9a90feb0912870c3323b24874b0ca3d8018c4b96d0b97c0e82ded0"
	wantEntropy := "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"

	if got := hex.EncodeToString(dk); got != wantKey {
		t.Errorf("derived key:\n  got:  %s\n  want: %s", got, wantKey)
	}
	if got := hex.EncodeToString(entropy); got != wantEntropy {
		t.Errorf("entropy:\n  got:  %s\n  want: %s", got, wantEntropy)
	}
}

func TestSpecVector2_CoreHMAC(t *testing.T) {
	key, err := ParseKey(specMasterXprv)
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	defer key.Zero()

	path, err := ParsePath("m/83696968'/0'/1'")
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}

	dk, entropy, err := DeriveKeyAndEntropy(key, path)
	if err != nil {
		t.Fatalf("DeriveKeyAndEntropy: %v", err)
	}

	wantKey := "503776919131758bb7de7beb6c0ae24894f4ec042c26032890c29359216e21ba"
	wantEntropy := "70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e"

	if got := hex.EncodeToString(dk); got != wantKey {
		t.Errorf("derived key:\n  got:  %s\n  want: %s", got, wantKey)
	}
	if got := hex.EncodeToString(entropy); got != wantEntropy {
		t.Errorf("entropy:\n  got:  %s\n  want: %s", got, wantEntropy)
	}
}

// --- API consistency tests ---

func TestDeriveEntropy_MatchesDeriveKeyAndEntropy(t *testing.T) {
	key, err := ParseKey(specMasterXprv)
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	defer key.Zero()

	path, _ := ParsePath("m/83696968'/0'/0'")

	entropy, err := DeriveEntropy(key, path)
	if err != nil {
		t.Fatalf("DeriveEntropy: %v", err)
	}

	_, entropy2, err := DeriveKeyAndEntropy(key, path)
	if err != nil {
		t.Fatalf("DeriveKeyAndEntropy: %v", err)
	}

	if !bytes.Equal(entropy, entropy2) {
		t.Error("DeriveEntropy and DeriveKeyAndEntropy returned different entropy")
	}

	if len(entropy) != 64 {
		t.Errorf("entropy length: got %d, want 64", len(entropy))
	}
}

func TestDeriveEntropyFromString(t *testing.T) {
	path, _ := ParsePath("m/83696968'/0'/0'")

	entropy, err := DeriveEntropyFromString(specMasterXprv, path)
	if err != nil {
		t.Fatalf("DeriveEntropyFromString: %v", err)
	}

	wantEntropy := "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"
	if got := hex.EncodeToString(entropy); got != wantEntropy {
		t.Errorf("entropy:\n  got:  %s\n  want: %s", got, wantEntropy)
	}
}

// --- Leading zero regression (vector #14) ---

func TestLeadingZeroDerivedKey(t *testing.T) {
	masterXprv := "xprv9s21ZrQH143K33feVLZmQbPSTS3sF2gaBBVRk3oCtKjpmVVtuUhXy7Yt8UfQVUyqhmmJoEouLRMReJZw3n4rtQ4FJNsyE7NTghC5QFroQQ9"

	key, err := ParseKey(masterXprv)
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	defer key.Zero()

	path, _ := ParsePath("m/83696968'/0'/0'")

	dk, entropy, err := DeriveKeyAndEntropy(key, path)
	if err != nil {
		t.Fatalf("DeriveKeyAndEntropy: %v", err)
	}

	// Key starts with 0x00 - tests leading zero preservation.
	wantKey := "004085fd27c49b5b7617721f4855b6c2a1e65733499df5cc7b53916eb4782d31"
	wantEntropy := "22bfc5db7e3cf685f2f1c9d475570254198b0193f7f6603a6170aabb9480e1782b56ef536747a0f7ccefbe82d13ef46591c7370f5043ff6a1fd5a85d9f129726"

	if got := hex.EncodeToString(dk); got != wantKey {
		t.Errorf("derived key (leading zero):\n  got:  %s\n  want: %s", got, wantKey)
	}
	if got := hex.EncodeToString(entropy); got != wantEntropy {
		t.Errorf("entropy (leading zero):\n  got:  %s\n  want: %s", got, wantEntropy)
	}
}

// --- 12-word master key regression (vector #15) ---

func TestDifferentMasterKey_12Word(t *testing.T) {
	// 12-word mnemonic-derived master key from regression.json vector 15.
	masterXprv := "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"

	key, err := ParseKey(masterXprv)
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	defer key.Zero()

	// BIP39 15-word path through the core engine.
	path, _ := ParsePath("m/83696968'/39'/0'/15'/0'")

	_, entropy, err := DeriveKeyAndEntropy(key, path)
	if err != nil {
		t.Fatalf("DeriveKeyAndEntropy: %v", err)
	}

	wantEntropy := "5dc4f27a1bbcabfbed28723f2ac282194ec617dd549ac10bc0365ee77457ffb6912561ff590a85e8917326c0f6470eee3c9958b40b205d097fd341b23685201d"
	if got := hex.EncodeToString(entropy); got != wantEntropy {
		t.Errorf("entropy (12word master):\n  got:  %s\n  want: %s", got, wantEntropy)
	}
}

// --- Path parsing tests ---

func TestParsePath_Valid(t *testing.T) {
	tests := []struct {
		input   string
		wantLen int
		wantStr string
	}{
		{"m/83696968'/0'/0'", 3, "m/83696968'/0'/0'"},
		{"m/83696968h/0h/0h", 3, "m/83696968'/0'/0'"},
		{"m/83696968H/0H/0H", 3, "m/83696968'/0'/0'"},
		{"m/83696968p/0p/0p", 3, "m/83696968'/0'/0'"},
		{"m/83696968'/39'/0'/12'/0'", 5, "m/83696968'/39'/0'/12'/0'"},
		{"  m/83696968'/0'/0'  ", 3, "m/83696968'/0'/0'"},
		{"m/83696968'/128169'/64'/0'", 4, "m/83696968'/128169'/64'/0'"},
		{"m/83696968'/128169'/32'/2147483647'", 4, "m/83696968'/128169'/32'/2147483647'"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			p, err := ParsePath(tt.input)
			if err != nil {
				t.Fatalf("ParsePath(%q): %v", tt.input, err)
			}
			if p.Len() != tt.wantLen {
				t.Errorf("Len: got %d, want %d", p.Len(), tt.wantLen)
			}
			if p.String() != tt.wantStr {
				t.Errorf("String: got %q, want %q", p.String(), tt.wantStr)
			}
		})
	}
}

func TestParsePath_Invalid(t *testing.T) {
	tests := []struct {
		input   string
		wantErr error
	}{
		{"", ErrInvalidPath},
		{"m/", ErrInvalidPath},
		{"83696968'/0'/0'", ErrInvalidPath},
		{"m/83696968'/0'/0", ErrNonHardenedComponent},
		{"m/83696968/0'/0'", ErrNonHardenedComponent},
		{"m/44'/0'/0'", ErrInvalidPath},
		{"m/83696968'", ErrIncompletePath},
		{"m/83696968'/0'/abc'", ErrInvalidPath},
		{"m/83696968'/0'//0'", ErrInvalidPath},
		{"m/83696968'/2147483648'", ErrInvalidPath},
		{"m/83696968'/-1'", ErrInvalidPath},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := ParsePath(tt.input)
			if err == nil {
				t.Fatalf("ParsePath(%q): expected error, got nil", tt.input)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ParsePath(%q): got %v, want %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

// --- Path builder tests ---

func TestPathBuilders(t *testing.T) {
	tests := []struct {
		name    string
		path    Path
		wantStr string
		wantLen int
	}{
		{"CorePath", CorePath(0, 0), "m/83696968'/0'/0'", 3},
		{"BIP39Path", BIP39Path(0, 12, 0), "m/83696968'/39'/0'/12'/0'", 5},
		{"WIFPath", WIFPath(0), "m/83696968'/2'/0'", 3},
		{"XPRVPath", XPRVPath(0), "m/83696968'/32'/0'", 3},
		{"HexPath", HexPath(32, 0), "m/83696968'/128169'/32'/0'", 4},
		{"Base64Path", Base64Path(21, 0), "m/83696968'/707764'/21'/0'", 4},
		{"Base85Path", Base85Path(12, 0), "m/83696968'/707785'/12'/0'", 4},
		{"RSAPath", RSAPath(2048, 0), "m/83696968'/828365'/2048'/0'", 4},
		{"DicePath", DicePath(6, 10, 0), "m/83696968'/89101'/6'/10'/0'", 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.path.String() != tt.wantStr {
				t.Errorf("String: got %q, want %q", tt.path.String(), tt.wantStr)
			}
			if tt.path.Len() != tt.wantLen {
				t.Errorf("Len: got %d, want %d", tt.path.Len(), tt.wantLen)
			}
		})
	}
}

func TestPathBuilders_E2E(t *testing.T) {
	// Verify that path builders produce entropy matching ParsePath paths.
	key, err := ParseKey(specMasterXprv)
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	defer key.Zero()

	built := CorePath(0, 0)
	parsed, _ := ParsePath("m/83696968'/0'/0'")

	e1, err := DeriveEntropy(key, built)
	if err != nil {
		t.Fatalf("DeriveEntropy(built): %v", err)
	}
	e2, err := DeriveEntropy(key, parsed)
	if err != nil {
		t.Fatalf("DeriveEntropy(parsed): %v", err)
	}
	if !bytes.Equal(e1, e2) {
		t.Error("built path and parsed path produce different entropy")
	}
}

// --- Error path tests ---

func TestDeriveEntropy_NilKey(t *testing.T) {
	path, _ := ParsePath("m/83696968'/0'/0'")
	_, err := DeriveEntropy(nil, path)
	if !errors.Is(err, ErrNilKey) {
		t.Errorf("got: %v, want: %v", err, ErrNilKey)
	}
}

func TestDeriveEntropy_PublicKey(t *testing.T) {
	xpub := "xpub661MyMwAqRbcEpFyaVwRcfeeAtFKbH3UnesyJDSbkBQw15pyoHMA6bTEcsSY1NQ8Yxfme29GEXRdj9fWwnPrAG7wX9VbT3GUh9d4GMhawAT"
	_, err := ParseKey(xpub)
	if !errors.Is(err, ErrPublicKeyNotAllowed) {
		t.Errorf("got: %v, want: %v", err, ErrPublicKeyNotAllowed)
	}
}

func TestDeriveEntropy_EmptyKey(t *testing.T) {
	_, err := ParseKey("")
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("got: %v, want: %v", err, ErrInvalidKey)
	}
}

func TestDeriveEntropy_InvalidXprv(t *testing.T) {
	_, err := ParseKey("xprv_clearly_invalid_string")
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("got: %v, want: %v", err, ErrInvalidKey)
	}
}

func TestDeriveEntropy_WhitespaceXprv(t *testing.T) {
	path, _ := ParsePath("m/83696968'/0'/0'")
	// Whitespace-padded xprv should parse identically.
	entropy1, err := DeriveEntropyFromString(specMasterXprv, path)
	if err != nil {
		t.Fatal(err)
	}
	entropy2, err := DeriveEntropyFromString("  "+specMasterXprv+"  \n", path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(entropy1, entropy2) {
		t.Error("whitespace-trimmed xprv produced different entropy")
	}
}

// --- Property tests ---

func TestDeriveEntropy_Determinism(t *testing.T) {
	key, err := ParseKey(specMasterXprv)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Zero()

	path, _ := ParsePath("m/83696968'/0'/0'")

	e1, err := DeriveEntropy(key, path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	e2, err := DeriveEntropy(key, path)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	if !bytes.Equal(e1, e2) {
		t.Error("not deterministic: same input produced different output")
	}
}

func TestDeriveEntropy_IndexIndependence(t *testing.T) {
	key, err := ParseKey(specMasterXprv)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Zero()

	p0, _ := ParsePath("m/83696968'/0'/0'")
	p1, _ := ParsePath("m/83696968'/0'/1'")

	e0, err := DeriveEntropy(key, p0)
	if err != nil {
		t.Fatalf("index 0: %v", err)
	}
	e1, err := DeriveEntropy(key, p1)
	if err != nil {
		t.Fatalf("index 1: %v", err)
	}

	if bytes.Equal(e0, e1) {
		t.Error("different indexes produced identical entropy")
	}
}

func TestDeriveEntropy_AppIndependence(t *testing.T) {
	key, err := ParseKey(specMasterXprv)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Zero()

	p39, _ := ParsePath("m/83696968'/39'/0'/12'/0'")
	p2, _ := ParsePath("m/83696968'/2'/0'")

	e39, err := DeriveEntropy(key, p39)
	if err != nil {
		t.Fatalf("app 39: %v", err)
	}
	e2, err := DeriveEntropy(key, p2)
	if err != nil {
		t.Fatalf("app 2: %v", err)
	}

	if bytes.Equal(e39, e2) {
		t.Error("different app codes produced identical entropy")
	}
}

// --- secp256k1 validation tests ---

func TestValidateSecp256k1Key(t *testing.T) {
	// Valid key (from spec vector 1).
	validKey, _ := hex.DecodeString("cca20ccb0e9a90feb0912870c3323b24874b0ca3d8018c4b96d0b97c0e82ded0")
	if err := ValidateSecp256k1Key(validKey); err != nil {
		t.Errorf("valid key rejected: %v", err)
	}

	// Zero key.
	zeroKey := make([]byte, 32)
	if err := ValidateSecp256k1Key(zeroKey); !errors.Is(err, ErrInvalidKeyRange) {
		t.Errorf("zero key: got %v, want ErrInvalidKeyRange", err)
	}

	// Key >= curve order.
	orderKey, _ := hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	if err := ValidateSecp256k1Key(orderKey); !errors.Is(err, ErrInvalidKeyRange) {
		t.Errorf("order key: got %v, want ErrInvalidKeyRange", err)
	}

	// Wrong length.
	if err := ValidateSecp256k1Key([]byte{0x01}); !errors.Is(err, ErrInvalidKeyRange) {
		t.Errorf("short key: got %v, want ErrInvalidKeyRange", err)
	}
}

// --- Option tests ---

func TestWithHMACKey_Nil(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()
	path, _ := ParsePath("m/83696968'/0'/0'")

	_, err := DeriveEntropy(key, path, WithHMACKey(nil))
	if !errors.Is(err, ErrInvalidHMACKey) {
		t.Errorf("got: %v, want: %v", err, ErrInvalidHMACKey)
	}
}

func TestWithHMACKey_Empty(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()
	path, _ := ParsePath("m/83696968'/0'/0'")

	_, err := DeriveEntropy(key, path, WithHMACKey([]byte{}))
	if !errors.Is(err, ErrInvalidHMACKey) {
		t.Errorf("got: %v, want: %v", err, ErrInvalidHMACKey)
	}
}

func TestWithHMACKey_Custom(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()
	path, _ := ParsePath("m/83696968'/0'/0'")

	// Custom HMAC key should produce different entropy.
	standard, err := DeriveEntropy(key, path)
	if err != nil {
		t.Fatalf("standard: %v", err)
	}
	custom, err := DeriveEntropy(key, path, WithHMACKey([]byte("custom-key")))
	if err != nil {
		t.Fatalf("custom HMAC key: %v", err)
	}
	if bytes.Equal(standard, custom) {
		t.Error("custom HMAC key produced identical entropy to standard")
	}
}

func TestWithPostProcessor_TooShort(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()
	path, _ := ParsePath("m/83696968'/0'/0'")

	short := func(entropy []byte) ([]byte, error) {
		return entropy[:32], nil
	}

	_, err := DeriveEntropy(key, path, WithEntropyPostProcessor(short))
	if !errors.Is(err, ErrPostProcessorShort) {
		t.Errorf("got: %v, want: %v", err, ErrPostProcessorShort)
	}
}

func TestWithPostProcessor_Valid(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()
	path, _ := ParsePath("m/83696968'/0'/0'")

	// Post-processor that prepends a marker byte.
	pp := func(entropy []byte) ([]byte, error) {
		out := make([]byte, len(entropy)+1)
		out[0] = 0xFF
		copy(out[1:], entropy)
		return out, nil
	}

	result, err := DeriveEntropy(key, path, WithEntropyPostProcessor(pp))
	if err != nil {
		t.Fatalf("valid post-processor: %v", err)
	}
	if result[0] != 0xFF {
		t.Error("post-processor output not used")
	}
	if len(result) != 65 {
		t.Errorf("length: got %d, want 65", len(result))
	}
}

// --- Custom deriver tests ---

func TestWithCustomDeriver(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()
	path, _ := ParsePath("m/83696968'/0'/0'")

	// Custom deriver that returns a fixed 32-byte key.
	fixedKey := make([]byte, 32)
	fixedKey[0] = 0x42
	deriver := func(_ *hdkeychain.ExtendedKey, _ Path) ([]byte, error) {
		out := make([]byte, 32)
		copy(out, fixedKey)
		return out, nil
	}

	entropy, err := DeriveEntropy(key, path, WithCustomDeriver(deriver))
	if err != nil {
		t.Fatalf("custom deriver: %v", err)
	}
	if len(entropy) != 64 {
		t.Errorf("entropy length: got %d, want 64", len(entropy))
	}

	// Must differ from standard derivation.
	standard, sErr := DeriveEntropy(key, path)
	if sErr != nil {
		t.Fatalf("standard derivation: %v", sErr)
	}
	if bytes.Equal(entropy, standard) {
		t.Error("custom deriver produced same entropy as standard")
	}

	// DeriveKeyAndEntropy with custom deriver should return the fixed key.
	dk, _, err := DeriveKeyAndEntropy(key, path, WithCustomDeriver(deriver))
	if err != nil {
		t.Fatalf("DeriveKeyAndEntropy custom: %v", err)
	}
	if !bytes.Equal(dk, fixedKey) {
		t.Error("DeriveKeyAndEntropy did not return the custom deriver's key")
	}
}

func TestWithCustomDeriver_EmptyReturn(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()
	path, _ := ParsePath("m/83696968'/0'/0'")

	deriver := func(_ *hdkeychain.ExtendedKey, _ Path) ([]byte, error) {
		return nil, nil
	}

	_, err := DeriveEntropy(key, path, WithCustomDeriver(deriver))
	if !errors.Is(err, ErrEmptyKeyMaterial) {
		t.Errorf("got: %v, want: %v", err, ErrEmptyKeyMaterial)
	}
}

func TestWithCustomDeriver_Error(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()
	path, _ := ParsePath("m/83696968'/0'/0'")

	deriver := func(_ *hdkeychain.ExtendedKey, _ Path) ([]byte, error) {
		return nil, errors.New("deriver failed")
	}

	_, err := DeriveEntropy(key, path, WithCustomDeriver(deriver))
	if err == nil {
		t.Fatal("expected error from failing deriver")
	}
}

// --- ValidateSecp256k1Key edge cases ---

func TestValidateSecp256k1Key_MaxValid(t *testing.T) {
	// order - 1 is the maximum valid private key.
	orderMinus1, _ := hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")
	if err := ValidateSecp256k1Key(orderMinus1); err != nil {
		t.Errorf("order-1 should be valid: %v", err)
	}
}

func TestValidateSecp256k1Key_One(t *testing.T) {
	// 1 is the minimum valid private key.
	one := make([]byte, 32)
	one[31] = 0x01
	if err := ValidateSecp256k1Key(one); err != nil {
		t.Errorf("key=1 should be valid: %v", err)
	}
}

// --- Path builder overflow protection ---

func TestBuildPath_OverflowPanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on overflow component, got none")
		}
	}()
	// 0x80000000 exceeds hardenedMax (0x7FFFFFFF).
	// This would cause silent uint32 wrap in Derive().
	CorePath(0, 0x80000000)
}

// --- Combined option tests ---

func TestCustomDeriver_WithPostProcessor(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()
	path, _ := ParsePath("m/83696968'/0'/0'")

	fixedKey := make([]byte, 32)
	fixedKey[0] = 0x42
	deriver := func(_ *hdkeychain.ExtendedKey, _ Path) ([]byte, error) {
		out := make([]byte, 32)
		copy(out, fixedKey)
		return out, nil
	}

	pp := func(entropy []byte) ([]byte, error) {
		out := make([]byte, len(entropy)+1)
		out[0] = 0xAA
		copy(out[1:], entropy)
		return out, nil
	}

	// Custom deriver only (no post-processor).
	entropyPlain, err := DeriveEntropy(key, path, WithCustomDeriver(deriver))
	if err != nil {
		t.Fatalf("deriver only: %v", err)
	}

	// Custom deriver + post-processor.
	entropyPP, err := DeriveEntropy(key, path, WithCustomDeriver(deriver), WithEntropyPostProcessor(pp))
	if err != nil {
		t.Fatalf("deriver + post-processor: %v", err)
	}

	if len(entropyPP) != 65 {
		t.Errorf("post-processed length: got %d, want 65", len(entropyPP))
	}
	if entropyPP[0] != 0xAA {
		t.Error("post-processor marker byte not present")
	}
	// The post-processed output should contain the plain entropy shifted by 1.
	if !bytes.Equal(entropyPP[1:], entropyPlain) {
		t.Error("post-processed entropy payload does not match plain entropy")
	}

	// DeriveKeyAndEntropy with both options.
	dk, ent, err := DeriveKeyAndEntropy(key, path, WithCustomDeriver(deriver), WithEntropyPostProcessor(pp))
	if err != nil {
		t.Fatalf("DeriveKeyAndEntropy combined: %v", err)
	}
	if !bytes.Equal(dk, fixedKey) {
		t.Error("DeriveKeyAndEntropy did not return the custom key")
	}
	if !bytes.Equal(ent, entropyPP) {
		t.Error("DeriveKeyAndEntropy entropy does not match DeriveEntropy")
	}
}

// TestPostProcessor_AliasingInput verifies that a post-processor returning
// the input slice unchanged does not produce zeroed output. This is a
// regression test for a slice-aliasing bug where ZeroBytes(entropy) would
// destroy the returned processed slice if they shared the same backing array.
func TestPostProcessor_AliasingInput(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()
	path, _ := ParsePath("m/83696968'/0'/0'")

	// Post-processor that returns the input unchanged (same slice).
	noop := func(entropy []byte) ([]byte, error) {
		return entropy, nil
	}

	result, err := DeriveEntropy(key, path, WithEntropyPostProcessor(noop))
	if err != nil {
		t.Fatalf("noop post-processor: %v", err)
	}

	// The result must NOT be all zeros.
	allZero := true
	for _, b := range result {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("post-processor returning input unchanged produced all-zero output (aliasing bug)")
	}

	// Must match standard derivation.
	standard, _ := DeriveEntropy(key, path)
	if !bytes.Equal(result, standard) {
		t.Error("noop post-processor produced different entropy than standard")
	}
}

// --- Anti-tamper tests ---
// These tests verify hardcoded constants against independent sources.
// A rogue contributor changing a crypto constant would need to change
// both the constant AND these independent verifications simultaneously.

func TestHMACKey_Content(t *testing.T) {
	// Verify the HMAC key is exactly the BIP85-specified ASCII string.
	// This catches single-character mutations that pass the length check.
	want := []byte{
		0x62, 0x69, 0x70, 0x2d, 0x65, 0x6e, 0x74, 0x72, 0x6f,
		0x70, 0x79, 0x2d, 0x66, 0x72, 0x6f, 0x6d, 0x2d, 0x6b,
	} // "bip-entropy-from-k" as raw bytes
	if !bytes.Equal(hmacKeyBIP85, want) {
		t.Fatal("HMAC key content does not match BIP85 spec")
	}
}

func TestSecp256k1Order_Correct(t *testing.T) {
	// Verify our hardcoded curve order matches the btcec library.
	// Independent source: btcec computes this from the curve parameters.
	btcecOrder := btcec.S256().N
	if secp256k1Order.Cmp(btcecOrder) != 0 {
		t.Fatalf("secp256k1 order mismatch:\n  ours:  %s\n  btcec: %s",
			secp256k1Order.Text(16), btcecOrder.Text(16))
	}
}

func TestZeroBytes_ActuallyZeros(t *testing.T) {
	buf := []byte{0xFF, 0xAA, 0x55, 0x01, 0x80, 0xDE, 0xAD, 0xBE}
	ZeroBytes(buf)
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("ZeroBytes did not zero byte at index %d: got 0x%02x", i, b)
		}
	}
}

func TestZeroBytes_NilSafe(t *testing.T) {
	// Must not panic on nil slice.
	ZeroBytes(nil)
	// Must not panic on empty slice.
	ZeroBytes([]byte{})
}

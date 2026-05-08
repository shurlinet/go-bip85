package bip85

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/sha3"
)

// ========================================================================
// DICE: Spec vector (BIP85 spec v2.0.0)
// ========================================================================

func TestSpecVector_DICE(t *testing.T) {
	key, err := ParseKey(specMasterXprv)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Zero()

	path := DicePath(6, 10, 0)
	entropy, err := DeriveEntropy(key, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(entropy)

	values, formatted, err := DeriveDice(entropy, 6, 10)
	if err != nil {
		t.Fatal(err)
	}

	want := "1,0,0,2,0,1,5,5,2,4"
	if formatted != want {
		t.Errorf("DICE(6,10):\n  got:  %s\n  want: %s", formatted, want)
	}

	// Verify raw values.
	wantValues := []int{1, 0, 0, 2, 0, 1, 5, 5, 2, 4}
	if len(values) != len(wantValues) {
		t.Fatalf("values length: got %d, want %d", len(values), len(wantValues))
	}
	for i, v := range values {
		if v != wantValues[i] {
			t.Errorf("value[%d]: got %d, want %d", i, v, wantValues[i])
		}
	}

	// Verify entropy matches spec.
	wantEntropy := "5e41f8f5d5d9ac09a20b8a5797a3172b28c806aead00d27e36609e2dd116a59176a738804236586f668da8a51b90c708a4226d7f92259c69f64c51124b6f6cd2"
	if got := hex.EncodeToString(entropy); got != wantEntropy {
		t.Errorf("entropy:\n  got:  %s\n  want: %s", got, wantEntropy)
	}
}

// ========================================================================
// DICE: Cross-implementation vectors (from bipsea via vectors.json)
// ========================================================================

func TestCrossImpl_DICE(t *testing.T) {
	vf := loadVectors(t)
	tested := 0
	for _, mk := range vf.MasterKeys {
		key, err := ParseKey(mk.MasterXprv)
		if err != nil {
			t.Fatalf("%s: ParseKey: %v", mk.MasterID, err)
		}
		for _, v := range mk.Vectors {
			if v.App != "dice" {
				continue
			}
			tested++
			sides := uint32(v.Params["sides"].(float64))
			rolls := int(v.Params["rolls"].(float64))
			t.Run(fmt.Sprintf("%s/%s", mk.MasterID, v.Path), func(t *testing.T) {
				path, err := ParsePath(v.Path)
				if err != nil {
					t.Fatal(err)
				}
				entropy, err := DeriveEntropy(key, path)
				if err != nil {
					t.Fatal(err)
				}
				defer ZeroBytes(entropy)

				_, formatted, err := DeriveDice(entropy, sides, rolls)
				if err != nil {
					t.Fatal(err)
				}
				if formatted != v.Output {
					t.Errorf("DICE(%d,%d):\n  got:  %s\n  want: %s", sides, rolls, formatted, v.Output)
				}
			})
		}
		key.Zero()
	}
	if tested < 15 {
		t.Fatalf("DICE cross-impl: only tested %d vectors, expected at least 15 (vectors.json may be corrupted)", tested)
	}
}

// ========================================================================
// DICE: Smoke tests
// ========================================================================

func TestDICE_Smoke(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	configs := []struct {
		sides uint32
		rolls int
	}{
		{2, 10},
		{2, 100},
		{6, 10},
		{6, 100},
		{10, 10},
		{10, 100},
		{52, 10},
		{52, 100},
		{100, 10},
		{100, 100},
	}

	for _, cfg := range configs {
		t.Run(fmt.Sprintf("sides_%d_rolls_%d", cfg.sides, cfg.rolls), func(t *testing.T) {
			path := DicePath(cfg.sides, uint32(cfg.rolls), 0)
			entropy, err := DeriveEntropy(key, path)
			if err != nil {
				t.Fatal(err)
			}
			defer ZeroBytes(entropy)

			values, _, err := DeriveDice(entropy, cfg.sides, cfg.rolls)
			if err != nil {
				t.Fatalf("DeriveDice(%d, %d): %v", cfg.sides, cfg.rolls, err)
			}

			// Verify roll count.
			if len(values) != cfg.rolls {
				t.Errorf("roll count: got %d, want %d", len(values), cfg.rolls)
			}

			// Verify all values in range [0, sides-1].
			for i, v := range values {
				if v < 0 || v >= int(cfg.sides) {
					t.Errorf("value[%d] = %d out of range [0, %d)", i, v, cfg.sides)
				}
			}

			// Determinism: derive again, same result.
			entropy2, _ := DeriveEntropy(key, path)
			values2, _, _ := DeriveDice(entropy2, cfg.sides, cfg.rolls)
			ZeroBytes(entropy2)
			if len(values) != len(values2) {
				t.Fatal("not deterministic: different roll count")
			}
			for i := range values {
				if values[i] != values2[i] {
					t.Errorf("not deterministic: value[%d] differs", i)
					break
				}
			}
		})
	}
}

// ========================================================================
// DICE: Property tests
// ========================================================================

func TestDICE_RangeProperty(t *testing.T) {
	// For each side count, verify all roll values are in [0, sides-1]
	// across a large number of rolls.
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	for _, sides := range []uint32{2, 3, 5, 6, 8, 10, 52, 100} {
		t.Run(fmt.Sprintf("sides_%d", sides), func(t *testing.T) {
			path := DicePath(sides, 1000, 0)
			entropy, err := DeriveEntropy(key, path)
			if err != nil {
				t.Fatal(err)
			}
			defer ZeroBytes(entropy)

			values, err := DeriveRolls(entropy, sides, 1000)
			if err != nil {
				t.Fatal(err)
			}

			for i, v := range values {
				if v < 0 || v >= int(sides) {
					t.Fatalf("sides=%d: value[%d] = %d out of range [0, %d)", sides, i, v, sides)
				}
			}
		})
	}
}

func TestDICE_RejectionProperty(t *testing.T) {
	// For sides=3 (bitsPerRoll=2, 4 possible values, reject 3), verify
	// no values >= 3 appear in a large sample.
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := DicePath(3, 10000, 0)
	entropy, err := DeriveEntropy(key, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(entropy)

	values, err := DeriveRolls(entropy, 3, 10000)
	if err != nil {
		t.Fatal(err)
	}

	for i, v := range values {
		if v >= 3 {
			t.Fatalf("rejection failed: value[%d] = %d (expected < 3)", i, v)
		}
	}
}

func TestDICE_CoinFlipProperty(t *testing.T) {
	// sides=2 (coin flip): only 0 and 1 should appear.
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := DicePath(2, 10000, 0)
	entropy, err := DeriveEntropy(key, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(entropy)

	values, err := DeriveRolls(entropy, 2, 10000)
	if err != nil {
		t.Fatal(err)
	}

	for i, v := range values {
		if v != 0 && v != 1 {
			t.Fatalf("coin flip: value[%d] = %d (expected 0 or 1)", i, v)
		}
	}
}

// ========================================================================
// DICE: FormatRolls tests
// ========================================================================

func TestFormatRolls(t *testing.T) {
	tests := []struct {
		values []int
		sides  uint32
		want   string
	}{
		{[]int{1, 0, 0, 2, 0, 1, 5, 5, 2, 4}, 6, "1,0,0,2,0,1,5,5,2,4"},
		{[]int{1, 1, 1, 1, 1, 0, 1, 0, 0, 1}, 2, "1,1,1,1,1,0,1,0,0,1"},
		{[]int{81, 13, 21, 21, 23, 6, 66, 24, 99, 5}, 100, "81,13,21,21,23,06,66,24,99,05"},
		{nil, 6, ""},
		{[]int{}, 6, ""},
	}

	for _, tt := range tests {
		got := FormatRolls(tt.values, tt.sides)
		if got != tt.want {
			t.Errorf("FormatRolls(%v, %d): got %q, want %q", tt.values, tt.sides, got, tt.want)
		}
	}
}

func TestFormatRolls_SidesZero(t *testing.T) {
	// sides=0 would cause uint32 underflow (maxVal = 0 - 1 = 4294967295)
	// without the guard. Verify the guard produces sane output.
	got := FormatRolls([]int{0}, 0)
	if got != "0" {
		t.Errorf("FormatRolls([]int{0}, 0): got %q, want %q", got, "0")
	}
}

func TestFormatRolls_ZeroPadding(t *testing.T) {
	// sides=1000: max value is 999, width is 3.
	values := []int{0, 1, 42, 999}
	got := FormatRolls(values, 1000)
	want := "000,001,042,999"
	if got != want {
		t.Errorf("FormatRolls zero-pad: got %q, want %q", got, want)
	}
}

// ========================================================================
// DICE: Error path tests
// ========================================================================

func TestDICE_InvalidSides(t *testing.T) {
	entropy := make([]byte, 64)
	for _, sides := range []uint32{0, 1} {
		_, err := DeriveRolls(entropy, sides, 10)
		if !errors.Is(err, ErrInvalidDiceSides) {
			t.Errorf("sides=%d: got %v, want ErrInvalidDiceSides", sides, err)
		}
	}
}

func TestDICE_InvalidRolls(t *testing.T) {
	entropy := make([]byte, 64)
	for _, rolls := range []int{0, -1, -100} {
		_, err := DeriveRolls(entropy, 6, rolls)
		if !errors.Is(err, ErrInvalidDiceRolls) {
			t.Errorf("rolls=%d: got %v, want ErrInvalidDiceRolls", rolls, err)
		}
	}

	// On 64-bit platforms, test rolls exceeding the spec max (2^32-1).
	// On 32-bit, int can't represent this value so the test is skipped.
	// Use a variable to prevent compile-time constant overflow on 32-bit.
	maxRolls := int64(DiceMaxSides)
	if int64(^uint(0)>>1) > maxRolls {
		overflow := int(maxRolls + 1)
		_, err := DeriveRolls(entropy, 6, overflow)
		if !errors.Is(err, ErrInvalidDiceRolls) {
			t.Errorf("rolls=%d: got %v, want ErrInvalidDiceRolls", overflow, err)
		}
	}
}

func TestDICE_ShortEntropy(t *testing.T) {
	_, err := DeriveRolls(make([]byte, 63), 6, 10)
	if !errors.Is(err, ErrInvalidLength) {
		t.Errorf("got %v, want ErrInvalidLength", err)
	}
}

func TestDICE_NilEntropy(t *testing.T) {
	_, err := DeriveRolls(nil, 6, 10)
	if !errors.Is(err, ErrInvalidLength) {
		t.Errorf("got %v, want ErrInvalidLength", err)
	}
}

// ========================================================================
// DICE: Entropy copy isolation
// ========================================================================

func TestEntropyCopyIsolation_Dice(t *testing.T) {
	entropy := make([]byte, 64)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	original := make([]byte, 64)
	copy(original, entropy)

	_, _, err := DeriveDice(entropy, 6, 10)
	if err != nil {
		t.Fatal(err)
	}

	for i := range entropy {
		if entropy[i] != original[i] {
			t.Fatal("DeriveDice modified the input entropy slice")
		}
	}
}

// ========================================================================
// DICE: Regression vectors (hardcoded, survive JSON corruption)
// ========================================================================

func TestRegression_DICE_SpecVector(t *testing.T) {
	// regression_id 11: DICE 6 sides, 10 rolls, index 0.
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := DicePath(6, 10, 0)
	entropy, _ := DeriveEntropy(key, path)
	defer ZeroBytes(entropy)

	_, formatted, err := DeriveDice(entropy, 6, 10)
	if err != nil {
		t.Fatal(err)
	}

	want := "1,0,0,2,0,1,5,5,2,4"
	if formatted != want {
		t.Errorf("DICE regression:\n  got:  %s\n  want: %s", formatted, want)
	}
}

func TestRegression_DICE_CoinFlip(t *testing.T) {
	// regression_id 19: DICE 2 sides, 20 rolls, index 0 (coin flip).
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := DicePath(2, 20, 0)
	entropy, _ := DeriveEntropy(key, path)
	defer ZeroBytes(entropy)

	_, formatted, err := DeriveDice(entropy, 2, 20)
	if err != nil {
		t.Fatal(err)
	}

	want := "1,1,1,1,1,0,1,0,0,1,0,0,1,1,0,0,0,1,1,1"
	if formatted != want {
		t.Errorf("DICE coin flip regression:\n  got:  %s\n  want: %s", formatted, want)
	}
}

func TestRegression_DICE_100Sides(t *testing.T) {
	// Cross-impl: DICE 100 sides, 10 rolls, index 0, spec master key.
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := DicePath(100, 10, 0)
	entropy, _ := DeriveEntropy(key, path)
	defer ZeroBytes(entropy)

	_, formatted, err := DeriveDice(entropy, 100, 10)
	if err != nil {
		t.Fatal(err)
	}

	want := "81,13,21,21,23,06,66,24,99,05"
	if formatted != want {
		t.Errorf("DICE 100 sides regression:\n  got:  %s\n  want: %s", formatted, want)
	}
}

func TestRegression_DICE_Index1(t *testing.T) {
	// Cross-impl vector: DICE 6 sides, 10 rolls, index 1, spec master key.
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := DicePath(6, 10, 1)
	entropy, _ := DeriveEntropy(key, path)
	defer ZeroBytes(entropy)

	_, formatted, err := DeriveDice(entropy, 6, 10)
	if err != nil {
		t.Fatal(err)
	}

	want := "1,0,0,3,3,0,4,3,3,0"
	if formatted != want {
		t.Errorf("DICE index 1 regression:\n  got:  %s\n  want: %s", formatted, want)
	}
}

// ========================================================================
// DICE: DeriveDice convenience function
// ========================================================================

func TestDeriveDice_ReturnsRawAndFormatted(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := DicePath(6, 10, 0)
	entropy, _ := DeriveEntropy(key, path)
	defer ZeroBytes(entropy)

	values, formatted, err := DeriveDice(entropy, 6, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Verify consistency between raw and formatted.
	parts := strings.Split(formatted, ",")
	if len(parts) != len(values) {
		t.Fatalf("parts=%d, values=%d", len(parts), len(values))
	}
	for i, part := range parts {
		v, err := strconv.Atoi(part)
		if err != nil {
			t.Fatalf("part %d: %v", i, err)
		}
		if v != values[i] {
			t.Errorf("part[%d] = %d, values[%d] = %d", i, v, i, values[i])
		}
	}
}

// ========================================================================
// DICE: Independent oracle (anti-tamper / anti-AI-sabotage)
//
// This test reimplements the DICE algorithm from scratch without calling
// DeriveRolls, then verifies the result matches. If a rogue contributor
// (human or AI) modifies DeriveRolls to produce biased or wrong output
// AND updates the spec vector expected values to match, this independent
// oracle would still catch the divergence - because the attacker would
// need to modify BOTH DeriveRolls AND this independent implementation
// simultaneously, which is far more visible in code review.
// ========================================================================

func TestDICE_IndependentOracle(t *testing.T) {
	// Step 1: derive entropy via the normal pipeline (this part is shared).
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := DicePath(6, 10, 0)
	entropy, err := DeriveEntropy(key, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(entropy)

	// Step 2: independently reimplement DICE without calling DeriveRolls.
	// This is the BIP85 DICE algorithm from the spec, coded inline.
	sides := uint32(6)
	rolls := 10
	bitsNeeded := 0 // ceil(log2(sides)) via manual bit counting
	for v := sides - 1; v > 0; v >>= 1 {
		bitsNeeded++
	}
	bytesNeeded := (bitsNeeded + 7) / 8

	// Create DRNG independently (same entropy, same SHAKE256 seed).
	xof := sha3.NewShake256()
	if _, wErr := xof.Write(entropy); wErr != nil {
		t.Fatal(wErr)
	}

	var oracleResults []int
	buf := make([]byte, bytesNeeded)
	for len(oracleResults) < rolls {
		if _, rErr := xof.Read(buf); rErr != nil {
			t.Fatal(rErr)
		}
		// Big-endian assembly.
		var val uint32
		for _, b := range buf {
			val = (val << 8) | uint32(b)
		}
		// Retain MSBs.
		val >>= uint(bytesNeeded*8 - bitsNeeded)
		if val < sides {
			oracleResults = append(oracleResults, int(val))
		}
	}

	// Step 3: compare oracle results with DeriveRolls output.
	libResults, err := DeriveRolls(entropy, sides, rolls)
	if err != nil {
		t.Fatal(err)
	}

	if len(oracleResults) != len(libResults) {
		t.Fatalf("oracle produced %d rolls, library produced %d", len(oracleResults), len(libResults))
	}
	for i := range oracleResults {
		if oracleResults[i] != libResults[i] {
			t.Errorf("roll %d: oracle=%d, library=%d", i, oracleResults[i], libResults[i])
		}
	}

	// Step 4: verify both match the spec vector.
	wantFormatted := "1,0,0,2,0,1,5,5,2,4"
	gotFormatted := FormatRolls(libResults, sides)
	if gotFormatted != wantFormatted {
		t.Errorf("formatted output:\n  got:  %s\n  want: %s", gotFormatted, wantFormatted)
	}
}

// ========================================================================
// DICE: bits.Len verification (anti-tamper for integer log2)
// ========================================================================

func TestBitsLen_KnownValues(t *testing.T) {
	// Verify bits.Len produces the correct bitsPerRoll for known sides.
	tests := []struct {
		sides       uint32
		wantBitsLen int
	}{
		{2, 1},   // log2(1) = 0 bits -> bits.Len(1) = 1
		{3, 2},   // log2(2) = 1 bits -> bits.Len(2) = 2
		{4, 2},   // log2(3) = ~1.6 -> bits.Len(3) = 2
		{5, 3},   // bits.Len(4) = 3
		{6, 3},   // bits.Len(5) = 3
		{7, 3},   // bits.Len(6) = 3
		{8, 3},   // bits.Len(7) = 3
		{9, 4},   // bits.Len(8) = 4
		{16, 4},  // bits.Len(15) = 4
		{17, 5},  // bits.Len(16) = 5
		{100, 7}, // bits.Len(99) = 7
		{256, 8}, // bits.Len(255) = 8
	}

	for _, tt := range tests {
		// Independent verification via string formatting.
		binaryLen := len(strconv.FormatUint(uint64(tt.sides-1), 2))
		if binaryLen != tt.wantBitsLen {
			t.Errorf("sides=%d: binary string length = %d, want %d", tt.sides, binaryLen, tt.wantBitsLen)
		}
		// Cross-check against the actual bits.Len function used in DeriveRolls.
		bitsLen := bits.Len(uint(tt.sides - 1))
		if bitsLen != tt.wantBitsLen {
			t.Errorf("sides=%d: bits.Len = %d, want %d", tt.sides, bitsLen, tt.wantBitsLen)
		}
	}
}

package bip85

import (
	"fmt"
	"math/bits"
	"strconv"
	"strings"
)

const (
	// DiceMinSides is the minimum number of sides for the DICE application.
	DiceMinSides = 2
	// DiceMaxSides is the maximum number of sides for the DICE application (2^32 - 1).
	DiceMaxSides uint32 = 1<<32 - 1

	// diceMaxRejections is the safety cap for rejection sampling. With a
	// properly seeded SHAKE256 DRNG this should never be reached.
	diceMaxRejections = 10000
)

// DeriveRolls derives a DICE application result from BIP85 entropy.
//
// Roll values are zero-indexed: an N-sided die produces values in [0, N-1].
// The DRNG is seeded with the 64-byte entropy, then rejection sampling
// produces each roll by reading the minimum number of bytes, retaining
// the most significant bits, and discarding values >= sides.
//
// sides must be in [2, 2^32-1]. rolls must be in [1, 2^32-1].
//
// Path: m/83696968'/89101'/{sides}'/{rolls}'/{index}'.
func DeriveRolls(entropy []byte, sides uint32, rolls int) ([]int, error) {
	if sides < DiceMinSides {
		return nil, fmt.Errorf("%w: sides must be >= %d, got %d", ErrInvalidDiceSides, DiceMinSides, sides)
	}
	if rolls < 1 || int64(rolls) > int64(DiceMaxSides) {
		return nil, fmt.Errorf("%w: rolls must be in [1, %d], got %d", ErrInvalidDiceRolls, DiceMaxSides, rolls)
	}
	if len(entropy) < 64 {
		return nil, fmt.Errorf("%w: entropy too short for dice rolls", ErrInvalidLength)
	}

	// Work on a copy to avoid modifying the caller's entropy slice.
	ent := make([]byte, 64)
	copy(ent, entropy[:64])
	defer ZeroBytes(ent)

	drng := NewDRNG(ent)

	// Integer math for bits per roll - no floating point in crypto.
	bitsPerRoll := bits.Len(uint(sides - 1))
	if bitsPerRoll == 0 {
		// sides == 1 is already rejected above, but guard defensively.
		return nil, fmt.Errorf("%w: sides must be >= %d", ErrInvalidDiceSides, DiceMinSides)
	}
	bytesPerRoll := (bitsPerRoll + 7) / 8 // integer ceiling division

	// Cap pre-allocation to avoid a single massive allocation for
	// very large rolls values. Go's slice growth handles the rest.
	prealloc := rolls
	if prealloc > 1024 {
		prealloc = 1024
	}
	result := make([]int, 0, prealloc)
	buf := make([]byte, bytesPerRoll)
	defer ZeroBytes(buf) // buf holds DRNG output derived from secret entropy.

	for len(result) < rolls {
		rejections := 0
		for {
			if rejections >= diceMaxRejections {
				return nil, fmt.Errorf("bip85: dice rejection sampling exceeded %d attempts (entropy source may be degenerate)", diceMaxRejections)
			}

			n, err := drng.Read(buf)
			if err != nil {
				return nil, fmt.Errorf("bip85: DRNG read failed: %w", err)
			}
			if n != bytesPerRoll {
				return nil, fmt.Errorf("bip85: DRNG read returned %d bytes, expected %d", n, bytesPerRoll)
			}

			// Interpret bytes as big-endian integer.
			var val uint32
			for _, b := range buf {
				val = (val << 8) | uint32(b)
			}

			// Retain only the most significant bitsPerRoll bits.
			// The excess bits are at the low end.
			totalBits := bytesPerRoll * 8
			excessBits := totalBits - bitsPerRoll
			if excessBits < 0 {
				return nil, fmt.Errorf("bip85: dice internal error: negative excess bits %d (bytesPerRoll=%d, bitsPerRoll=%d)", excessBits, bytesPerRoll, bitsPerRoll)
			}
			val >>= uint(excessBits)

			if val < sides {
				result = append(result, int(val))
				break
			}
			rejections++
		}
	}

	return result, nil
}

// FormatRolls formats dice roll values as a comma-separated string.
// Values are zero-padded to the width of (sides-1) for readability
// when sides >= 10.
func FormatRolls(rollValues []int, sides uint32) string {
	if len(rollValues) == 0 {
		return ""
	}
	if sides == 0 {
		sides = 1 // Prevent uint32 underflow in maxVal calculation.
	}

	// Compute the zero-padding width from the maximum possible value.
	maxVal := sides - 1
	width := len(strconv.FormatUint(uint64(maxVal), 10))

	var b strings.Builder
	for i, v := range rollValues {
		if i > 0 {
			b.WriteByte(',')
		}
		s := strconv.Itoa(v)
		// Zero-pad to width.
		for j := len(s); j < width; j++ {
			b.WriteByte('0')
		}
		b.WriteString(s)
	}
	return b.String()
}

// DeriveDice derives formatted dice rolls from BIP85 entropy.
// This is a convenience function that calls DeriveRolls and FormatRolls.
//
// Returns both the raw roll values and the formatted string.
func DeriveDice(entropy []byte, sides uint32, rolls int) (values []int, formatted string, err error) {
	values, err = DeriveRolls(entropy, sides, rolls)
	if err != nil {
		return nil, "", err
	}
	formatted = FormatRolls(values, sides)
	return values, formatted, nil
}

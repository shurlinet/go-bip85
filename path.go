package bip85

import (
	"fmt"
	"strconv"
	"strings"
)

// purposeCode is the BIP85 magic number used as the first hardened component
// in every BIP85 derivation path: m/83696968'/...
const purposeCode uint32 = 83696968

// BIP85 application codes as defined in the specification.
// These are used as the second hardened component in derivation paths.
const (
	AppBIP39  uint32 = 39     // BIP39 mnemonic derivation
	AppWIF    uint32 = 2      // HD-Seed WIF (compressed private key)
	AppXPRV   uint32 = 32     // BIP32 extended private key
	AppHex    uint32 = 128169 // Raw hex entropy (16-64 bytes)
	AppBase64 uint32 = 707764 // Base64-encoded password (20-86 chars)
	AppBase85 uint32 = 707785 // RFC 1924 Base85-encoded password (10-80 chars)
	AppRSA    uint32 = 828365 // RSA key generation via DRNG
	AppDice   uint32 = 89101  // Dice roll generation via rejection sampling
)

// Path represents a validated BIP85 derivation path. All components are
// hardened. The purpose code (83696968') is always the first component.
//
// A Path is immutable after construction. It is safe for concurrent use.
type Path struct {
	// components stores the raw (un-hardened) values.
	// components[0] is always purposeCode (83696968).
	components []uint32
}

// ParsePath parses a BIP85 derivation path string. The path must start with
// "m/83696968'" and all components must be hardened (marked with ', h, H, or p).
//
// Accepted formats:
//
//	m/83696968'/0'/0'
//	m/83696968h/0h/0h
//	m/83696968H/0H/0H
//	m/83696968p/0p/0p
func ParsePath(s string) (Path, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Path{}, ErrInvalidPath
	}

	if !strings.HasPrefix(s, "m/") {
		return Path{}, fmt.Errorf("%w: must start with \"m/\"", ErrInvalidPath)
	}
	rest := s[2:]
	if rest == "" {
		return Path{}, fmt.Errorf("%w: empty path after \"m/\"", ErrInvalidPath)
	}

	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		return Path{}, fmt.Errorf("%w: BIP85 path requires at least purpose and one more component", ErrIncompletePath)
	}

	components := make([]uint32, 0, len(parts))
	for i, part := range parts {
		if part == "" {
			return Path{}, fmt.Errorf("%w: empty component at position %d", ErrInvalidPath, i)
		}

		trimmed, hardened := stripHardenedMarker(part)
		if !hardened {
			return Path{}, fmt.Errorf("%w: component %q at position %d is not hardened", ErrNonHardenedComponent, part, i)
		}

		val, err := strconv.ParseUint(trimmed, 10, 31)
		if err != nil {
			return Path{}, fmt.Errorf("%w: invalid component %q at position %d", ErrInvalidPath, part, i)
		}
		components = append(components, uint32(val))
	}

	if components[0] != purposeCode {
		return Path{}, fmt.Errorf("%w: first component must be %d' (BIP85 purpose), got %d'", ErrInvalidPath, purposeCode, components[0])
	}

	return Path{components: components}, nil
}

// stripHardenedMarker returns the numeric part and whether a hardened marker
// was found. Accepts ', h, H, p as hardened markers.
func stripHardenedMarker(s string) (string, bool) {
	if len(s) == 0 {
		return s, false
	}
	last := s[len(s)-1]
	switch last {
	case '\'', 'h', 'H', 'p':
		return s[:len(s)-1], true
	default:
		return s, false
	}
}

// Components returns the raw (un-hardened) path component values.
// The returned slice is a copy.
func (p Path) Components() []uint32 {
	out := make([]uint32, len(p.components))
	copy(out, p.components)
	return out
}

// String returns the canonical string form of the path using the '
// hardened marker (e.g. "m/83696968'/0'/0'").
func (p Path) String() string {
	var b strings.Builder
	b.WriteString("m")
	for _, c := range p.components {
		b.WriteByte('/')
		b.WriteString(strconv.FormatUint(uint64(c), 10))
		b.WriteByte('\'')
	}
	return b.String()
}

// Len returns the number of components (including the purpose code).
func (p Path) Len() int {
	return len(p.components)
}

// CorePath returns a path for direct BIP85 derivation without a registered
// application: m/83696968'/{appCode}'/{index}'. Use the application-specific
// builders (BIP39Path, WIFPath, etc.) for standard BIP85 applications.
func CorePath(appCode, index uint32) Path {
	return buildPath(appCode, index)
}

// BIP39Path returns: m/83696968'/39'/{language}'/{words}'/{index}'.
func BIP39Path(language, words, index uint32) Path {
	return buildPath(AppBIP39, language, words, index)
}

// WIFPath returns: m/83696968'/2'/{index}'.
func WIFPath(index uint32) Path {
	return buildPath(AppWIF, index)
}

// XPRVPath returns: m/83696968'/32'/{index}'.
func XPRVPath(index uint32) Path {
	return buildPath(AppXPRV, index)
}

// HexPath returns: m/83696968'/128169'/{numBytes}'/{index}'.
func HexPath(numBytes, index uint32) Path {
	return buildPath(AppHex, numBytes, index)
}

// Base64Path returns: m/83696968'/707764'/{pwdLen}'/{index}'.
func Base64Path(pwdLen, index uint32) Path {
	return buildPath(AppBase64, pwdLen, index)
}

// Base85Path returns: m/83696968'/707785'/{pwdLen}'/{index}'.
func Base85Path(pwdLen, index uint32) Path {
	return buildPath(AppBase85, pwdLen, index)
}

// RSAPath returns: m/83696968'/828365'/{keyBits}'/{keyIndex}'.
func RSAPath(keyBits, keyIndex uint32) Path {
	return buildPath(AppRSA, keyBits, keyIndex)
}

// DicePath returns: m/83696968'/89101'/{sides}'/{rolls}'/{index}'.
func DicePath(sides, rolls, index uint32) Path {
	return buildPath(AppDice, sides, rolls, index)
}

// hardenedMax is the maximum allowed value for a hardened path component.
// Values above this would overflow when added to HardenedKeyStart (0x80000000).
const hardenedMax uint32 = 0x7FFFFFFF // 2^31 - 1

// buildPath constructs a Path from purpose + appCode + extra components.
// Panics if any component exceeds hardenedMax (2^31-1), which would cause
// silent uint32 overflow during BIP32 derivation.
func buildPath(appCode uint32, extra ...uint32) Path {
	components := make([]uint32, 0, 2+len(extra))
	components = append(components, purposeCode, appCode)
	components = append(components, extra...)
	for _, c := range components {
		if c > hardenedMax {
			panic(fmt.Sprintf("bip85: path component %d exceeds maximum %d", c, hardenedMax))
		}
	}
	return Path{components: components}
}

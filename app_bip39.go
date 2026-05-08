package bip85

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// BIP39 language codes as defined in the BIP85 spec.
const (
	LangEnglish            uint32 = 0
	LangJapanese           uint32 = 1
	LangKorean             uint32 = 2
	LangSpanish            uint32 = 3
	LangChineseSimplified  uint32 = 4
	LangChineseTraditional uint32 = 5
	LangFrench             uint32 = 6
	LangItalian            uint32 = 7
	LangCzech              uint32 = 8
	LangPortuguese         uint32 = 9
)

// wordCountToBytes maps valid BIP39 word counts to entropy byte lengths.
// Lookup table avoids formula ambiguity.
var wordCountToBytes = map[int]int{
	12: 16,
	15: 20,
	18: 24,
	21: 28,
	24: 32,
}

//go:embed wordlists/english.txt
var wordlistEnglish string

//go:embed wordlists/japanese.txt
var wordlistJapanese string

//go:embed wordlists/korean.txt
var wordlistKorean string

//go:embed wordlists/spanish.txt
var wordlistSpanish string

//go:embed wordlists/chinese_simplified.txt
var wordlistChineseSimplified string

//go:embed wordlists/chinese_traditional.txt
var wordlistChineseTraditional string

//go:embed wordlists/french.txt
var wordlistFrench string

//go:embed wordlists/italian.txt
var wordlistItalian string

//go:embed wordlists/czech.txt
var wordlistCzech string

//go:embed wordlists/portuguese.txt
var wordlistPortuguese string

// wordlistSHA256 maps language code -> expected SHA256 hex of the raw
// embedded file content. These are computed from the official BIP39
// wordlists in bitcoin/bips repository.
var wordlistSHA256 = map[uint32]string{
	LangEnglish:            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
	LangJapanese:           "2eed0aef492291e061633d7ad8117f1a2b03eb80a29d0e4e3117ac2528d05ffd",
	LangKorean:             "9e95f86c167de88f450f0aaf89e87f6624a57f973c67b516e338e8e8b8897f60",
	LangSpanish:            "46846a5a0139d1e3cb77293e521c2865f7bcdb82c44e8d0a06a2cd0ecba48c0b",
	LangChineseSimplified:  "5c5942792bd8340cb8b27cd592f1015edf56a8c5b26276ee18a482428e7c5726",
	LangChineseTraditional: "417b26b3d8500a4ae3d59717d7011952db6fc2fb84b807f3f94ac734e89c1b5f",
	LangFrench:             "ebc3959ab7801a1df6bac4fa7d970652f1df76b683cd2f4003c941c63d517e59",
	LangItalian:            "d392c49fdb700a24cd1fceb237c1f65dcc128f6b34a8aacb58b59384b5c648c2",
	LangCzech:              "7e80e161c3e93d9554c2efb78d4e3cebf8fc727e9c52e03b83b94406bdcc95fc",
	LangPortuguese:         "2685e9c194c82ae67e10ba59d9ea5345a23dc093e92276fc5361f6667d79cd3f",
}

// wordlistEntry holds the raw embedded content and parsed words for one language.
type wordlistEntry struct {
	raw   string   // raw embedded file content
	words []string // parsed words, 2048 entries
}

var (
	wordlistEntries = map[uint32]*wordlistEntry{
		LangEnglish:            {raw: wordlistEnglish},
		LangJapanese:           {raw: wordlistJapanese},
		LangKorean:             {raw: wordlistKorean},
		LangSpanish:            {raw: wordlistSpanish},
		LangChineseSimplified:  {raw: wordlistChineseSimplified},
		LangChineseTraditional: {raw: wordlistChineseTraditional},
		LangFrench:             {raw: wordlistFrench},
		LangItalian:            {raw: wordlistItalian},
		LangCzech:              {raw: wordlistCzech},
		LangPortuguese:         {raw: wordlistPortuguese},
	}

	wordlistVerifyOnce sync.Once
	wordlistVerifyErr  error
)

// verifyWordlists performs one-time SHA256 verification and parsing of
// all embedded BIP39 wordlists. Called lazily on first BIP39 derivation.
func verifyWordlists() error {
	wordlistVerifyOnce.Do(func() {
		// Sort keys for deterministic verification order. If any
		// wordlist is corrupted, the error message is consistent
		// across runs regardless of Go's map iteration order.
		langs := make([]uint32, 0, len(wordlistEntries))
		for lang := range wordlistEntries {
			langs = append(langs, lang)
		}
		slices.Sort(langs)

		for _, lang := range langs {
			entry := wordlistEntries[lang]
			// SHA256 of raw file content.
			hash := sha256.Sum256([]byte(entry.raw))
			gotHex := fmt.Sprintf("%x", hash)
			wantHex, ok := wordlistSHA256[lang]
			if !ok {
				wordlistVerifyErr = fmt.Errorf("%w: no expected hash for language %d", ErrCorruptedWordlist, lang)
				return
			}
			if gotHex != wantHex {
				wordlistVerifyErr = fmt.Errorf("%w: language %d hash mismatch", ErrCorruptedWordlist, lang)
				return
			}

			// Parse words, trimming any \r from Windows line endings.
			lines := strings.Split(entry.raw, "\n")
			words := make([]string, 0, 2048)
			for _, line := range lines {
				w := strings.TrimRight(line, "\r \t")
				if w != "" {
					words = append(words, w)
				}
			}
			if len(words) != 2048 {
				wordlistVerifyErr = fmt.Errorf("%w: language %d has %d words, expected 2048", ErrCorruptedWordlist, lang, len(words))
				return
			}

			// Check for duplicates.
			seen := make(map[string]struct{}, 2048)
			for _, w := range words {
				if _, dup := seen[w]; dup {
					wordlistVerifyErr = fmt.Errorf("%w: language %d has duplicate word %q", ErrCorruptedWordlist, lang, w)
					return
				}
				seen[w] = struct{}{}
			}

			entry.words = words
		}
	})
	return wordlistVerifyErr
}

// getWordlist returns the parsed wordlist for the given language code.
// Triggers one-time verification on first call.
//
// The returned slice is the shared internal wordlist. Callers must NOT
// modify it. DeriveBIP39 only reads from the returned slice (word lookup
// by index), so no copy is needed on the hot path. If a public API ever
// exposes this, it must return a copy.
func getWordlist(lang uint32) ([]string, error) {
	if err := verifyWordlists(); err != nil {
		return nil, err
	}
	entry, ok := wordlistEntries[lang]
	if !ok {
		return nil, fmt.Errorf("%w: %d (valid: 0-9)", ErrInvalidLanguage, lang)
	}
	if len(entry.words) != 2048 {
		return nil, fmt.Errorf("%w: language %d not parsed", ErrCorruptedWordlist, lang)
	}
	return entry.words, nil
}

// DeriveBIP39 derives a BIP39 mnemonic from BIP85 entropy.
//
// The entropy is truncated to the byte length required for the given
// word count, then a SHA256 checksum is appended per BIP39. The combined
// bits are split into 11-bit groups (MSB-first), each group indexing
// into the wordlist for the given language.
//
// Valid word counts: 12, 15, 18, 21, 24.
// Language codes: 0=English through 9=Portuguese.
//
// Japanese mnemonics use the ideographic space (U+3000) as separator
// per the BIP39 specification. All other languages use ASCII space.
//
// The output words use the same Unicode normalization form as the
// embedded BIP39 wordlists (NFKD, per BIP39 spec). Other implementations
// may output NFC-normalized text. Both forms represent the same words
// and produce the same BIP39 seed when processed through PBKDF2.
//
// Path: m/83696968'/39'/{language}'/{words}'/{index}'.
func DeriveBIP39(entropy []byte, language uint32, words int) (string, error) {
	entropyBytes, ok := wordCountToBytes[words]
	if !ok {
		return "", fmt.Errorf("%w: %d (valid: 12, 15, 18, 21, 24)", ErrInvalidWordCount, words)
	}
	if len(entropy) < entropyBytes {
		return "", fmt.Errorf("%w: entropy too short for %d-word mnemonic", ErrInvalidLength, words)
	}

	wordlist, err := getWordlist(language)
	if err != nil {
		return "", err
	}

	// Work on a copy to avoid modifying the caller's entropy slice.
	ent := make([]byte, entropyBytes)
	copy(ent, entropy[:entropyBytes])
	defer ZeroBytes(ent)

	// BIP39: truncate FIRST, then compute SHA256 checksum over the
	// truncated entropy. Checksum bits = entropy_bits / 32.
	// Total bits = entropy_bits + checksum_bits = entropy_bits * 33 / 32.
	checksum := sha256.Sum256(ent)
	defer ZeroBytes(checksum[:]) // Checksum is derived from secret entropy.
	entropyBits := entropyBytes * 8
	totalBits := entropyBits + entropyBits/32

	// Don't trust: verify total bits divides evenly into 11-bit groups.
	if totalBits%11 != 0 {
		return "", fmt.Errorf("bip85: BIP39 total bits %d not divisible by 11", totalBits)
	}
	if totalBits/11 != words {
		return "", fmt.Errorf("bip85: BIP39 total bits %d / 11 = %d, expected %d words", totalBits, totalBits/11, words)
	}

	// Extract 11-bit word indexes, MSB-first.
	// We treat ent + checksum as a single big-endian bitstream.
	mnemonic := make([]string, words)
	for i := 0; i < words; i++ {
		idx := extract11Bits(ent, checksum[:], i, entropyBits)
		if idx >= 2048 {
			return "", fmt.Errorf("bip85: BIP39 word index %d out of range at position %d", idx, i)
		}
		mnemonic[i] = wordlist[idx]
	}

	// Japanese uses ideographic space (U+3000) as separator per BIP39 spec.
	sep := " "
	if language == LangJapanese {
		sep = "\u3000"
	}
	result := strings.Join(mnemonic, sep)

	// Don't trust: verify the output splits back to the requested word count.
	if n := strings.Count(result, sep) + 1; n != words {
		return "", fmt.Errorf("bip85: BIP39 output has %d words, expected %d", n, words)
	}
	return result, nil
}

// extract11Bits extracts an 11-bit value starting at bit position i*11
// from the concatenation of entropy and checksum bytes.
// MSB-first: bit 0 is the leftmost (most significant) bit of entropy[0].
func extract11Bits(entropy, checksum []byte, wordIndex int, entropyBits int) uint32 {
	bitOffset := wordIndex * 11
	var result uint32
	for b := 0; b < 11; b++ {
		pos := bitOffset + b
		var byteVal byte
		if pos < entropyBits {
			byteVal = entropy[pos/8]
		} else {
			byteVal = checksum[(pos-entropyBits)/8]
		}
		bitVal := (byteVal >> (7 - uint(pos%8))) & 1
		result = (result << 1) | uint32(bitVal)
	}
	return result
}

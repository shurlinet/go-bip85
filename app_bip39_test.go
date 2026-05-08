package bip85

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"
)

// --- BIP85 spec vectors: BIP39 ---

func TestSpecVector_BIP39_12English(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := BIP39Path(0, 12, 0)
	entropy, err := DeriveEntropy(key, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(entropy)

	mnemonic, err := DeriveBIP39(entropy, 0, 12)
	if err != nil {
		t.Fatal(err)
	}

	want := "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose"
	if mnemonic != want {
		t.Errorf("BIP39 12 English:\n  got:  %s\n  want: %s", mnemonic, want)
	}

	// Also verify the truncated entropy matches spec.
	wantEntropy := "6250b68daf746d12a24d58b4787a714b"
	if got := hex.EncodeToString(entropy[:16]); got != wantEntropy {
		t.Errorf("app entropy:\n  got:  %s\n  want: %s", got, wantEntropy)
	}
}

func TestSpecVector_BIP39_18English(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := BIP39Path(0, 18, 0)
	entropy, err := DeriveEntropy(key, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(entropy)

	mnemonic, err := DeriveBIP39(entropy, 0, 18)
	if err != nil {
		t.Fatal(err)
	}

	want := "near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token"
	if mnemonic != want {
		t.Errorf("BIP39 18 English:\n  got:  %s\n  want: %s", mnemonic, want)
	}

	wantEntropy := "938033ed8b12698449d4bbca3c853c66b293ea1b1ce9d9dc"
	if got := hex.EncodeToString(entropy[:24]); got != wantEntropy {
		t.Errorf("app entropy:\n  got:  %s\n  want: %s", got, wantEntropy)
	}
}

func TestSpecVector_BIP39_24English(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := BIP39Path(0, 24, 0)
	entropy, err := DeriveEntropy(key, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(entropy)

	mnemonic, err := DeriveBIP39(entropy, 0, 24)
	if err != nil {
		t.Fatal(err)
	}

	want := "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano"
	if mnemonic != want {
		t.Errorf("BIP39 24 English:\n  got:  %s\n  want: %s", mnemonic, want)
	}

	wantEntropy := "ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f"
	if got := hex.EncodeToString(entropy[:32]); got != wantEntropy {
		t.Errorf("app entropy:\n  got:  %s\n  want: %s", got, wantEntropy)
	}
}

// --- BIP85 spec vectors: BASE64 ---

func TestSpecVector_BASE64(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := Base64Path(21, 0)
	entropy, err := DeriveEntropy(key, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(entropy)

	// Verify intermediate entropy matches spec.
	wantEntropy := "74a2e87a9ba0cdd549bdd2f9ea880d554c6c355b08ed25088cfa88f3f1c4f74632b652fd4a8f5fda43074c6f6964a3753b08bb5210c8f5e75c07a4c2a20bf6e9"
	if got := hex.EncodeToString(entropy); got != wantEntropy {
		t.Errorf("entropy:\n  got:  %s\n  want: %s", got, wantEntropy)
	}

	pwd, err := DeriveBase64(entropy, 21)
	if err != nil {
		t.Fatal(err)
	}

	want := "dKLoepugzdVJvdL56ogNV"
	if pwd != want {
		t.Errorf("BASE64(21):\n  got:  %s\n  want: %s", pwd, want)
	}
}

// --- BIP85 spec vectors: BASE85 ---

func TestSpecVector_BASE85(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := Base85Path(12, 0)
	entropy, err := DeriveEntropy(key, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(entropy)

	// Verify intermediate entropy matches spec.
	wantEntropy := "f7cfe56f63dca2490f65fcbf9ee63dcd85d18f751b6b5e1c1b8733af6459c904a75e82b4a22efff9b9e69de2144b293aa8714319a054b6cb55826a8e51425209"
	if got := hex.EncodeToString(entropy); got != wantEntropy {
		t.Errorf("entropy:\n  got:  %s\n  want: %s", got, wantEntropy)
	}

	pwd, err := DeriveBase85(entropy, 12)
	if err != nil {
		t.Fatal(err)
	}

	want := "_s`{TW89)i4`"
	if pwd != want {
		t.Errorf("BASE85(12):\n  got:  %s\n  want: %s", pwd, want)
	}
}

// --- Cross-impl vectors: BIP39 ---

func TestCrossImpl_BIP39(t *testing.T) {
	vf := loadVectors(t)
	tested := 0
	for _, mk := range vf.MasterKeys {
		key, err := ParseKey(mk.MasterXprv)
		if err != nil {
			t.Fatalf("%s: ParseKey: %v", mk.MasterID, err)
		}
		for _, v := range mk.Vectors {
			if v.App != "bip39" {
				continue
			}
			tested++
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

				lang := uint32(v.Params["language"].(float64))
				words := int(v.Params["words"].(float64))

				mnemonic, err := DeriveBIP39(entropy, lang, words)
				if err != nil {
					t.Fatal(err)
				}

				expected := v.Output

				// BIP39 wordlists from bitcoin/bips use NFKD normalization
				// (per BIP39 spec), while bipsea outputs NFC. Both are valid
				// representations of the same characters. For cross-impl
				// comparison, normalize both sides to NFC.
				//
				// Japanese separator: BIP39 spec requires ideographic space
				// (U+3000). bipsea uses ASCII space. We follow the spec.
				// Normalize separators before comparing words.

				gotNorm := norm.NFC.String(mnemonic)
				wantNorm := norm.NFC.String(expected)

				if lang == LangJapanese {
					// Normalize separators: replace ideographic space with
					// ASCII space for word-level comparison.
					gotWords := strings.Fields(strings.ReplaceAll(gotNorm, "\u3000", " "))
					wantWords := strings.Fields(strings.ReplaceAll(wantNorm, "\u3000", " "))
					if len(gotWords) != len(wantWords) {
						t.Errorf("word count: got %d, want %d", len(gotWords), len(wantWords))
						return
					}
					for i := range gotWords {
						if gotWords[i] != wantWords[i] {
							t.Errorf("word %d: got %q, want %q", i, gotWords[i], wantWords[i])
						}
					}
					// Verify we use ideographic space.
					if words > 1 && !strings.Contains(mnemonic, "\u3000") {
						t.Error("Japanese mnemonic should use ideographic space (U+3000)")
					}
					return
				}

				if gotNorm != wantNorm {
					t.Errorf("BIP39:\n  got:  %s\n  want: %s", mnemonic, expected)
				}
			})
		}
		key.Zero()
	}
	if tested < 80 {
		t.Fatalf("BIP39 cross-impl: only tested %d vectors, expected at least 80", tested)
	}
}

// --- Cross-impl vectors: BASE64 ---

func TestCrossImpl_BASE64(t *testing.T) {
	vf := loadVectors(t)
	tested := 0
	for _, mk := range vf.MasterKeys {
		key, err := ParseKey(mk.MasterXprv)
		if err != nil {
			t.Fatalf("%s: ParseKey: %v", mk.MasterID, err)
		}
		for _, v := range mk.Vectors {
			if v.App != "base64" {
				continue
			}
			tested++
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

				pwdLen := int(v.Params["pwd_len"].(float64))
				pwd, err := DeriveBase64(entropy, pwdLen)
				if err != nil {
					t.Fatal(err)
				}
				if pwd != v.Output {
					t.Errorf("BASE64(%d):\n  got:  %s\n  want: %s", pwdLen, pwd, v.Output)
				}
			})
		}
		key.Zero()
	}
	if tested < 15 {
		t.Fatalf("BASE64 cross-impl: only tested %d vectors, expected at least 15", tested)
	}
}

// --- Cross-impl vectors: BASE85 ---

func TestCrossImpl_BASE85(t *testing.T) {
	vf := loadVectors(t)
	tested := 0
	for _, mk := range vf.MasterKeys {
		key, err := ParseKey(mk.MasterXprv)
		if err != nil {
			t.Fatalf("%s: ParseKey: %v", mk.MasterID, err)
		}
		for _, v := range mk.Vectors {
			if v.App != "base85" {
				continue
			}
			tested++
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

				pwdLen := int(v.Params["pwd_len"].(float64))
				pwd, err := DeriveBase85(entropy, pwdLen)
				if err != nil {
					t.Fatal(err)
				}
				if pwd != v.Output {
					t.Errorf("BASE85(%d):\n  got:  %s\n  want: %s", pwdLen, pwd, v.Output)
				}
			})
		}
		key.Zero()
	}
	if tested < 15 {
		t.Fatalf("BASE85 cross-impl: only tested %d vectors, expected at least 15", tested)
	}
}

// --- BIP39 checksum validity property ---

func TestBIP39_ChecksumValidity(t *testing.T) {
	// For every derived mnemonic, recompute the BIP39 checksum and verify
	// it matches (the mnemonic is valid per BIP39).
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	for _, words := range []int{12, 15, 18, 21, 24} {
		t.Run(fmt.Sprintf("%d_words", words), func(t *testing.T) {
			path := BIP39Path(0, uint32(words), 0)
			entropy, err := DeriveEntropy(key, path)
			if err != nil {
				t.Fatal(err)
			}
			defer ZeroBytes(entropy)

			mnemonic, err := DeriveBIP39(entropy, 0, words)
			if err != nil {
				t.Fatal(err)
			}

			// Split mnemonic back into word indexes.
			wordlist, _ := getWordlist(0)
			wordIdx := make(map[string]int, 2048)
			for i, w := range wordlist {
				wordIdx[w] = i
			}

			mnemonicWords := strings.Split(mnemonic, " ")
			if len(mnemonicWords) != words {
				t.Fatalf("word count: got %d, want %d", len(mnemonicWords), words)
			}

			// Reconstruct entropy + checksum from word indexes.
			entropyBytes := wordCountToBytes[words]
			totalBits := words * 11
			checksumBits := totalBits - entropyBytes*8

			// Collect all 11-bit groups.
			allBits := make([]byte, totalBits)
			for i, w := range mnemonicWords {
				idx, ok := wordIdx[w]
				if !ok {
					t.Fatalf("word %q not in wordlist", w)
				}
				for b := 0; b < 11; b++ {
					if (idx>>(10-b))&1 == 1 {
						allBits[i*11+b] = 1
					}
				}
			}

			// Extract entropy bytes (first entropyBytes*8 bits).
			reconstructedEntropy := make([]byte, entropyBytes)
			for i := 0; i < entropyBytes*8; i++ {
				if allBits[i] == 1 {
					reconstructedEntropy[i/8] |= 1 << (7 - uint(i%8))
				}
			}

			// Compute expected checksum.
			hash := sha256.Sum256(reconstructedEntropy)
			expectedChecksum := hash[0] >> (8 - uint(checksumBits))

			// Extract actual checksum bits.
			var actualChecksum byte
			for i := 0; i < checksumBits; i++ {
				if allBits[entropyBytes*8+i] == 1 {
					actualChecksum |= 1 << (uint(checksumBits-1) - uint(i))
				}
			}

			if actualChecksum != expectedChecksum {
				t.Errorf("checksum mismatch: got %08b, want %08b", actualChecksum, expectedChecksum)
			}
		})
	}
}

// --- BIP39 smoke tests (10 langs x 5 word counts) ---

func TestBIP39_Smoke(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	for lang := uint32(0); lang <= 9; lang++ {
		for _, words := range []int{12, 15, 18, 21, 24} {
			t.Run(fmt.Sprintf("lang_%d_%d_words", lang, words), func(t *testing.T) {
				path := BIP39Path(lang, uint32(words), 0)
				entropy, err := DeriveEntropy(key, path)
				if err != nil {
					t.Fatal(err)
				}
				defer ZeroBytes(entropy)

				mnemonic, err := DeriveBIP39(entropy, lang, words)
				if err != nil {
					t.Fatalf("DeriveBIP39(lang=%d, words=%d): %v", lang, words, err)
				}

				// Verify word count.
				sep := " "
				if lang == LangJapanese {
					sep = "\u3000"
				}
				mnemonicWords := strings.Split(mnemonic, sep)
				if len(mnemonicWords) != words {
					t.Errorf("word count: got %d, want %d", len(mnemonicWords), words)
				}

				// Verify each word exists in the wordlist.
				wordlist, _ := getWordlist(lang)
				wordSet := make(map[string]struct{}, 2048)
				for _, w := range wordlist {
					wordSet[w] = struct{}{}
				}
				for i, w := range mnemonicWords {
					if _, ok := wordSet[w]; !ok {
						t.Errorf("word %d %q not in language %d wordlist", i, w, lang)
					}
				}

				// Determinism: derive again, same result.
				entropy2, _ := DeriveEntropy(key, path)
				mnemonic2, _ := DeriveBIP39(entropy2, lang, words)
				ZeroBytes(entropy2)
				if mnemonic != mnemonic2 {
					t.Error("not deterministic")
				}
			})
		}
	}
}

// --- BASE64 smoke tests (all 67 valid lengths) ---

func TestBASE64_Smoke(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	for pwdLen := Base64MinLen; pwdLen <= Base64MaxLen; pwdLen++ {
		t.Run(fmt.Sprintf("len_%d", pwdLen), func(t *testing.T) {
			path := Base64Path(uint32(pwdLen), 0)
			entropy, err := DeriveEntropy(key, path)
			if err != nil {
				t.Fatal(err)
			}
			defer ZeroBytes(entropy)

			pwd, err := DeriveBase64(entropy, pwdLen)
			if err != nil {
				t.Fatalf("DeriveBase64(%d): %v", pwdLen, err)
			}
			if len(pwd) != pwdLen {
				t.Errorf("length: got %d, want %d", len(pwd), pwdLen)
			}

			// Determinism.
			entropy2, _ := DeriveEntropy(key, path)
			pwd2, _ := DeriveBase64(entropy2, pwdLen)
			ZeroBytes(entropy2)
			if pwd != pwd2 {
				t.Error("not deterministic")
			}
		})
	}
}

// --- BASE85 smoke tests (all 71 valid lengths) ---

func TestBASE85_Smoke(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	for pwdLen := Base85MinLen; pwdLen <= Base85MaxLen; pwdLen++ {
		t.Run(fmt.Sprintf("len_%d", pwdLen), func(t *testing.T) {
			path := Base85Path(uint32(pwdLen), 0)
			entropy, err := DeriveEntropy(key, path)
			if err != nil {
				t.Fatal(err)
			}
			defer ZeroBytes(entropy)

			pwd, err := DeriveBase85(entropy, pwdLen)
			if err != nil {
				t.Fatalf("DeriveBase85(%d): %v", pwdLen, err)
			}
			if len(pwd) != pwdLen {
				t.Errorf("length: got %d, want %d", len(pwd), pwdLen)
			}

			// All characters must be from the RFC 1924 alphabet.
			for i, c := range pwd {
				if !strings.ContainsRune(rfc1924Alphabet, c) {
					t.Errorf("char %d %q not in RFC 1924 alphabet", i, string(c))
				}
			}

			// Determinism.
			entropy2, _ := DeriveEntropy(key, path)
			pwd2, _ := DeriveBase85(entropy2, pwdLen)
			ZeroBytes(entropy2)
			if pwd != pwd2 {
				t.Error("not deterministic")
			}
		})
	}
}

// --- Error cases ---

func TestBIP39_InvalidWordCount(t *testing.T) {
	entropy := make([]byte, 64)
	for _, words := range []int{0, 1, 11, 13, 14, 16, 17, 19, 20, 22, 23, 25} {
		_, err := DeriveBIP39(entropy, 0, words)
		if !errors.Is(err, ErrInvalidWordCount) {
			t.Errorf("words=%d: got %v, want ErrInvalidWordCount", words, err)
		}
	}
}

func TestBIP39_InvalidLanguage(t *testing.T) {
	entropy := make([]byte, 64)
	_, err := DeriveBIP39(entropy, 10, 12)
	if !errors.Is(err, ErrInvalidLanguage) {
		t.Errorf("got %v, want ErrInvalidLanguage", err)
	}
}

func TestBIP39_ShortEntropy(t *testing.T) {
	_, err := DeriveBIP39(make([]byte, 15), 0, 12)
	if !errors.Is(err, ErrInvalidLength) {
		t.Errorf("got %v, want ErrInvalidLength", err)
	}
}

func TestBIP39_NilEntropy(t *testing.T) {
	_, err := DeriveBIP39(nil, 0, 12)
	if !errors.Is(err, ErrInvalidLength) {
		t.Errorf("got %v, want ErrInvalidLength", err)
	}
}

func TestBASE64_InvalidLength(t *testing.T) {
	entropy := make([]byte, 64)
	_, err := DeriveBase64(entropy, 19)
	if !errors.Is(err, ErrInvalidLength) {
		t.Errorf("got %v, want ErrInvalidLength", err)
	}
	_, err = DeriveBase64(entropy, 87)
	if !errors.Is(err, ErrInvalidLength) {
		t.Errorf("got %v, want ErrInvalidLength", err)
	}
}

func TestBASE64_ShortEntropy(t *testing.T) {
	_, err := DeriveBase64(make([]byte, 63), 20)
	if !errors.Is(err, ErrInvalidLength) {
		t.Errorf("got %v, want ErrInvalidLength", err)
	}
}

func TestBASE64_NilEntropy(t *testing.T) {
	_, err := DeriveBase64(nil, 20)
	if !errors.Is(err, ErrInvalidLength) {
		t.Errorf("got %v, want ErrInvalidLength", err)
	}
}

func TestBASE85_InvalidLength(t *testing.T) {
	entropy := make([]byte, 64)
	_, err := DeriveBase85(entropy, 9)
	if !errors.Is(err, ErrInvalidLength) {
		t.Errorf("got %v, want ErrInvalidLength", err)
	}
	_, err = DeriveBase85(entropy, 81)
	if !errors.Is(err, ErrInvalidLength) {
		t.Errorf("got %v, want ErrInvalidLength", err)
	}
}

func TestBASE85_ShortEntropy(t *testing.T) {
	_, err := DeriveBase85(make([]byte, 63), 10)
	if !errors.Is(err, ErrInvalidLength) {
		t.Errorf("got %v, want ErrInvalidLength", err)
	}
}

func TestBASE85_NilEntropy(t *testing.T) {
	_, err := DeriveBase85(nil, 10)
	if !errors.Is(err, ErrInvalidLength) {
		t.Errorf("got %v, want ErrInvalidLength", err)
	}
}

// --- Entropy copy isolation ---

func TestEntropyCopyIsolation_BIP39(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := BIP39Path(0, 12, 0)
	entropy, err := DeriveEntropy(key, path)
	if err != nil {
		t.Fatal(err)
	}
	original := make([]byte, len(entropy))
	copy(original, entropy)

	_, err = DeriveBIP39(entropy, 0, 12)
	if err != nil {
		t.Fatal(err)
	}

	for i := range entropy {
		if entropy[i] != original[i] {
			t.Fatal("DeriveBIP39 modified the input entropy slice")
		}
	}
}

func TestEntropyCopyIsolation_Base64(t *testing.T) {
	entropy := make([]byte, 64)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	original := make([]byte, 64)
	copy(original, entropy)

	_, _ = DeriveBase64(entropy, 40)

	for i := range entropy {
		if entropy[i] != original[i] {
			t.Fatal("DeriveBase64 modified the input entropy slice")
		}
	}
}

func TestEntropyCopyIsolation_Base85(t *testing.T) {
	entropy := make([]byte, 64)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	original := make([]byte, 64)
	copy(original, entropy)

	_, _ = DeriveBase85(entropy, 40)

	for i := range entropy {
		if entropy[i] != original[i] {
			t.Fatal("DeriveBase85 modified the input entropy slice")
		}
	}
}

// --- Anti-tamper: wordlist integrity ---

func TestWordlistIntegrity(t *testing.T) {
	// Verify all 10 wordlists pass SHA256 verification.
	err := verifyWordlists()
	if err != nil {
		t.Fatalf("wordlist verification failed: %v", err)
	}

	for lang := uint32(0); lang <= 9; lang++ {
		words, err := getWordlist(lang)
		if err != nil {
			t.Fatalf("language %d: %v", lang, err)
		}
		if len(words) != 2048 {
			t.Errorf("language %d: got %d words, want 2048", lang, len(words))
		}
	}
}

func TestWordlistSHA256_IndependentVerification(t *testing.T) {
	// Independent verification: compute SHA256 of each raw embedded wordlist
	// and compare against the hardcoded expected hashes. This catches a
	// malicious contributor who changes BOTH the wordlist file AND the
	// expected hash in the same commit.
	//
	// These expected values were computed from the official bitcoin/bips
	// BIP39 wordlists at the time of initial embedding.
	independentHashes := map[uint32]string{
		0: "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda", // english
		1: "2eed0aef492291e061633d7ad8117f1a2b03eb80a29d0e4e3117ac2528d05ffd", // japanese
		2: "9e95f86c167de88f450f0aaf89e87f6624a57f973c67b516e338e8e8b8897f60", // korean
		3: "46846a5a0139d1e3cb77293e521c2865f7bcdb82c44e8d0a06a2cd0ecba48c0b", // spanish
		4: "5c5942792bd8340cb8b27cd592f1015edf56a8c5b26276ee18a482428e7c5726", // chinese_simplified
		5: "417b26b3d8500a4ae3d59717d7011952db6fc2fb84b807f3f94ac734e89c1b5f", // chinese_traditional
		6: "ebc3959ab7801a1df6bac4fa7d970652f1df76b683cd2f4003c941c63d517e59", // french
		7: "d392c49fdb700a24cd1fceb237c1f65dcc128f6b34a8aacb58b59384b5c648c2", // italian
		8: "7e80e161c3e93d9554c2efb78d4e3cebf8fc727e9c52e03b83b94406bdcc95fc", // czech
		9: "2685e9c194c82ae67e10ba59d9ea5345a23dc093e92276fc5361f6667d79cd3f", // portuguese
	}

	for lang, entry := range wordlistEntries {
		hash := sha256.Sum256([]byte(entry.raw))
		got := fmt.Sprintf("%x", hash)
		want, ok := independentHashes[lang]
		if !ok {
			t.Fatalf("no independent hash for language %d", lang)
		}
		if got != want {
			t.Fatalf("language %d SHA256 mismatch (possible tampering):\n  got:  %s\n  want: %s", lang, got, want)
		}

		// Cross-check: the source-code hardcoded hashes must match these
		// independent test hashes. If they diverge, someone changed one
		// but not the other.
		srcHash, srcOK := wordlistSHA256[lang]
		if !srcOK || srcHash != want {
			t.Fatalf("language %d: source hash %q does not match independent test hash %q", lang, srcHash, want)
		}
	}
}

func TestWordlistSHA256_CorruptionDetection(t *testing.T) {
	// Verify the SHA256 comparison mechanism catches corrupted content.
	// We can't modify the embedded wordlist at runtime (sync.Once already
	// ran), so we verify the detection logic independently: compute
	// SHA256 of a known-corrupted string and confirm it doesn't match
	// the expected hash.
	//
	// This proves: if the binary were tampered with, the hash check
	// would catch it and return ErrCorruptedWordlist.

	// Take the English wordlist content, corrupt one byte.
	entry := wordlistEntries[LangEnglish]
	corrupted := "X" + entry.raw[1:] // Mutate first byte.

	hash := sha256.Sum256([]byte(corrupted))
	corruptedHex := fmt.Sprintf("%x", hash)
	expectedHex := wordlistSHA256[LangEnglish]

	if corruptedHex == expectedHex {
		t.Fatal("corrupted content produces same SHA256 as original (hash collision - astronomically unlikely, check logic)")
	}

	// Verify the expected hash matches what verifyWordlists() checks.
	originalHash := sha256.Sum256([]byte(entry.raw))
	originalHex := fmt.Sprintf("%x", originalHash)
	if originalHex != expectedHex {
		t.Fatalf("original content hash %q does not match expected %q", originalHex, expectedHex)
	}
}

func TestWordlistSHA256_AlphabetCheck(t *testing.T) {
	// Verify the RFC 1924 alphabet constant is exactly 85 characters.
	if len(rfc1924Alphabet) != 85 {
		t.Fatalf("RFC 1924 alphabet length: got %d, want 85", len(rfc1924Alphabet))
	}

	// Verify no duplicate characters.
	seen := make(map[byte]struct{}, 85)
	for i := 0; i < len(rfc1924Alphabet); i++ {
		if _, dup := seen[rfc1924Alphabet[i]]; dup {
			t.Fatalf("duplicate character %c at position %d", rfc1924Alphabet[i], i)
		}
		seen[rfc1924Alphabet[i]] = struct{}{}
	}
}

// --- Base85 RFC 1924 encoder unit tests ---

func TestBase85RFC1924_KnownValues(t *testing.T) {
	tests := []struct {
		input string // hex
		want  string
	}{
		{"00000000", "00000"},
		{"FFFFFFFF", "|NsC0"}, // verified against Python base64.b85encode
		{"00000001", "00001"},
		{"00000054", "0000~"}, // 84 = last char in alphabet
	}
	for _, tt := range tests {
		src, _ := hex.DecodeString(tt.input)
		got := encodeBase85RFC1924(src)
		if got != tt.want {
			t.Errorf("encode(%s): got %q, want %q", tt.input, got, tt.want)
		}
	}
}

// --- BIP39 Japanese ideographic space ---

func TestBIP39_JapaneseIdeographicSpace(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := BIP39Path(LangJapanese, 12, 0)
	entropy, err := DeriveEntropy(key, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(entropy)

	mnemonic, err := DeriveBIP39(entropy, LangJapanese, 12)
	if err != nil {
		t.Fatal(err)
	}

	// Japanese mnemonic must use ideographic space U+3000, not ASCII space.
	if strings.Contains(mnemonic, " ") {
		t.Error("Japanese mnemonic uses ASCII space instead of ideographic space")
	}
	if !strings.Contains(mnemonic, "\u3000") {
		t.Error("Japanese mnemonic does not contain ideographic space (U+3000)")
	}

	// Must have 12 words.
	parts := strings.Split(mnemonic, "\u3000")
	if len(parts) != 12 {
		t.Errorf("word count: got %d, want 12", len(parts))
	}
}

// --- Regression: hardcoded BIP39/BASE64/BASE85 vectors ---

func TestRegression_BIP39_12English_Index1(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := BIP39Path(0, 12, 1)
	entropy, _ := DeriveEntropy(key, path)
	defer ZeroBytes(entropy)

	mnemonic, err := DeriveBIP39(entropy, 0, 12)
	if err != nil {
		t.Fatal(err)
	}

	// Hardcoded from bipsea cross-impl vector.
	want := "mystery car occur shallow stable order number feature else best trigger curious"
	if mnemonic != want {
		t.Errorf("BIP39(12, en, idx=1):\n  got:  %s\n  want: %s", mnemonic, want)
	}
}

func TestRegression_BIP39_24English(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := BIP39Path(0, 24, 0)
	entropy, _ := DeriveEntropy(key, path)
	defer ZeroBytes(entropy)

	mnemonic, err := DeriveBIP39(entropy, 0, 24)
	if err != nil {
		t.Fatal(err)
	}

	// Hardcoded from BIP85 spec.
	want := "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano"
	if mnemonic != want {
		t.Errorf("BIP39(24, en, idx=0):\n  got:  %s\n  want: %s", mnemonic, want)
	}
}

func TestRegression_BASE64_SpecVector(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := Base64Path(21, 0)
	entropy, _ := DeriveEntropy(key, path)
	defer ZeroBytes(entropy)

	pwd, _ := DeriveBase64(entropy, 21)
	want := "dKLoepugzdVJvdL56ogNV"
	if pwd != want {
		t.Errorf("BASE64(21):\n  got:  %s\n  want: %s", pwd, want)
	}
}

func TestRegression_BASE85_SpecVector(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := Base85Path(12, 0)
	entropy, _ := DeriveEntropy(key, path)
	defer ZeroBytes(entropy)

	pwd, _ := DeriveBase85(entropy, 12)
	want := "_s`{TW89)i4`"
	if pwd != want {
		t.Errorf("BASE85(12):\n  got:  %s\n  want: %s", pwd, want)
	}
}

func TestRegression_BIP39_Japanese(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := BIP39Path(LangJapanese, 12, 0)
	entropy, _ := DeriveEntropy(key, path)
	defer ZeroBytes(entropy)

	mnemonic, err := DeriveBIP39(entropy, LangJapanese, 12)
	if err != nil {
		t.Fatal(err)
	}

	// Japanese wordlists are NFKD-normalized (per BIP39 spec), which uses
	// combining marks. Compare via hex to avoid editor/terminal NFC
	// recomposition silently changing the expected string.
	wantHex := "e3818ae381bee38184e3828ae38080e381abe38293e381a6e38184e38080e38193e381b5e38293e38080e3818de38299e38293e38184e3828de38080e381abe38293e38184e38080e3819be38299e38293e38193e38299e38080e381b2e38281e38184e38080e381bee381bbe38186e38080e3819fe3819fe381bfe38080e38195e381a8e38186e38080e38195e38299e38184e3819fe3818fe38080e38182e381a6e381aa"
	gotHex := hex.EncodeToString([]byte(mnemonic))
	if gotHex != wantHex {
		t.Errorf("BIP39 Japanese hex mismatch:\n  got:  %s\n  want: %s", gotHex, wantHex)
	}

	// Verify ideographic space separator.
	if !strings.Contains(mnemonic, "\u3000") {
		t.Error("missing ideographic space")
	}

	// Verify 12 words.
	parts := strings.Split(mnemonic, "\u3000")
	if len(parts) != 12 {
		t.Errorf("word count: got %d, want 12", len(parts))
	}
}

func TestRegression_BASE64_Index1(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := Base64Path(21, 1)
	entropy, _ := DeriveEntropy(key, path)
	defer ZeroBytes(entropy)

	pwd, _ := DeriveBase64(entropy, 21)
	want := "oAC9Cjj6FpoMokSeKEtfO"
	if pwd != want {
		t.Errorf("BASE64(21, idx=1):\n  got:  %s\n  want: %s", pwd, want)
	}
}

func TestRegression_BASE85_Len40(t *testing.T) {
	key, _ := ParseKey(specMasterXprv)
	defer key.Zero()

	path := Base85Path(40, 0)
	entropy, _ := DeriveEntropy(key, path)
	defer ZeroBytes(entropy)

	pwd, _ := DeriveBase85(entropy, 40)
	want := "NrS!m=v0^BG7<j$J$)y%AY_4<mmiT}MZ=Lp1%*fB"
	if pwd != want {
		t.Errorf("BASE85(40):\n  got:  %s\n  want: %s", pwd, want)
	}
}

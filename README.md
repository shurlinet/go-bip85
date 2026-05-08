# go-bip85

[![Go Reference](https://pkg.go.dev/badge/github.com/shurlinet/go-bip85.svg)](https://pkg.go.dev/github.com/shurlinet/go-bip85)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The first Go implementation of [BIP85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki) (Deterministic Entropy From BIP32 Keychains). Implements the BIP85 specification v2.0.0.

BIP85 derives deterministic entropy from a single BIP32 master key. One backup recovers everything: mnemonics, private keys, passwords, symmetric keys, dice rolls.

## Install

```
go get github.com/shurlinet/go-bip85
```

Requires Go 1.25 or later.

## Quick Start

From mnemonic to derived mnemonic, end to end:

```go
package main

import (
    "fmt"
    "log"

    // Step 1: use any BIP32 library to go from mnemonic -> master xprv.
    // go-bip85 starts from the xprv.
    "github.com/btcsuite/btcd/btcutil/hdkeychain"
    "github.com/btcsuite/btcd/chaincfg"
    "github.com/tyler-smith/go-bip39" // or any BIP39 library

    "github.com/shurlinet/go-bip85"
)

func main() {
    // Your master mnemonic (NEVER hardcode real mnemonics).
    mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    // Mnemonic -> BIP39 seed -> BIP32 master key.
    seed := bip39.NewSeed(mnemonic, "") // empty passphrase
    masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
    if err != nil {
        log.Fatal(err)
    }
    defer masterKey.Zero()

    // go-bip85: derive a 12-word English mnemonic at index 0.
    path := bip85.BIP39Path(bip85.LangEnglish, 12, 0)
    entropy, err := bip85.DeriveEntropy(masterKey, path)
    if err != nil {
        log.Fatal(err)
    }
    defer bip85.ZeroBytes(entropy)

    childMnemonic, err := bip85.DeriveBIP39(entropy, bip85.LangEnglish, 12)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(childMnemonic)
    // Each index produces a completely independent mnemonic.
}
```

If you already have an xprv string (e.g., from a wallet export):

```go
entropy, err := bip85.DeriveEntropyFromString("xprv9s21ZrQH143K...", path)
```

## Applications

| Application | Function | Path | Output |
|---|---|---|---|
| BIP39 | `DeriveBIP39` | `m/83696968'/39'/{lang}'/{words}'/{idx}'` | Mnemonic string |
| WIF | `DeriveWIF` | `m/83696968'/2'/{idx}'` | Compressed WIF string |
| XPRV | `DeriveXPRV` | `m/83696968'/32'/{idx}'` | Extended private key string |
| HEX | `DeriveHex` | `m/83696968'/128169'/{bytes}'/{idx}'` | Hex-encoded bytes |
| BASE64 | `DeriveBase64` | `m/83696968'/707764'/{len}'/{idx}'` | Base64 password |
| BASE85 | `DeriveBase85` | `m/83696968'/707785'/{len}'/{idx}'` | RFC 1924 Base85 password |
| DICE | `DeriveDice` | `m/83696968'/89101'/{sides}'/{rolls}'/{idx}'` | Dice roll values |
| DRNG | `NewDRNG` | (from entropy) | io.Reader (unlimited bytes) |

All application functions accept raw entropy bytes. They are independent of how the entropy was derived.

### Path Builders

Type-safe path constructors prevent typos:

```go
bip85.BIP39Path(0, 12, 0)     // m/83696968'/39'/0'/12'/0'
bip85.WIFPath(0)               // m/83696968'/2'/0'
bip85.XPRVPath(0)              // m/83696968'/32'/0'
bip85.HexPath(32, 0)           // m/83696968'/128169'/32'/0'
bip85.Base64Path(21, 0)        // m/83696968'/707764'/21'/0'
bip85.Base85Path(12, 0)        // m/83696968'/707785'/12'/0'
bip85.DicePath(6, 10, 0)       // m/83696968'/89101'/6'/10'/0'
bip85.RSAPath(2048, 0)         // m/83696968'/828365'/2048'/0'
```

String paths also work: `bip85.ParsePath("m/83696968'/39'/0'/12'/0'")`.

### BIP39 Languages

All 10 BIP39 languages are supported. Japanese uses ideographic space (U+3000) per spec.

| Code | Language |
|---|---|
| 0 | English |
| 1 | Japanese |
| 2 | Korean |
| 3 | Spanish |
| 4 | Chinese (Simplified) |
| 5 | Chinese (Traditional) |
| 6 | French |
| 7 | Italian |
| 8 | Czech |
| 9 | Portuguese |

### Network Support

WIF and XPRV accept `*chaincfg.Params` for non-Bitcoin networks:

```go
// Bitcoin mainnet (default when nil)
wif, _ := bip85.DeriveWIF(entropy, nil)

// Bitcoin testnet
wif, _ := bip85.DeriveWIF(entropy, &chaincfg.TestNet3Params)

// Any BIP32-compatible chain (Litecoin, Komodo, etc.)
wif, _ := bip85.DeriveWIF(entropy, &myCustomParams)
```

## Chain-Agnostic API

For chains that don't use BIP32 (Solana, Cardano, Polkadot), use `EntropyFromRawKey`:

```go
// Your Ed25519/Sr25519/custom-derived private key.
myKey := deriveViaSlip10(seed, path) // your derivation

// Apply BIP85 HMAC extraction directly. Zero btcsuite types.
// Any key length works - 32 bytes (Ed25519), 48, 64, etc.
entropy, err := bip85.EntropyFromRawKey(myKey)
```

This applies `HMAC-SHA512("bip-entropy-from-k", key)` to any key bytes. The result feeds into the same application functions. See [examples/multichain](examples/multichain/) for a complete runnable example.

## RSA

RSA key generation (`DeriveRSA`) is intentionally not provided as a high-level function.

**Why:** Go's `crypto/rsa.GenerateKey` (since Go 1.24) mixes system entropy into prime generation for FIPS 140-3 compliance. This makes RSA output non-deterministic: the same BIP85 entropy produces a *different* RSA key on each call. The key is not recoverable from the seed backup alone, which breaks the core BIP85 promise.

**This is a Go platform constraint, not a go-bip85 limitation.** The BIP85 spec's RSA application works correctly when the RSA implementation uses only the provided DRNG as its randomness source.

**Consumer workaround:** Use the DRNG directly as an `io.Reader` with an RSA implementation that does not mix system entropy:

```go
entropy, _ := bip85.DeriveEntropy(key, bip85.RSAPath(2048, 0))
drng := bip85.NewDRNG(entropy)
// Pass drng to an RSA implementation that uses ONLY the provided reader.
```

The full RSA implementation is preserved on the `rsa-non-deterministic` branch for reference.

**Kept:** `RSAPath` (path builder), `AppRSA` (app code 828365'), `RSAMinBits`, `RSAMaxBits`, `GPGCreationTimestamp` (Bitcoin genesis block timestamp for GPG key creation dates per spec).

## DRNG

BIP85-DRNG-SHAKE256 produces an unlimited deterministic byte stream:

```go
drng := bip85.NewDRNG(entropy) // 64 bytes of BIP85 entropy
buf := make([]byte, 32)
drng.Read(buf) // deterministic output
```

The DRNG implements `io.Reader` and can be passed to any function that accepts a randomness source. It never returns `io.EOF`.

**Important:** DRNG instances must not be shared between goroutines. Each goroutine must create its own instance.

## Extensibility

Override behavior without modifying go-bip85:

```go
// Custom HMAC key (non-standard output)
entropy, _ := bip85.DeriveEntropy(key, path, bip85.WithHMACKey([]byte("my-key")))

// Custom derivation (your own key derivation scheme)
entropy, _ := bip85.DeriveEntropy(key, path, bip85.WithCustomDeriver(myDeriver))

// Post-processing (extra HKDF layer, etc.)
entropy, _ := bip85.DeriveEntropy(key, path, bip85.WithEntropyPostProcessor(myPostProcessor))
```

## Consumer Responsibilities

**EC key validation:** If you use raw HEX entropy as an elliptic curve private key (outside of `DeriveWIF`/`DeriveXPRV` which validate automatically), call `ValidateSecp256k1Key` first. Invalid keys (zero or >= curve order) must be rejected by trying the next BIP85 index.

**No caching:** BIP85 derivation is deterministic and fast. There is no need to cache derived outputs. Re-derive on every use from the master key. Caching introduces storage security requirements that derivation-on-demand avoids.

**Path tracking:** You are responsible for recording which derivation path produced which output. The library cannot reverse-derive a path from an output. Losing path metadata means brute-force recovery across all possible paths.

**DRNG isolation:** DRNG instances must not be shared between goroutines. Each goroutine must create its own instance. Sharing produces interleaved bytes with no error - silently wrong output.

## What's Not Implemented

**RSA GPG sub-keys:** The GPG sub-key hierarchy (sub_key path extension + frozen timestamp) from the BIP85 spec is not implemented. The basic RSA application path and `GPGCreationTimestamp` constant are provided for consumers who build GPG keys externally.

**FromMnemonic:** This library takes an xprv string or pre-parsed key as input, not a mnemonic. Converting mnemonic to BIP39 seed to BIP32 master key is the consumer's responsibility. See the Quick Start section for a complete example chain.

Both can be extended via the `WithCustomDeriver` option or by using `EntropyFromRawKey` with your own derivation.

## Security

**Memory zeroing:** This library zeros secret key material after use via `ZeroBytes` and `defer`. However, the Go garbage collector may copy data before zeroing occurs. For hardware-grade security, use a hardware wallet.

**Master key security:** All derived outputs are only as secure as the master key. A weak or compromised master key compromises all derived entropy.

**Logging:** Do not pass `ExtendedKey` values or entropy byte slices to loggers or tracing frameworks. `ExtendedKey.String()` outputs the full xprv.

**COLDCARD compatibility:** This library produces identical output to COLDCARD and other BIP85-compliant implementations when given the same master key and derivation path. All 12 BIP85 spec test vectors pass byte-for-byte.

**Concurrency:** Derivation functions (`DeriveEntropy`, `DeriveKeyAndEntropy`, `EntropyFromRawKey`) are safe for concurrent use with the same parsed key. DRNG instances are NOT safe for concurrent use.

## Testing

- 12 BIP85 spec vectors (mandatory gate)
- 268 cross-implementation vectors (generated from bipsea, verified against ethankosakovsky, bip85-js, rust-bip85, Ledger)
- 188+ smoke tests across all applications and parameter ranges
- 21 hardcoded regression vectors (survive JSON corruption)
- 22 property and behavioral tests (determinism, round-trip, independence, copy isolation, range, rejection sampling)
- 8 fuzz targets
- 5 AI threat defense tests (HMAC argument order, full entropy verification, independent HMAC oracle, error message key leak scan, XPRV field order)
- Independent oracle (anti-tamper DICE test)
- SHA256 wordlist integrity verification
- Anti-tamper tests for HMAC key content and secp256k1 order

```
go test -race -count=1 ./...
```

## Examples

See the [examples/](examples/) directory:

- [basic](examples/basic/) - BIP32 master key to BIP39 mnemonic
- [dice](examples/dice/) - PIN generation and alphanumeric passwords via DICE
- [multichain](examples/multichain/) - Chain-agnostic entropy for Solana, Cardano, Polkadot
- [drng](examples/drng/) - DRNG as io.Reader for custom key generation
- [password](examples/password/) - Base64 and Base85 password generation

## Dependencies

| Dependency | Purpose |
|---|---|
| `btcsuite/btcd` | BIP32 HD key derivation, secp256k1, WIF encoding |
| `golang.org/x/crypto` | SHAKE256 (DRNG) |
| `golang.org/x/text` | Unicode NFC normalization (test-only, BIP39 cross-impl comparison) |

## AI Transparency

This library was developed with assistance from Claude (Anthropic). All code was reviewed, tested against reference implementations, and verified against the BIP85 specification. The test suite includes anti-tamper tests designed to catch both human and AI-introduced errors.

## Acknowledgments

- [BIP85 specification authors](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki) (Ethan Kosakovsky, Aneesh Karve)
- [bipsea](https://github.com/akarve/bipsea) (gold standard Python BIP85 implementation, used for cross-implementation vector generation)
- [ethankosakovsky/bip85](https://github.com/ethankosakovsky/bip85) (original Python reference)
- [btcsuite](https://github.com/btcsuite/btcd) (Bitcoin libraries for Go)

## License

MIT

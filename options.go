package bip85

import "github.com/btcsuite/btcd/btcutil/hdkeychain"

// derivationConfig holds the pipeline configuration for a single derivation.
type derivationConfig struct {
	hmacKey       []byte
	customDeriver func(root *hdkeychain.ExtendedKey, path Path) (privateKey []byte, err error)
	postProcessor func(entropy []byte) ([]byte, error)
}

// Option configures the BIP85 derivation pipeline.
type Option func(*derivationConfig)

// WithHMACKey overrides the default HMAC key ("bip-entropy-from-k").
// The key must be non-nil and non-empty.
//
// Setting a custom HMAC key produces non-standard output that will not
// match any reference BIP85 implementation.
func WithHMACKey(key []byte) Option {
	return func(c *derivationConfig) {
		c.hmacKey = key
	}
}

// WithCustomDeriver replaces the default BIP32 derivation with a custom
// function. The function receives the parsed root key and path, and must
// return a freshly allocated slice of raw private key material.
//
// Security: the deriver receives the full master key. Only use derivers
// from your own trust domain. A malicious deriver can read or copy the
// master key. Do not accept Options from untrusted sources.
//
// Setting a custom deriver produces non-standard output that will not
// match any reference BIP85 implementation.
func WithCustomDeriver(fn func(root *hdkeychain.ExtendedKey, path Path) ([]byte, error)) Option {
	return func(c *derivationConfig) {
		c.customDeriver = fn
	}
}

// WithEntropyPostProcessor adds a post-processing step after the HMAC-SHA512
// entropy extraction. The function receives the 64-byte entropy and must
// return at least 64 bytes.
//
// Setting a post-processor produces non-standard output that will not
// match any reference BIP85 implementation.
func WithEntropyPostProcessor(fn func(entropy []byte) ([]byte, error)) Option {
	return func(c *derivationConfig) {
		c.postProcessor = fn
	}
}

// applyOptions builds a derivationConfig from the given options, applying
// defaults for any unset fields.
func applyOptions(opts []Option) derivationConfig {
	cfg := derivationConfig{
		hmacKey: hmacKeyBIP85,
	}
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	return cfg
}

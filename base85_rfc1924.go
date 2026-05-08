package bip85

import "encoding/binary"

// rfc1924Alphabet is the 85-character encoding alphabet from RFC 1924.
// Value 0 maps to '0', value 84 maps to '~'. This is NOT the same as
// Go's encoding/ascii85 (which uses Adobe Ascii85).
const rfc1924Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"

// encodeBase85RFC1924 encodes src using the RFC 1924 Base85 alphabet.
// Input length must be a multiple of 4 bytes. Each 4-byte group is
// interpreted as a big-endian uint32 and encoded as 5 characters,
// most-significant digit first.
func encodeBase85RFC1924(src []byte) string {
	if len(src)%4 != 0 {
		panic("bip85: base85 input length must be a multiple of 4")
	}
	out := make([]byte, (len(src)/4)*5)
	for i := 0; i < len(src); i += 4 {
		v := binary.BigEndian.Uint32(src[i : i+4])
		off := (i / 4) * 5
		// Encode MSB-first: out[off] is the most significant digit.
		for j := 4; j >= 0; j-- {
			out[off+j] = rfc1924Alphabet[v%85]
			v /= 85
		}
		// 85^5 > 2^32, so v must be 0 after extracting 5 digits.
		if v != 0 {
			panic("bip85: base85 encoding error: residual value after 5 divisions")
		}
	}
	result := string(out)
	ZeroBytes(out) // out holds encoded secret-derived data
	return result
}

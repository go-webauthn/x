package asn1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeECDSASignature(t *testing.T) {
	der := testECDSADER(t)

	// The minimal encodings of the two integers, which is what the DER above carries. The leading zero octet on s
	// is required by DER as the high bit of its first octet is set.
	minimalR, minimalS := testECDSAR, append([]byte{0x00}, testECDSAS...)

	testCases := []struct {
		name string
		have []byte
	}{
		{
			"ShouldNormalizeDERToItself",
			der,
		},
		{
			"ShouldNormalizeBERPaddedR",
			sequence(integer(append([]byte{0x00}, minimalR...)), integer(minimalS)),
		},
		{
			"ShouldNormalizeBERPaddedS",
			sequence(integer(minimalR), integer(append([]byte{0x00}, minimalS...))),
		},
		{
			"ShouldNormalizeBERPaddedBoth",
			sequence(integer(append([]byte{0x00}, minimalR...)), integer(append([]byte{0x00}, minimalS...))),
		},
		{
			"ShouldNormalizeBERExcessivePadding",
			sequence(
				integer(append([]byte{0x00, 0x00, 0x00, 0x00}, minimalR...)),
				integer(append([]byte{0x00, 0x00, 0x00, 0x00}, minimalS...)),
			),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := NormalizeECDSASignature(tc.have)

			require.NoError(t, err)
			assert.Equal(t, der, actual)
		})
	}
}

func TestNormalizeECDSASignatureShouldBeDeterministic(t *testing.T) {
	// Every accepted encoding of the same pair of integers must produce the same bytes, and repeating the call must
	// produce them again.
	minimalR, minimalS := testECDSAR, append([]byte{0x00}, testECDSAS...)

	encodings := [][]byte{
		testECDSADER(t),
		sequence(integer(append([]byte{0x00}, minimalR...)), integer(minimalS)),
		sequence(integer(minimalR), integer(append([]byte{0x00, 0x00}, minimalS...))),
	}

	expected := testECDSADER(t)

	for range 3 {
		for i, have := range encodings {
			actual, err := NormalizeECDSASignature(have)

			require.NoError(t, err, "encoding %d", i)
			assert.Equal(t, expected, actual, "encoding %d", i)
		}
	}
}

func TestNormalizeECDSASignatureShouldRejectInvalid(t *testing.T) {
	minimalR, minimalS := testECDSAR, append([]byte{0x00}, testECDSAS...)

	testCases := []struct {
		name string
		have []byte
		err  string
	}{
		{
			"ShouldRejectEmpty",
			nil,
			"asn1: syntax error: sequence truncated",
		},
		{
			"ShouldRejectNotASequence",
			integer(minimalR),
			"asn1: structure error: ecdsa signature is not a sequence",
		},
		{
			"ShouldRejectTrailingDataAfterSignature",
			append(sequence(integer(minimalR), integer(minimalS)), 0x00),
			"asn1: structure error: ecdsa signature has 1 bytes of trailing data",
		},
		{
			"ShouldRejectTrailingElementWithinSequence",
			sequence(integer(minimalR), integer(minimalS), integer([]byte{0x01})),
			"asn1: structure error: ecdsa signature sequence has 3 bytes of trailing data",
		},
		{
			"ShouldRejectSingleInteger",
			sequence(integer(minimalR)),
			"asn1: syntax error: sequence truncated",
		},
		{
			"ShouldRejectEmptyInteger",
			sequence(integer(nil), integer(minimalS)),
			"asn1: structure error: empty integer",
		},
		{
			"ShouldRejectNegativeR",
			sequence(integer([]byte{0xff, 0x01}), integer(minimalS)),
			"asn1: structure error: ecdsa signature has a r value which is not a positive integer",
		},
		{
			"ShouldRejectNegativeS",
			sequence(integer(minimalR), integer([]byte{0xff, 0x01})),
			"asn1: structure error: ecdsa signature has a s value which is not a positive integer",
		},
		{
			"ShouldRejectZeroR",
			sequence(integer([]byte{0x00}), integer(minimalS)),
			"asn1: structure error: ecdsa signature has a r value which is not a positive integer",
		},
		{
			"ShouldRejectZeroS",
			sequence(integer(minimalR), integer([]byte{0x00, 0x00})),
			"asn1: structure error: ecdsa signature has a s value which is not a positive integer",
		},
		{
			"ShouldRejectIndefiniteLength",
			// SEQUENCE with an indefinite length, terminated by the end-of-contents octets BER permits.
			append(append([]byte{TagSequence | 0x20, 0x80}, append(integer(minimalR), integer(minimalS)...)...), 0x00, 0x00),
			"asn1: syntax error: indefinite length found (not DER)",
		},
		{
			"ShouldRejectNonMinimalLength",
			// The same sequence with its length in the long form where the short form would carry it.
			func() []byte {
				content := append(integer(minimalR), integer(minimalS)...)

				return append([]byte{TagSequence | 0x20, 0x81, byte(len(content))}, content...)
			}(),
			"asn1: structure error: non-minimal length",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := NormalizeECDSASignature(tc.have)

			assert.EqualError(t, err, tc.err)
			assert.Nil(t, actual)
		})
	}
}

// TestNormalizeECDSASignatureShouldVerify checks that padding the integers of a genuine signature yields one which
// no longer parses as DER, and that normalizing it restores a signature which verifies against the same message.
func TestNormalizeECDSASignatureShouldVerify(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("attestation signature normalization"))

	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	require.NoError(t, err)

	require.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest[:], der))

	var signature ECDSASignature

	rest, err := Unmarshal(der, &signature)
	require.NoError(t, err)
	require.Empty(t, rest)

	// Rebuild the signature with a superfluous leading zero octet on each integer, which is valid BER and invalid
	// DER, then confirm the strict verifier rejects it.
	pad := func(i *big.Int) []byte {
		content, err := Marshal(i)
		require.NoError(t, err)

		return integer(append([]byte{0x00}, content[2:]...))
	}

	ber := sequence(pad(signature.R), pad(signature.S))

	require.NotEqual(t, der, ber)
	require.False(t, ecdsa.VerifyASN1(&key.PublicKey, digest[:], ber))

	normalized, err := NormalizeECDSASignature(ber)
	require.NoError(t, err)

	assert.Equal(t, der, normalized)
	assert.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest[:], normalized))
}

func element(tag byte, content []byte) []byte {
	return append([]byte{tag, byte(len(content))}, content...)
}

func integer(content []byte) []byte {
	return element(TagInteger, content)
}

func sequence(elements ...[]byte) []byte {
	var content []byte

	for _, e := range elements {
		content = append(content, e...)
	}

	return element(TagSequence|0x20, content)
}

var (
	testECDSAR = []byte{
		0x4f, 0x2a, 0x1b, 0x63, 0x9c, 0x08, 0xd5, 0xe7, 0x11, 0x3a, 0x6d, 0x84, 0x27, 0xf0, 0x5b, 0xc2,
		0x9e, 0x74, 0x30, 0xab, 0x15, 0x68, 0xd9, 0x02, 0x3c, 0xe5, 0x81, 0x47, 0xba, 0x60, 0x2f, 0x93,
	}
	testECDSAS = []byte{
		0xd1, 0x86, 0x47, 0x2b, 0xf9, 0x30, 0x5c, 0xa8, 0x13, 0xe4, 0x77, 0x0a, 0x9b, 0x25, 0x68, 0xcf,
		0x51, 0xdc, 0x03, 0x9e, 0x87, 0x4a, 0xb6, 0x1f, 0x72, 0x38, 0xc5, 0x90, 0x0d, 0xe6, 0x41, 0x2b,
	}
)

func testECDSADER(t *testing.T) []byte {
	t.Helper()

	der, err := Marshal(ECDSASignature{
		R: new(big.Int).SetBytes(testECDSAR),
		S: new(big.Int).SetBytes(testECDSAS),
	})

	require.NoError(t, err)

	return der
}

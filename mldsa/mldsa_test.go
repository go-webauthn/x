package mldsa_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha3"
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/go-webauthn/x/mldsa"
	"github.com/go-webauthn/x/mldsa/mldsacrypto"
)

func TestParameters(t *testing.T) {
	tests := []struct {
		params     *mldsa.Parameters
		name       string
		pubKeySize int
		sigSize    int
	}{
		{mldsa.MLDSA44(), "ML-DSA-44", mldsa.MLDSA44PublicKeySize, mldsa.MLDSA44SignatureSize},
		{mldsa.MLDSA65(), "ML-DSA-65", mldsa.MLDSA65PublicKeySize, mldsa.MLDSA65SignatureSize},
		{mldsa.MLDSA87(), "ML-DSA-87", mldsa.MLDSA87PublicKeySize, mldsa.MLDSA87SignatureSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.params.String() != tt.name {
				t.Errorf("String() = %q, want %q", tt.params.String(), tt.name)
			}
			if tt.params.PublicKeySize() != tt.pubKeySize {
				t.Errorf("PublicKeySize() = %d, want %d", tt.params.PublicKeySize(), tt.pubKeySize)
			}
			if tt.params.SignatureSize() != tt.sigSize {
				t.Errorf("SignatureSize() = %d, want %d", tt.params.SignatureSize(), tt.sigSize)
			}
		})
	}
}

func TestParametersIdentity(t *testing.T) {
	// Multiple invocations return the same value.
	p44a, p44b := mldsa.MLDSA44(), mldsa.MLDSA44()
	if p44a != p44b {
		t.Error("MLDSA44() returned different values")
	}
	p65a, p65b := mldsa.MLDSA65(), mldsa.MLDSA65()
	if p65a != p65b {
		t.Error("MLDSA65() returned different values")
	}
	p87a, p87b := mldsa.MLDSA87(), mldsa.MLDSA87()
	if p87a != p87b {
		t.Error("MLDSA87() returned different values")
	}
	// Different parameter sets are not equal.
	if p44a == p65a {
		t.Error("MLDSA44() == MLDSA65()")
	}
}

func testAllParams(t *testing.T, f func(t *testing.T, params *mldsa.Parameters)) {
	t.Run("ML-DSA-44", func(t *testing.T) { f(t, mldsa.MLDSA44()) })
	t.Run("ML-DSA-65", func(t *testing.T) { f(t, mldsa.MLDSA65()) })
	t.Run("ML-DSA-87", func(t *testing.T) { f(t, mldsa.MLDSA87()) })
}

func TestGenerateKey(t *testing.T) {
	testAllParams(t, func(t *testing.T, params *mldsa.Parameters) {
		sk, err := mldsa.GenerateKey(params)
		if err != nil {
			t.Fatal(err)
		}
		if len(sk.Bytes()) != mldsa.PrivateKeySize {
			t.Errorf("seed length = %d, want %d", len(sk.Bytes()), mldsa.PrivateKeySize)
		}
		pk := sk.PublicKey()
		if len(pk.Bytes()) != params.PublicKeySize() {
			t.Errorf("public key length = %d, want %d", len(pk.Bytes()), params.PublicKeySize())
		}
		if pk.Parameters() != params {
			t.Errorf("Parameters() = %v, want %v", pk.Parameters(), params)
		}
	})
}

func TestGenerateKeyInvalidParams(t *testing.T) {
	_, err := mldsa.GenerateKey(&mldsa.Parameters{})
	if err == nil {
		t.Fatal("expected error for invalid parameters")
	}
}

func TestNewPrivateKey(t *testing.T) {
	testAllParams(t, func(t *testing.T, params *mldsa.Parameters) {
		seed := make([]byte, mldsa.PrivateKeySize)
		rand.Read(seed)
		sk, err := mldsa.NewPrivateKey(params, seed)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sk.Bytes(), seed) {
			t.Error("Bytes() does not match seed")
		}
	})
}

func TestNewPrivateKeyInvalidSeed(t *testing.T) {
	testAllParams(t, func(t *testing.T, params *mldsa.Parameters) {
		// Too short.
		if _, err := mldsa.NewPrivateKey(params, make([]byte, 31)); err == nil {
			t.Error("expected error for short seed")
		}
		// Too long.
		if _, err := mldsa.NewPrivateKey(params, make([]byte, 33)); err == nil {
			t.Error("expected error for long seed")
		}
	})
}

func TestNewPrivateKeyInvalidParams(t *testing.T) {
	_, err := mldsa.NewPrivateKey(&mldsa.Parameters{}, make([]byte, mldsa.PrivateKeySize))
	if err == nil {
		t.Fatal("expected error for invalid parameters")
	}
}

func TestKeyRoundTrip(t *testing.T) {
	testAllParams(t, func(t *testing.T, params *mldsa.Parameters) {
		sk1, err := mldsa.GenerateKey(params)
		if err != nil {
			t.Fatal(err)
		}
		sk2, err := mldsa.NewPrivateKey(params, sk1.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if !sk1.Equal(sk2) {
			t.Error("round-tripped private key is not equal")
		}
		if !sk1.PublicKey().Equal(sk2.PublicKey()) {
			t.Error("public key from round-tripped private key is not equal")
		}

		pk1 := sk1.PublicKey()
		pk2, err := mldsa.NewPublicKey(params, pk1.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if !pk1.Equal(pk2) {
			t.Error("round-tripped public key is not equal")
		}
		if pk2.Parameters() != params {
			t.Errorf("Parameters() = %v, want %v", pk2.Parameters(), params)
		}
	})
}

func TestNewPublicKeyInvalidEncoding(t *testing.T) {
	testAllParams(t, func(t *testing.T, params *mldsa.Parameters) {
		// Wrong length.
		if _, err := mldsa.NewPublicKey(params, make([]byte, 10)); err == nil {
			t.Error("expected error for wrong length")
		}
	})
}

func TestNewPublicKeyInvalidParams(t *testing.T) {
	_, err := mldsa.NewPublicKey(&mldsa.Parameters{}, make([]byte, 100))
	if err == nil {
		t.Fatal("expected error for invalid parameters")
	}
}

func TestPrivateKeyEqual(t *testing.T) {
	sk1, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	sk2, _ := mldsa.GenerateKey(mldsa.MLDSA44())

	if !sk1.Equal(sk1) {
		t.Error("key should be equal to itself")
	}
	if sk1.Equal(sk2) {
		t.Error("different keys should not be equal")
	}
	if sk1.Equal("not a key") {
		t.Error("should not be equal to non-key type")
	}
}

func TestPublicKeyEqual(t *testing.T) {
	sk1, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	sk2, _ := mldsa.GenerateKey(mldsa.MLDSA44())

	pk1 := sk1.PublicKey()
	pk2 := sk2.PublicKey()

	if !pk1.Equal(pk1) {
		t.Error("key should be equal to itself")
	}
	if pk1.Equal(pk2) {
		t.Error("different keys should not be equal")
	}
	if pk1.Equal("not a key") {
		t.Error("should not be equal to non-key type")
	}
}

func TestPublicMethod(t *testing.T) {
	sk, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	pub := sk.Public()
	pk, ok := pub.(*mldsa.PublicKey)
	if !ok {
		t.Fatalf("Public() returned %T, want *mldsa.PublicKey", pub)
	}
	if !pk.Equal(sk.PublicKey()) {
		t.Error("Public() and PublicKey() returned different keys")
	}
}

func TestSignAndVerify(t *testing.T) {
	testAllParams(t, func(t *testing.T, params *mldsa.Parameters) {
		sk, err := mldsa.GenerateKey(params)
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("test message")
		sig, err := sk.Sign(nil, msg, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) != params.SignatureSize() {
			t.Errorf("signature length = %d, want %d", len(sig), params.SignatureSize())
		}
		if err := mldsa.Verify(sk.PublicKey(), msg, sig, nil); err != nil {
			t.Errorf("Verify failed: %v", err)
		}
	})
}

func TestSignAndVerifyWithContext(t *testing.T) {
	sk, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	msg := []byte("test message")

	sig, err := sk.Sign(nil, msg, &mldsa.Options{Context: "test context"})
	if err != nil {
		t.Fatal(err)
	}

	// Verify with correct context.
	if err := mldsa.Verify(sk.PublicKey(), msg, sig, &mldsa.Options{Context: "test context"}); err != nil {
		t.Errorf("Verify failed: %v", err)
	}
	// Verify with wrong context.
	if err := mldsa.Verify(sk.PublicKey(), msg, sig, nil); err == nil {
		t.Error("expected verification failure with wrong context")
	}
	if err := mldsa.Verify(sk.PublicKey(), msg, sig, &mldsa.Options{Context: "wrong"}); err == nil {
		t.Error("expected verification failure with wrong context")
	}
}

func TestSignContextTooLong(t *testing.T) {
	sk, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	longCtx := strings.Repeat("x", 256)
	_, err := sk.Sign(nil, []byte("msg"), &mldsa.Options{Context: longCtx})
	if err == nil {
		t.Fatal("expected error for context too long")
	}
}

func TestSignDeterministic(t *testing.T) {
	testAllParams(t, func(t *testing.T, params *mldsa.Parameters) {
		sk, _ := mldsa.GenerateKey(params)
		msg := []byte("test message")

		sig1, err := sk.SignDeterministic(msg, nil)
		if err != nil {
			t.Fatal(err)
		}
		sig2, err := sk.SignDeterministic(msg, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sig1, sig2) {
			t.Error("deterministic signatures differ")
		}
		if err := mldsa.Verify(sk.PublicKey(), msg, sig1, nil); err != nil {
			t.Errorf("Verify failed: %v", err)
		}
	})
}

func TestSignDeterministicWithContext(t *testing.T) {
	sk, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	msg := []byte("test message")

	sig1, err := sk.SignDeterministic(msg, &mldsa.Options{Context: "ctx"})
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := sk.SignDeterministic(msg, &mldsa.Options{Context: "ctx"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Error("deterministic signatures with same context differ")
	}
	// Different context should produce different signature.
	sig3, err := sk.SignDeterministic(msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sig1, sig3) {
		t.Error("deterministic signatures with different context should differ")
	}
}

func TestSignDeterministicContextTooLong(t *testing.T) {
	sk, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	longCtx := strings.Repeat("x", 256)
	_, err := sk.SignDeterministic([]byte("msg"), &mldsa.Options{Context: longCtx})
	if err == nil {
		t.Fatal("expected error for context too long")
	}
}

func TestSignInvalidHashFunc(t *testing.T) {
	sk, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	_, err := sk.Sign(nil, []byte("msg"), crypto.SHA256)
	if err == nil {
		t.Fatal("expected error for invalid HashFunc")
	}
}

func TestSignDeterministicInvalidHashFunc(t *testing.T) {
	sk, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	_, err := sk.SignDeterministic([]byte("msg"), crypto.SHA256)
	if err == nil {
		t.Fatal("expected error for invalid HashFunc")
	}
}

// computeMu computes the μ message representative as specified in FIPS 204.
// μ = SHAKE256(tr || 0x00 || len(ctx) || ctx || msg), where
// tr = SHAKE256(publicKeyBytes) is 64 bytes.
func computeMu(pk *mldsa.PublicKey, msg []byte, context string) []byte {
	H := sha3.NewSHAKE256()
	H.Write(pk.Bytes())
	var tr [64]byte
	H.Read(tr[:])

	H.Reset()
	H.Write(tr[:])
	H.Write([]byte{0x00}) // ML-DSA domain separator
	H.Write([]byte{byte(len(context))})
	H.Write([]byte(context))
	H.Write(msg)
	mu := make([]byte, 64)
	H.Read(mu)
	return mu
}

func TestSignExternalMu(t *testing.T) {
	testAllParams(t, func(t *testing.T, params *mldsa.Parameters) {
		sk, _ := mldsa.GenerateKey(params)
		msg := []byte("test message")

		mu := computeMu(sk.PublicKey(), msg, "")

		sig, err := sk.Sign(nil, mu, mldsacrypto.MLDSAMu)
		if err != nil {
			t.Fatal(err)
		}
		// The signature produced via external mu should verify against
		// the original message via the standard Verify.
		if err := mldsa.Verify(sk.PublicKey(), msg, sig, nil); err != nil {
			t.Errorf("Verify failed: %v", err)
		}
	})
}

func TestSignExternalMuWithContext(t *testing.T) {
	sk, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	msg := []byte("test message")

	mu := computeMu(sk.PublicKey(), msg, "my context")

	sig, err := sk.Sign(nil, mu, mldsacrypto.MLDSAMu)
	if err != nil {
		t.Fatal(err)
	}
	if err := mldsa.Verify(sk.PublicKey(), msg, sig, &mldsa.Options{Context: "my context"}); err != nil {
		t.Errorf("Verify failed: %v", err)
	}
	// Should fail with wrong context.
	if err := mldsa.Verify(sk.PublicKey(), msg, sig, nil); err == nil {
		t.Error("expected verification failure with wrong context")
	}
}

func TestSignExternalMuDeterministic(t *testing.T) {
	sk, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	msg := []byte("test message")
	mu := computeMu(sk.PublicKey(), msg, "")

	sig1, err := sk.SignDeterministic(mu, mldsacrypto.MLDSAMu)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := sk.SignDeterministic(mu, mldsacrypto.MLDSAMu)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Error("deterministic external mu signatures differ")
	}
	if err := mldsa.Verify(sk.PublicKey(), msg, sig1, nil); err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}

func TestSignExternalMuInvalidLength(t *testing.T) {
	sk, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	// μ must be exactly 64 bytes.
	_, err := sk.Sign(nil, make([]byte, 32), mldsacrypto.MLDSAMu)
	if err == nil {
		t.Fatal("expected error for invalid mu length")
	}
	_, err = sk.SignDeterministic(make([]byte, 32), mldsacrypto.MLDSAMu)
	if err == nil {
		t.Fatal("expected error for invalid mu length")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	sk1, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	sk2, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	msg := []byte("test message")
	sig, _ := sk1.Sign(nil, msg, nil)

	if err := mldsa.Verify(sk2.PublicKey(), msg, sig, nil); err == nil {
		t.Error("expected verification failure with wrong key")
	}
}

func TestVerifyWrongMessage(t *testing.T) {
	sk, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	sig, _ := sk.Sign(nil, []byte("message 1"), nil)

	if err := mldsa.Verify(sk.PublicKey(), []byte("message 2"), sig, nil); err == nil {
		t.Error("expected verification failure with wrong message")
	}
}

func TestVerifyTruncatedSignature(t *testing.T) {
	sk, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	msg := []byte("test message")
	sig, _ := sk.Sign(nil, msg, nil)

	if err := mldsa.Verify(sk.PublicKey(), msg, sig[:len(sig)-1], nil); err == nil {
		t.Error("expected verification failure with truncated signature")
	}
}

func TestOptionsHashFunc(t *testing.T) {
	opts := &mldsa.Options{}
	if opts.HashFunc() != 0 {
		t.Errorf("HashFunc() = %d, want 0", opts.HashFunc())
	}
}

func TestCryptoSignerInterface(t *testing.T) {
	sk, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	var _ crypto.Signer = sk
}

func ExamplePrivateKey_Sign_withContext() {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		log.Fatal(err)
	}

	message := []byte("hello, world")
	sig, err := sk.Sign(nil, message, &mldsa.Options{Context: "example"})
	if err != nil {
		log.Fatal(err)
	}

	if err := mldsa.Verify(sk.PublicKey(), message, sig, &mldsa.Options{Context: "example"}); err != nil {
		log.Fatal(err)
	}
	fmt.Println("signature verified")
	// Output: signature verified
}

func ExamplePrivateKey_SignDeterministic() {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		log.Fatal(err)
	}

	message := []byte("hello, world")
	sig, err := sk.SignDeterministic(message, nil)
	if err != nil {
		log.Fatal(err)
	}

	if err := mldsa.Verify(sk.PublicKey(), message, sig, nil); err != nil {
		log.Fatal(err)
	}
	fmt.Println("signature verified")
	// Output: signature verified
}

func ExamplePrivateKey_Sign_externalMu() {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		log.Fatal(err)
	}
	pk := sk.PublicKey()

	// Compute μ externally, as specified in FIPS 204.
	//
	// This is useful when the message is large, because μ can be computed
	// incrementally by the caller without buffering the full message.
	//
	// First, compute tr = SHAKE256(publicKey).
	H := sha3.NewSHAKE256()
	H.Write(pk.Bytes())
	var tr [64]byte
	H.Read(tr[:])

	// Then, compute μ = SHAKE256(tr || 0x00 || len(ctx) || ctx || msg).
	// The second byte is 0x00 for ML-DSA (as opposed to HashML-DSA) and ctx
	// is the context string, empty by default.
	message := []byte("hello, world")
	H.Reset()
	H.Write(tr[:])
	H.Write([]byte{0x00}) // ML-DSA domain separator
	H.Write([]byte{0x00}) // context length (0 for empty context)
	H.Write(message)
	mu := make([]byte, 64)
	H.Read(mu)

	// Sign the pre-computed μ by passing MLDSAMu as the hash function.
	sig, err := sk.Sign(nil, mu, mldsacrypto.MLDSAMu)
	if err != nil {
		log.Fatal(err)
	}

	// Verify against the original message using the standard Verify function.
	if err := mldsa.Verify(pk, message, sig, nil); err != nil {
		log.Fatal(err)
	}
	fmt.Println("signature verified")
	// Output: signature verified
}

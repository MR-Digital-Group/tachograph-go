package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"slices"
	"testing"

	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
)

func TestVerifyEccDataSignatureP521(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-521 key: %v", err)
	}
	data := []byte("a Gen2 transfer")
	digest := sha512.Sum512(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signature := slices.Concat(r.FillBytes(make([]byte, 66)), s.FillBytes(make([]byte, 66)))
	publicKey := &securityv1.EccCertificate_PublicKey{}
	publicKey.SetDomainParametersOid("1.3.132.0.35")
	publicKey.SetPublicPointX(key.X.FillBytes(make([]byte, 66)))
	publicKey.SetPublicPointY(key.Y.FillBytes(make([]byte, 66)))
	cert := &securityv1.EccCertificate{}
	cert.SetPublicKey(publicKey)

	if err := VerifyEccDataSignature(data, signature, cert); err != nil {
		t.Errorf("VerifyEccDataSignature() = %v, want nil", err)
	}
	if err := VerifyEccDataSignature([]byte("another transfer"), signature, cert); err == nil {
		t.Error("VerifyEccDataSignature() accepted a signature over other data")
	}
}

func TestEccSignatureAlgorithm(t *testing.T) {
	for oid, want := range map[string]securityv1.SignatureAlgorithm{
		"1.3.36.3.3.2.8.1.1.7":  securityv1.SignatureAlgorithm_ECDSA_WITH_SHA256, // brainpoolP256r1
		"1.2.840.10045.3.1.7":   securityv1.SignatureAlgorithm_ECDSA_WITH_SHA256, // P-256
		"1.3.36.3.3.2.8.1.1.11": securityv1.SignatureAlgorithm_ECDSA_WITH_SHA384, // brainpoolP384r1
		"1.3.132.0.34":          securityv1.SignatureAlgorithm_ECDSA_WITH_SHA384, // P-384
		"1.3.36.3.3.2.8.1.1.13": securityv1.SignatureAlgorithm_ECDSA_WITH_SHA512, // brainpoolP512r1
		"1.3.132.0.35":          securityv1.SignatureAlgorithm_ECDSA_WITH_SHA512, // P-521
		"1.2.3":                 securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_UNSPECIFIED,
	} {
		if got := EccSignatureAlgorithm(oid); got != want {
			t.Errorf("EccSignatureAlgorithm(%s) = %v, want %v", oid, got, want)
		}
	}
}

package security

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
)

// VerifyEccDataSignature verifies an ECDSA signature on data.
//
// This function implements the signature verification for Generation 2 card EF data
// as specified in Appendix 2, Section 3.3:
//
// The signature is computed over the EF data using ECDSA with a hash function
// determined by the curve parameters:
//   - brainpoolP256r1 / NIST P-256: SHA-256
//   - brainpoolP384r1 / NIST P-384: SHA-384
//   - brainpoolP512r1 / NIST P-521: SHA-512
//
// The signature format is plain format as specified in [TR-03111]:
// signature = r || s (concatenated big-endian byte arrays)
//
// The public key for verification is extracted from the provided EccCertificate.
func VerifyEccDataSignature(data, signature []byte, cardCert *securityv1.EccCertificate) error {
	if cardCert == nil {
		return fmt.Errorf("card certificate cannot be nil")
	}

	// Get card's public key
	pubKey := cardCert.GetPublicKey()
	if pubKey == nil {
		return fmt.Errorf("card certificate has no public key")
	}

	pointX := pubKey.GetPublicPointX()
	pointY := pubKey.GetPublicPointY()
	if len(pointX) == 0 || len(pointY) == 0 {
		return fmt.Errorf("card certificate public key is incomplete")
	}

	// Parse curve parameters to determine hash algorithm
	hashBits, curve, err := parseCurveOID(pubKey.GetDomainParametersOid())
	if err != nil {
		return fmt.Errorf("failed to parse curve: %w", err)
	}

	hash, err := hashFor(hashBits, data)
	if err != nil {
		return err
	}

	// Parse signature (plain format: r || s)
	// Each component is the same size as the curve's field size in bytes
	curveBytes := (hashBits + 7) / 8 // Convert bits to bytes, round up
	if len(signature) != curveBytes*2 {
		return fmt.Errorf("invalid signature length: got %d, want %d", len(signature), curveBytes*2)
	}

	r := new(big.Int).SetBytes(signature[:curveBytes])
	s := new(big.Int).SetBytes(signature[curveBytes:])

	// Construct card's public key
	x := new(big.Int).SetBytes(pointX)
	y := new(big.Int).SetBytes(pointY)

	cardPub := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Verify ECDSA signature
	valid := ecdsa.Verify(cardPub, hash, r, s)
	if !valid {
		return fmt.Errorf("ECDSA signature verification failed")
	}

	return nil
}


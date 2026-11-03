package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/way-platform/tachograph-go/internal/brainpool"
	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
)

// VerifyEccCertificateWithEccRoot verifies an ECC certificate against an ECC root certificate.
//
// This implements certificate chain verification for Generation 2 tachograph certificates
// as specified in Appendix 11, Section 6.3 "Certificate Verification".
//
// The signature algorithm used is ECDSA with the hash algorithm determined by the root's
// key size as specified in CSM_50:
//   - 256-bit ECC → SHA-256
//   - 384-bit ECC → SHA-384
//   - 512/521-bit ECC → SHA-512
//
// The certificate signature is verified over the encoded certificate body (including the
// certificate body tag and length) as specified in CSM_150.
func VerifyEccCertificateWithEccRoot(cert, root *securityv1.EccCertificate) error {
	if cert == nil {
		return fmt.Errorf("certificate cannot be nil")
	}
	if root == nil {
		return fmt.Errorf("root certificate cannot be nil")
	}
	cert.SetSignatureValid(false)
	// CSM_138: a certificate's CAR is its issuer's CHR.
	if car, chr := cert.GetCertificateAuthorityReference(), root.GetCertificateHolderReference(); car != chr {
		return fmt.Errorf("CAR %s does not name the issuer, whose CHR is %s", car, chr)
	}

	// Get root's public key
	rootPubKey := root.GetPublicKey()
	if rootPubKey == nil {
		return fmt.Errorf("root certificate has no public key")
	}
	if len(rootPubKey.GetPublicPointX()) == 0 || len(rootPubKey.GetPublicPointY()) == 0 {
		return fmt.Errorf("root certificate public key is incomplete")
	}

	// Parse root's curve parameters to determine hash size and curve
	hashBits, curve, err := parseCurveOID(rootPubKey.GetDomainParametersOid())
	if err != nil {
		return fmt.Errorf("failed to parse root certificate curve OID: %w", err)
	}

	// Extract and hash the certificate body (TBS - To Be Signed)
	// Per Appendix 11, Section 9.3.2, the signature is over the complete certificate
	// body (tag '7F 4E', including tag and length bytes), not the entire certificate.
	certRawData := cert.GetRawData()
	if len(certRawData) == 0 {
		return fmt.Errorf("certificate has no raw data")
	}

	// Parse the outer SEQUENCE to extract the certificate body
	var outerSeq asn1.RawValue
	_, err = asn1.Unmarshal(certRawData, &outerSeq)
	if err != nil {
		return fmt.Errorf("failed to parse certificate outer SEQUENCE: %w", err)
	}

	// Parse the certificate body SEQUENCE (this gives us the body with tag and length)
	var bodySeq asn1.RawValue
	_, err = asn1.Unmarshal(outerSeq.Bytes, &bodySeq)
	if err != nil {
		return fmt.Errorf("failed to parse certificate body SEQUENCE: %w", err)
	}

	// The certificate body to be signed includes the tag and length
	certBody := bodySeq.FullBytes

	hash, err := hashFor(hashBits, certBody)
	if err != nil {
		return err
	}

	// Get certificate signature
	certSignature := cert.GetSignature()
	if certSignature == nil {
		return fmt.Errorf("certificate has no signature")
	}
	if len(certSignature.GetR()) == 0 || len(certSignature.GetS()) == 0 {
		return fmt.Errorf("certificate signature is incomplete")
	}

	// Extract R and S components from signature
	r := new(big.Int).SetBytes(certSignature.GetR())
	s := new(big.Int).SetBytes(certSignature.GetS())

	// Construct root's public key
	rootX := new(big.Int).SetBytes(rootPubKey.GetPublicPointX())
	rootY := new(big.Int).SetBytes(rootPubKey.GetPublicPointY())

	ecdsaPub := &ecdsa.PublicKey{
		Curve: curve,
		X:     rootX,
		Y:     rootY,
	}

	// Verify ECDSA signature
	if !ecdsa.Verify(ecdsaPub, hash, r, s) {
		return fmt.Errorf("ECDSA certificate signature verification failed")
	}

	cert.SetSignatureValid(true)
	return nil
}

// VerifyEccCertificateWithCA verifies an ECC certificate against a CA certificate.
//
// This verifies the certificate signature using the CA's public key with ECDSA,
// following the same procedure as VerifyEccCertificateWithEccRoot but using
// the CA certificate as the signer.
func VerifyEccCertificateWithCA(cert, ca *securityv1.EccCertificate) error {
	// The verification process is identical whether verifying against root or CA
	return VerifyEccCertificateWithEccRoot(cert, ca)
}

// parseCurveOID parses an elliptic curve OID and returns the hash size in bits
// and the corresponding elliptic curve.
//
// Supported curves are defined in Appendix 11, Section 8.2.2, Table 1:
// - Brainpool curves: brainpoolP256r1, brainpoolP384r1, brainpoolP512r1
// - NIST curves: P-256, P-384, P-521
//
// Hash algorithm pairing (from CSM_50):
// - 256-bit curves → SHA-256
// - 384-bit curves → SHA-384
// - 512-bit curves → SHA-512
// - 521-bit curve (P-521) → SHA-512
func parseCurveOID(oid string) (hashBits int, curve elliptic.Curve, err error) {
	switch oid {
	case "1.3.36.3.3.2.8.1.1.7": // brainpoolP256r1
		return 256, brainpool.P256r1(), nil
	case "1.2.840.10045.3.1.7": // NIST P-256 (secp256r1)
		return 256, elliptic.P256(), nil
	case "1.3.36.3.3.2.8.1.1.11": // brainpoolP384r1
		return 384, brainpool.P384r1(), nil
	case "1.3.132.0.34": // NIST P-384 (secp384r1)
		return 384, elliptic.P384(), nil
	case "1.3.36.3.3.2.8.1.1.13": // brainpoolP512r1
		return 512, brainpool.P512r1(), nil
	case "1.3.132.0.35": // NIST P-521 (secp521r1)
		return 521, elliptic.P521(), nil
	default:
		return 0, nil, fmt.Errorf("unsupported curve OID: %s", oid)
	}
}

// hashFor hashes data with the SHA-2 function CSM_50 pairs with an ECC key size: SHA-256 for 256
// bits, SHA-384 for 384, SHA-512 for 512 and for P-521's 521.
func hashFor(bits int, data []byte) ([]byte, error) {
	switch bits {
	case 256:
		h := sha256.Sum256(data)
		return h[:], nil
	case 384:
		h := sha512.Sum384(data)
		return h[:], nil
	case 512, 521:
		h := sha512.Sum512(data)
		return h[:], nil
	default:
		return nil, fmt.Errorf("unsupported ECC key size: %d bits", bits)
	}
}

// EccSignatureAlgorithm names the data signature algorithm of a Gen2 key on the curve with this OID.
func EccSignatureAlgorithm(oid string) securityv1.SignatureAlgorithm {
	bits, _, err := parseCurveOID(oid)
	switch {
	case err != nil:
		return securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_UNSPECIFIED
	case bits == 256:
		return securityv1.SignatureAlgorithm_ECDSA_WITH_SHA256
	case bits == 384:
		return securityv1.SignatureAlgorithm_ECDSA_WITH_SHA384
	default:
		return securityv1.SignatureAlgorithm_ECDSA_WITH_SHA512
	}
}

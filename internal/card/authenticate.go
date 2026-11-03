package card

import (
	"context"
	"errors"
	"fmt"

	"github.com/way-platform/tachograph-go/internal/cert"
	"github.com/way-platform/tachograph-go/internal/security"
	cardv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/card/v1"
	ddv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/dd/v1"
	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
)

// AuthenticateOptions configures the card authentication process.
type AuthenticateOptions struct {
	// CertificateResolver is used to resolve CA certificates by their Certificate Authority Reference (CAR).
	CertificateResolver cert.Resolver
}

// AuthenticateRawCardFile performs cryptographic authentication on all signed Elementary Files
// in a raw card file. For each signed EF, it verifies the signature in the following signature
// block and populates the authentication field.
//
// This function mutates the rawFile parameter by setting the authentication field
// on signed EF records.
//
// Authentication is performed by:
// 1. Extracting the card certificate from the appropriate EF (e.g., EF_Card_Certificate)
// 2. Verifying the certificate chain against the European Root CA
// 3. Verifying the EF data signature using the card certificate
//
// If any EF fails authentication, its authentication.status will be set to the
// appropriate error status, and this function will return an error after processing
// all EFs.
func (opts AuthenticateOptions) AuthenticateRawCardFile(ctx context.Context, rawFile *cardv1.RawCardFile) error {
	if rawFile == nil {
		return fmt.Errorf("rawFile cannot be nil")
	}
	if opts.CertificateResolver == nil {
		opts.CertificateResolver = cert.DefaultResolver()
	}

	// Check which generations are present in the file
	// Many cards have both Gen1 and Gen2 data for backward compatibility
	hasGen1, hasGen2 := opts.detectGenerations(rawFile)

	var errs []error

	// Authenticate Gen1 data if present
	if hasGen1 {
		if err := opts.authenticateGen1CardFile(ctx, rawFile); err != nil {
			errs = append(errs, fmt.Errorf("Gen1 authentication failed: %w", err))
		}
	}

	// Authenticate Gen2 data if present
	if hasGen2 {
		if err := opts.authenticateGen2CardFile(ctx, rawFile); err != nil {
			errs = append(errs, fmt.Errorf("Gen2 authentication failed: %w", err))
		}
	}

	if !hasGen1 && !hasGen2 {
		return fmt.Errorf("unable to determine card generation")
	}

	return errors.Join(errs...)
}

// authenticateGen1CardFile authenticates a Generation 1 card file using RSA signature recovery.
func (opts AuthenticateOptions) authenticateGen1CardFile(ctx context.Context, rawFile *cardv1.RawCardFile) error {
	// Step 1: Extract certificates
	cardCert, mscaCert, err := opts.extractGen1CardCertificates(rawFile)
	if err != nil {
		return fmt.Errorf("failed to extract Gen1 certificates: %w", err)
	}

	// Step 2: Verify certificate chain
	if err := opts.verifyGen1CertificateChain(ctx, cardCert, mscaCert); err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	// Step 3: Authenticate each signed EF
	var errs []error
	records := rawFile.GetRecords()

	for i := 0; i < len(records); i++ {
		record := records[i]

		// Skip if not Gen1 or not a data record
		if record.GetGeneration() != ddv1.Generation_GENERATION_1 {
			continue
		}
		if record.GetContentType() != cardv1.ContentType_DATA {
			continue
		}

		// Skip unsigned EFs
		if !IsSignedFile(record.GetFile()) {
			continue
		}

		// Look for signature record (next record with same FID but signature type)
		var signatureRecord *cardv1.RawCardFile_Record
		if i+1 < len(records) {
			nextRecord := records[i+1]
			if nextRecord.GetFile() == record.GetFile() &&
				nextRecord.GetContentType() == cardv1.ContentType_SIGNATURE &&
				nextRecord.GetGeneration() == record.GetGeneration() {
				signatureRecord = nextRecord
			}
		}

		// Verify signature
		if err := opts.authenticateGen1EF(record, signatureRecord, cardCert); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// authenticateGen2CardFile authenticates a Generation 2 card file using ECDSA signature verification.
func (opts AuthenticateOptions) authenticateGen2CardFile(ctx context.Context, rawFile *cardv1.RawCardFile) error {
	// Step 1: Extract certificates
	cardCert, mscaCert, err := opts.extractGen2CardCertificates(rawFile)
	if err != nil {
		return fmt.Errorf("failed to extract Gen2 certificates: %w", err)
	}

	// Step 2: Verify certificate chain
	if err := opts.verifyGen2CertificateChain(ctx, cardCert, mscaCert); err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	// Step 3: Authenticate each signed EF
	var errs []error
	records := rawFile.GetRecords()

	for i := 0; i < len(records); i++ {
		record := records[i]

		// Skip if not Gen2 or not a data record
		if record.GetGeneration() != ddv1.Generation_GENERATION_2 {
			continue
		}
		if record.GetContentType() != cardv1.ContentType_DATA {
			continue
		}

		// Skip unsigned EFs
		if !IsSignedFile(record.GetFile()) {
			continue
		}

		// Look for signature record (next record with same FID but signature type)
		var signatureRecord *cardv1.RawCardFile_Record
		if i+1 < len(records) {
			nextRecord := records[i+1]
			if nextRecord.GetFile() == record.GetFile() &&
				nextRecord.GetContentType() == cardv1.ContentType_SIGNATURE &&
				nextRecord.GetGeneration() == record.GetGeneration() {
				signatureRecord = nextRecord
			}
		}

		// Verify signature
		if err := opts.authenticateGen2EF(record, signatureRecord, cardCert); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// detectGenerations checks which generations are present in the card file.
// Returns (hasGen1, hasGen2) booleans.
// Many cards have both Gen1 and Gen2 data for backward compatibility.
func (opts AuthenticateOptions) detectGenerations(rawFile *cardv1.RawCardFile) (bool, bool) {
	hasGen1 := false
	hasGen2 := false

	for _, record := range rawFile.GetRecords() {
		switch record.GetGeneration() {
		case ddv1.Generation_GENERATION_1:
			hasGen1 = true
		case ddv1.Generation_GENERATION_2:
			hasGen2 = true
		}

		// Early exit if we found both
		if hasGen1 && hasGen2 {
			return hasGen1, hasGen2
		}
	}

	return hasGen1, hasGen2
}

// extractGen1CardCertificates extracts the card and MSCA certificates from a Gen1 card file.
func (opts AuthenticateOptions) extractGen1CardCertificates(rawFile *cardv1.RawCardFile) (*securityv1.RsaCertificate, *securityv1.RsaCertificate, error) {
	var cardCert, mscaCert *securityv1.RsaCertificate
	var err error

	for _, record := range rawFile.GetRecords() {
		if record.GetGeneration() != ddv1.Generation_GENERATION_1 {
			continue
		}

		switch record.GetFile() {
		case cardv1.ElementaryFileType_EF_CARD_CERTIFICATE:
			cardCert, err = security.UnmarshalRsaCertificate(record.GetValue())
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse card certificate: %w", err)
			}

		case cardv1.ElementaryFileType_EF_CA_CERTIFICATE:
			mscaCert, err = security.UnmarshalRsaCertificate(record.GetValue())
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse MSCA certificate: %w", err)
			}
		}
	}

	if cardCert == nil {
		return nil, nil, fmt.Errorf("card certificate not found in Gen1 card file")
	}
	if mscaCert == nil {
		return nil, nil, fmt.Errorf("MSCA certificate not found in Gen1 card file")
	}

	return cardCert, mscaCert, nil
}

// extractGen2CardCertificates extracts the card and MSCA certificates from a Gen2 card file.
func (opts AuthenticateOptions) extractGen2CardCertificates(rawFile *cardv1.RawCardFile) (*securityv1.EccCertificate, *securityv1.EccCertificate, error) {
	var cardCert, mscaCert *securityv1.EccCertificate
	var err error

	for _, record := range rawFile.GetRecords() {
		if record.GetGeneration() != ddv1.Generation_GENERATION_2 {
			continue
		}

		switch record.GetFile() {
		case cardv1.ElementaryFileType_EF_CARD_SIGN_CERTIFICATE:
			cardCert, err = security.UnmarshalEccCertificate(record.GetValue())
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse card certificate: %w", err)
			}

		case cardv1.ElementaryFileType_EF_CA_CERTIFICATE:
			mscaCert, err = security.UnmarshalEccCertificate(record.GetValue())
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse MSCA certificate: %w", err)
			}
		}
	}

	if cardCert == nil {
		return nil, nil, fmt.Errorf("card certificate not found in Gen2 card file")
	}
	if mscaCert == nil {
		return nil, nil, fmt.Errorf("MSCA certificate not found in Gen2 card file")
	}

	return cardCert, mscaCert, nil
}

// verifyGen1CertificateChain verifies the Gen1 certificate chain: EUR Root -> MSCA -> Card
func (opts AuthenticateOptions) verifyGen1CertificateChain(ctx context.Context, cardCert *securityv1.RsaCertificate, mscaCert *securityv1.RsaCertificate) error {
	// Get EUR root certificate
	rootCert, err := opts.CertificateResolver.GetRootCertificate(ctx)
	if err != nil {
		return fmt.Errorf("failed to get root certificate: %w", err)
	}

	// Verify MSCA certificate against EUR root
	if err := security.VerifyRsaCertificateWithRoot(mscaCert, rootCert); err != nil {
		return fmt.Errorf("MSCA certificate verification failed: %w", err)
	}

	// Verify card certificate against MSCA
	if err := security.VerifyRsaCertificateWithCA(cardCert, mscaCert); err != nil {
		return fmt.Errorf("card certificate verification failed: %w", err)
	}

	return nil
}

// verifyGen2CertificateChain verifies the Gen2 certificate chain: EUR Root -> MSCA -> Card
func (opts AuthenticateOptions) verifyGen2CertificateChain(ctx context.Context, cardCert *securityv1.EccCertificate, mscaCert *securityv1.EccCertificate) error {
	// Get Gen2 ECC root certificate
	rootCert, err := opts.CertificateResolver.GetEccRootCertificate(ctx)
	if err != nil {
		return fmt.Errorf("failed to get Gen2 root certificate: %w", err)
	}

	// Verify MSCA certificate against EUR Gen2 root (both ECC)
	if err := security.VerifyEccCertificateWithEccRoot(mscaCert, rootCert); err != nil {
		return fmt.Errorf("MSCA certificate verification failed: %w", err)
	}

	// Verify card certificate against MSCA
	if err := security.VerifyEccCertificateWithCA(cardCert, mscaCert); err != nil {
		return fmt.Errorf("card certificate verification failed: %w", err)
	}

	return nil
}

// authenticateGen1EF authenticates a single Gen1 EF using RSA signature verification.
func (opts AuthenticateOptions) authenticateGen1EF(dataRecord *cardv1.RawCardFile_Record, signatureRecord *cardv1.RawCardFile_Record, cardCert *securityv1.RsaCertificate) error {
	auth := &securityv1.Authentication{}
	dataRecord.SetAuthentication(auth)

	if signatureRecord == nil {
		auth.SetStatus(securityv1.Authentication_DATA_SIGNATURE_INVALID)
		return fmt.Errorf("signature record not found for EF %v", dataRecord.GetFile())
	}

	// Verify the signature using PKCS#1 v1.5
	data := dataRecord.GetValue()
	signature := signatureRecord.GetValue()

	if err := security.VerifyRsaDataSignature(data, signature, cardCert); err != nil {
		auth.SetStatus(securityv1.Authentication_DATA_SIGNATURE_INVALID)
		return fmt.Errorf("signature verification failed for EF %v: %w", dataRecord.GetFile(), err)
	}

	// Authentication succeeded
	auth.SetStatus(securityv1.Authentication_VERIFIED)
	auth.SetSignatureAlgorithm(securityv1.SignatureAlgorithm_SHA1_WITH_RSA_ENCRYPTION)

	return nil
}

// authenticateGen2EF authenticates a single Gen2 EF using ECDSA signature verification.
func (opts AuthenticateOptions) authenticateGen2EF(dataRecord *cardv1.RawCardFile_Record, signatureRecord *cardv1.RawCardFile_Record, cardCert *securityv1.EccCertificate) error {
	auth := &securityv1.Authentication{}
	dataRecord.SetAuthentication(auth)

	if signatureRecord == nil {
		auth.SetStatus(securityv1.Authentication_DATA_SIGNATURE_INVALID)
		return fmt.Errorf("signature record not found for EF %v", dataRecord.GetFile())
	}

	// Verify the signature using ECDSA
	data := dataRecord.GetValue()
	signature := signatureRecord.GetValue()

	if err := security.VerifyEccDataSignature(data, signature, cardCert); err != nil {
		auth.SetStatus(securityv1.Authentication_DATA_SIGNATURE_INVALID)
		return fmt.Errorf("signature verification failed for EF %v: %w", dataRecord.GetFile(), err)
	}

	// Determine signature algorithm based on curve
	// We need to extract this from the certificate's public key
	pubKey := cardCert.GetPublicKey()
	var sigAlg securityv1.SignatureAlgorithm
	if pubKey != nil {
		oid := pubKey.GetDomainParametersOid()
		switch oid {
		case "1.3.36.3.3.2.8.1.1.7", "1.2.840.10045.3.1.7": // brainpoolP256r1, NIST P-256
			sigAlg = securityv1.SignatureAlgorithm_ECDSA_WITH_SHA256
		case "1.3.36.3.3.2.8.1.1.11", "1.3.132.0.34": // brainpoolP384r1, NIST P-384
			sigAlg = securityv1.SignatureAlgorithm_ECDSA_WITH_SHA384
		case "1.3.36.3.3.2.8.1.1.13", "1.3.132.0.35": // brainpoolP512r1, NIST P-521
			sigAlg = securityv1.SignatureAlgorithm_ECDSA_WITH_SHA512
		default:
			sigAlg = securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_UNSPECIFIED
		}
	}

	// Authentication succeeded
	auth.SetStatus(securityv1.Authentication_VERIFIED)
	auth.SetSignatureAlgorithm(sigAlg)

	return nil
}

// IsSignedFile reports whether the regulation signs an EF of a card download (Appendix 7,
// DDP_035): EF_ICC, EF_IC, EF_Card_Download and the certificate EFs are downloaded unsigned.
func IsSignedFile(fileType cardv1.ElementaryFileType) bool {
	// Per regulation, these EFs are NOT signed:
	// - EF_ICC, EF_IC (common card files)
	// - All certificate EFs
	// - EF_Card_Download (all variants)
	switch fileType {
	case cardv1.ElementaryFileType_EF_ICC,
		cardv1.ElementaryFileType_EF_IC,
		cardv1.ElementaryFileType_EF_CARD_CERTIFICATE,
		cardv1.ElementaryFileType_EF_CA_CERTIFICATE,
		cardv1.ElementaryFileType_EF_CARD_MA_CERTIFICATE,
		cardv1.ElementaryFileType_EF_CARD_SIGN_CERTIFICATE,
		cardv1.ElementaryFileType_EF_LINK_CERTIFICATE,
		cardv1.ElementaryFileType_EF_CARD_DOWNLOAD_DRIVER,
		cardv1.ElementaryFileType_EF_CARD_DOWNLOAD_WORKSHOP:
		return false
	default:
		return true
	}
}

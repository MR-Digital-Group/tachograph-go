package vu

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/way-platform/tachograph-go/internal/security"
	"github.com/way-platform/tachograph-go/internal/trust"
	ddv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/dd/v1"
	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
	vuv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/vu/v1"
)

// AuthenticateOptions configures the VU authentication process.
type AuthenticateOptions struct {
	// CertificateResolver supplies the trusted roots, link certificates and revocations.
	CertificateResolver trust.Resolver
	// ReceivedAt is when the download was received; its overview may be signed at most a day later.
	ReceivedAt time.Time
}

const (
	lenGen1Certificate = 194
	// idxGen1CurrentDateTime follows the two certificates, the VIN (17 bytes) and the registration (15 bytes).
	idxGen1CurrentDateTime = 2*lenGen1Certificate + 17 + 15
)

// vuChain is a generation's certificate chain, verified once per download. It holds the equipment
// certificate whenever the certificates verify, even when their validity is unknown.
type vuChain struct {
	auth *securityv1.Authentication
	gen1 *securityv1.RsaCertificate
	gen2 *securityv1.EccCertificate
}

// AuthenticateRawVehicleUnitFile sets an authentication on every record of rawFile. It fails only
// when rawFile is nil or the options lack a resolver or a receipt time.
func (opts AuthenticateOptions) AuthenticateRawVehicleUnitFile(rawFile *vuv1.RawVehicleUnitFile) error {
	switch {
	case rawFile == nil:
		return errors.New("rawFile cannot be nil")
	case opts.CertificateResolver == nil:
		return errors.New("a certificate resolver is required")
	case opts.ReceivedAt.IsZero():
		return errors.New("the time the download was received is required")
	}
	records := rawFile.GetRecords()
	gen1 := sync.OnceValue(func() *vuChain { return opts.gen1Chain(records) })
	gen2 := sync.OnceValue(func() *vuChain { return opts.gen2Chain(records) })
	for _, record := range records {
		switch {
		case record.GetType() == vuv1.TransferType_DOWNLOAD_INTERFACE_VERSION || record.GetType() == vuv1.TransferType_CARD_DOWNLOAD:
			record.SetAuthentication(trust.Status(securityv1.Authentication_UNSIGNED, fmt.Sprintf("the regulation leaves %v unsigned", record.GetType())))
		case record.GetGeneration() == ddv1.Generation_GENERATION_1:
			record.SetAuthentication(verifyGen1Transfer(record, gen1()))
		case record.GetGeneration() == ddv1.Generation_GENERATION_2:
			record.SetAuthentication(verifyGen2Transfer(record, gen2()))
		default:
			record.SetAuthentication(trust.Status(securityv1.Authentication_CERTIFICATE_VERIFICATION_FAILED, fmt.Sprintf("%v has no generation", record.GetType())))
		}
	}
	return nil
}

// findTransfer is the first transfer of one of the given types.
func findTransfer(records []*vuv1.RawVehicleUnitFile_Record, types ...vuv1.TransferType) *vuv1.RawVehicleUnitFile_Record {
	for _, record := range records {
		if slices.Contains(types, record.GetType()) {
			return record
		}
	}
	return nil
}

// recordArrayAt reads the record array at offset: its record type, its records and its size with the header.
func recordArrayAt(data []byte, offset int) (byte, [][]byte, int, error) {
	recordType, recordSize, noOfRecords, headerSize, err := parseRecordArrayHeader(data, offset)
	if err != nil {
		return 0, nil, 0, err
	}
	size := headerSize + int(recordSize)*int(noOfRecords)
	if offset+size > len(data) {
		return 0, nil, 0, fmt.Errorf("record array at offset %d needs %d bytes, %d remain", offset, size, len(data)-offset)
	}
	items := make([][]byte, noOfRecords)
	for i := range items {
		start := offset + headerSize + i*int(recordSize)
		items[i] = data[start : start+int(recordSize)]
	}
	return recordType, items, size, nil
}

// limitSigningTime fails a verified chain whose overview was signed more than a day after the download was received.
func (opts AuthenticateOptions) limitSigningTime(chain *vuChain, signedAt time.Time) {
	if chain.auth.GetStatus() != securityv1.Authentication_VERIFIED || !signedAt.After(opts.ReceivedAt.Add(24*time.Hour)) {
		return
	}
	chain.auth.SetStatus(securityv1.Authentication_CERTIFICATE_VERIFICATION_FAILED)
	chain.auth.SetDetail(fmt.Sprintf("the overview was signed at %s, more than a day after the download was received at %s",
		signedAt.Format(time.RFC3339), opts.ReceivedAt.UTC().Format(time.RFC3339)))
	chain.gen1, chain.gen2 = nil, nil
}

// date verifies a generation's chain at its overview's current date and time, which dates the
// download only once the overview's own signature verifies under the chain. When that signature
// fails or is missing, nothing dates the download: every signed transfer of the generation is
// CERTIFICATE_VALIDITY_UNKNOWN, unless its own signature fails.
func (opts AuthenticateOptions) date(overview *vuv1.RawVehicleUnitFile_Record, signedAt time.Time,
	verify func(trust.Window) *vuChain, verifyTransfer func(*vuv1.RawVehicleUnitFile_Record, *vuChain) *securityv1.Authentication,
) *vuChain {
	undated := verify(trust.Window{})
	if undated.gen1 == nil && undated.gen2 == nil {
		return undated
	}
	switch status := verifyTransfer(overview, undated).GetStatus(); status {
	case securityv1.Authentication_DATA_SIGNATURE_INVALID, securityv1.Authentication_SIGNATURE_MISSING:
		undated.auth = trust.WithStatus(undated.auth, securityv1.Authentication_CERTIFICATE_VALIDITY_UNKNOWN,
			fmt.Sprintf("the overview is %v, so its current date and time %s does not date the download", status, signedAt.Format(time.RFC3339)))
		return undated
	}
	chain := verify(trust.At(signedAt))
	opts.limitSigningTime(chain, signedAt)
	return chain
}

// gen1Chain verifies the chain in the Gen1 overview, dated by the overview's current date and time.
func (opts AuthenticateOptions) gen1Chain(records []*vuv1.RawVehicleUnitFile_Record) *vuChain {
	overview := findTransfer(records, vuv1.TransferType_OVERVIEW_GEN1)
	if overview == nil {
		return &vuChain{auth: trust.Status(securityv1.Authentication_CERTIFICATE_MISSING, "the download has no Gen1 overview, which carries the certificates")}
	}
	data, _, err := splitTransferValue(overview)
	if err != nil || len(data) < idxGen1CurrentDateTime+4 {
		return &vuChain{auth: trust.Status(securityv1.Authentication_CERTIFICATE_VERIFICATION_FAILED, "the Gen1 overview is too short for its certificates and current date and time")}
	}
	signedAt := time.Unix(int64(binary.BigEndian.Uint32(data[idxGen1CurrentDateTime:])), 0).UTC()
	return opts.date(overview, signedAt, func(w trust.Window) *vuChain {
		auth, signer := trust.VerifyGen1Chain(opts.CertificateResolver, data[:lenGen1Certificate], data[lenGen1Certificate:2*lenGen1Certificate], trust.VehicleUnit, w)
		return &vuChain{auth: auth, gen1: signer}
	}, verifyGen1Transfer)
}

// gen2Chain verifies the chain in the Gen2 overview, dated by the overview's current date and time.
func (opts AuthenticateOptions) gen2Chain(records []*vuv1.RawVehicleUnitFile_Record) *vuChain {
	overview := findTransfer(records, vuv1.TransferType_OVERVIEW_GEN2_V1, vuv1.TransferType_OVERVIEW_GEN2_V2)
	if overview == nil {
		return &vuChain{auth: trust.Status(securityv1.Authentication_CERTIFICATE_MISSING, "the download has no Gen2 overview, which carries the certificates")}
	}
	data, _, err := splitTransferValue(overview)
	if err != nil {
		return &vuChain{auth: trust.Status(securityv1.Authentication_CERTIFICATE_VERIFICATION_FAILED, fmt.Sprintf("Gen2 overview: %v", err))}
	}
	// The overview opens with the MSCA and VU certificate arrays, then VIN, registration and current date and time.
	var arrays [5][][]byte
	offset := 0
	for i := range arrays {
		_, items, size, err := recordArrayAt(data, offset)
		if err != nil {
			return &vuChain{auth: trust.Status(securityv1.Authentication_CERTIFICATE_VERIFICATION_FAILED, fmt.Sprintf("Gen2 overview: %v", err))}
		}
		arrays[i] = items
		offset += size
	}
	if len(arrays[0]) > 1 || len(arrays[1]) > 1 || len(arrays[4]) != 1 || len(arrays[4][0]) != 4 {
		return &vuChain{auth: trust.Status(securityv1.Authentication_CERTIFICATE_VERIFICATION_FAILED, "Gen2 overview: want at most one certificate per array and one 4-byte current date and time")}
	}
	signedAt := time.Unix(int64(binary.BigEndian.Uint32(arrays[4][0])), 0).UTC()
	var msca, equipment []byte
	if len(arrays[0]) == 1 {
		msca = arrays[0][0]
	}
	if len(arrays[1]) == 1 {
		equipment = arrays[1][0]
	}
	return opts.date(overview, signedAt, func(w trust.Window) *vuChain {
		auth, signer := trust.VerifyGen2Chain(opts.CertificateResolver, msca, equipment, nil, trust.VehicleUnit, w)
		return &vuChain{auth: auth, gen2: signer}
	}, verifyGen2Transfer)
}

// verifyGen1Transfer verifies a Gen1 transfer's PKCS#1 signature: over the overview's data after
// its two certificates, over all the data of another transfer (Appendix 7, 2.2.6).
func verifyGen1Transfer(record *vuv1.RawVehicleUnitFile_Record, chain *vuChain) *securityv1.Authentication {
	data, signature, err := splitTransferValue(record)
	if err != nil {
		return trust.WithStatus(chain.auth, securityv1.Authentication_DATA_SIGNATURE_INVALID, err.Error())
	}
	if trust.Blank(signature) {
		return trust.WithStatus(chain.auth, securityv1.Authentication_SIGNATURE_MISSING, "the transfer's signature is empty or zeroed")
	}
	if chain.gen1 == nil {
		return proto.CloneOf(chain.auth)
	}
	if record.GetType() == vuv1.TransferType_OVERVIEW_GEN1 {
		if len(data) < 2*lenGen1Certificate {
			return trust.WithStatus(chain.auth, securityv1.Authentication_DATA_SIGNATURE_INVALID, "the overview is shorter than its certificates")
		}
		data = data[2*lenGen1Certificate:]
	}
	if err := security.VerifyRsaDataSignature(data, signature, chain.gen1); err != nil {
		return trust.WithStatus(chain.auth, securityv1.Authentication_DATA_SIGNATURE_INVALID, err.Error())
	}
	return proto.CloneOf(chain.auth)
}

// verifyGen2Transfer verifies the ECDSA signature in a Gen2 transfer's SignatureRecordArray: over
// the overview's data after its certificate arrays, over all the data of another transfer.
func verifyGen2Transfer(record *vuv1.RawVehicleUnitFile_Record, chain *vuChain) *securityv1.Authentication {
	data, signatureArray, err := splitTransferValue(record)
	if err != nil {
		return trust.WithStatus(chain.auth, securityv1.Authentication_DATA_SIGNATURE_INVALID, err.Error())
	}
	recordType, signatures, size, err := recordArrayAt(signatureArray, 0)
	switch {
	case err != nil:
		return trust.WithStatus(chain.auth, securityv1.Authentication_DATA_SIGNATURE_INVALID, fmt.Sprintf("SignatureRecordArray: %v", err))
	case size != len(signatureArray):
		return trust.WithStatus(chain.auth, securityv1.Authentication_DATA_SIGNATURE_INVALID, fmt.Sprintf("SignatureRecordArray: %d bytes follow it", len(signatureArray)-size))
	case len(signatures) == 0:
		return trust.WithStatus(chain.auth, securityv1.Authentication_SIGNATURE_MISSING, "the transfer's SignatureRecordArray holds no signature")
	case recordType != recordTypeSignature || len(signatures) != 1:
		return trust.WithStatus(chain.auth, securityv1.Authentication_DATA_SIGNATURE_INVALID,
			fmt.Sprintf("the SignatureRecordArray holds %d records of type 0x%02X, want one of type 0x%02X", len(signatures), recordType, recordTypeSignature))
	case trust.Blank(signatures[0]):
		return trust.WithStatus(chain.auth, securityv1.Authentication_SIGNATURE_MISSING, "the transfer's signature is zeroed")
	case chain.gen2 == nil:
		return proto.CloneOf(chain.auth)
	}
	if record.GetType() == vuv1.TransferType_OVERVIEW_GEN2_V1 || record.GetType() == vuv1.TransferType_OVERVIEW_GEN2_V2 {
		offset := 0
		for range 2 {
			_, _, size, err := recordArrayAt(data, offset)
			if err != nil {
				return trust.WithStatus(chain.auth, securityv1.Authentication_DATA_SIGNATURE_INVALID, fmt.Sprintf("overview certificates: %v", err))
			}
			offset += size
		}
		data = data[offset:]
	}
	if err := security.VerifyEccDataSignature(data, signatures[0], chain.gen2); err != nil {
		return trust.WithStatus(chain.auth, securityv1.Authentication_DATA_SIGNATURE_INVALID, err.Error())
	}
	return proto.CloneOf(chain.auth)
}

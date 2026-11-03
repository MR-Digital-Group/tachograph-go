package tachographtest

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"

	"github.com/way-platform/tachograph-go"
	"github.com/way-platform/tachograph-go/internal/card"
	cardv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/card/v1"
	ddv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/dd/v1"
	tachographv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/v1"
	vuv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/vu/v1"
)

// Record types of Gen2 record arrays (Data Dictionary 2.120).
const (
	recordTypeMemberStateCertificate = 0x04
	recordTypeSignature              = 0x08
	recordTypeVuCertificate          = 0x0F
)

const lenGen1Certificate = 194

// SignVehicleUnitFile re-signs a VU download the way Appendix 7 lays it out: the overview of each
// generation carries that chain's MSCA and equipment certificates, and every transfer of the
// generation is signed with the chain's key, the overview over the data after its certificates.
// A nil chain leaves its generation as it is; download interface version and card download
// transfers stay unsigned.
func SignVehicleUnitFile(tb testing.TB, data []byte, gen1 *Gen1Chain, gen2 *Gen2Chain) []byte {
	tb.Helper()
	raw, err := tachograph.UnmarshalOptions{Strict: true}.Unmarshal(data)
	if err != nil {
		tb.Fatalf("unmarshal VU download: %v", err)
	}
	if raw.GetType() != tachographv1.RawFile_VEHICLE_UNIT {
		tb.Fatalf("not a VU download: %v", raw.GetType())
	}
	var out []byte
	for _, record := range raw.GetVehicleUnit().GetRecords() {
		value := record.GetValue()
		body := value[:len(value)-int(record.GetSignatureSize())]
		unsigned := record.GetType() == vuv1.TransferType_DOWNLOAD_INTERFACE_VERSION || record.GetType() == vuv1.TransferType_CARD_DOWNLOAD
		switch {
		case !unsigned && record.GetGeneration() == ddv1.Generation_GENERATION_1 && gen1 != nil:
			body = bytes.Clone(body)
			signed := body
			if record.GetType() == vuv1.TransferType_OVERVIEW_GEN1 {
				if len(body) < 2*lenGen1Certificate {
					tb.Fatalf("Gen1 overview of %d bytes", len(body))
				}
				clear(body[:2*lenGen1Certificate])
				copy(body[:lenGen1Certificate], gen1.MSCACertificate)
				copy(body[lenGen1Certificate:2*lenGen1Certificate], gen1.EquipmentCertificate)
				signed = body[2*lenGen1Certificate:]
			}
			value = slices.Concat(body, gen1.EquipmentKey.sign(tb, signed))
		case !unsigned && record.GetGeneration() == ddv1.Generation_GENERATION_2 && gen2 != nil:
			var certificates []byte
			if record.GetType() == vuv1.TransferType_OVERVIEW_GEN2_V1 || record.GetType() == vuv1.TransferType_OVERVIEW_GEN2_V2 {
				offset := 0
				for range 2 {
					if offset+5 > len(body) {
						tb.Fatalf("%v: no certificate record arrays", record.GetType())
					}
					offset += 5 + int(binary.BigEndian.Uint16(body[offset+1:]))*int(binary.BigEndian.Uint16(body[offset+3:]))
				}
				if offset > len(body) {
					tb.Fatalf("%v: certificate record arrays overrun the transfer", record.GetType())
				}
				certificates = slices.Concat(
					recordArray(recordTypeMemberStateCertificate, gen2.MSCACertificate),
					recordArray(recordTypeVuCertificate, gen2.EquipmentCertificate),
				)
				body = body[offset:]
			}
			value = slices.Concat(certificates, body, recordArray(recordTypeSignature, gen2.EquipmentKey.sign(tb, body)))
		}
		out = binary.BigEndian.AppendUint16(out, uint16(record.GetTag()))
		out = append(out, value...)
	}
	return append(out, raw.GetVehicleUnit().GetTrailingData()...)
}

// recordArray is a record array of one record, or of none when record is empty.
func recordArray(recordType byte, record []byte) []byte {
	if len(record) == 0 {
		return []byte{recordType, 0x00, 0x00, 0x00, 0x00}
	}
	return slices.Concat([]byte{recordType}, binary.BigEndian.AppendUint16(nil, uint16(len(record))), []byte{0x00, 0x01}, record)
}

// replacedCertificates are the certificate EFs SignDriverCardFile writes itself.
var replacedCertificates = []cardv1.ElementaryFileType{
	cardv1.ElementaryFileType_EF_CARD_CERTIFICATE,
	cardv1.ElementaryFileType_EF_CARD_SIGN_CERTIFICATE,
	cardv1.ElementaryFileType_EF_CA_CERTIFICATE,
	cardv1.ElementaryFileType_EF_LINK_CERTIFICATE,
}

// SignDriverCardFile re-signs a driver card download the way Appendix 7 (DDP_035, 3.4.2) lays it
// out: a DF with a chain carries the chain's certificate EFs before its first EF (Gen1: card and
// CA certificates; Gen2: card sign, CA and, when the chain has one, link certificates) and a
// signature after every EF the regulation signs, replacing the DF's earlier certificates and
// signatures. A nil chain leaves its DF as it is; the MF's EF_ICC and EF_IC stay unsigned.
func SignDriverCardFile(tb testing.TB, data []byte, gen1 *Gen1Chain, gen2 *Gen2Chain) []byte {
	tb.Helper()
	raw, err := tachograph.UnmarshalOptions{Strict: true}.Unmarshal(data)
	if err != nil {
		tb.Fatalf("unmarshal card download: %v", err)
	}
	if raw.GetType() != tachographv1.RawFile_CARD {
		tb.Fatalf("not a card download: %v", raw.GetType())
	}
	certificate := func(tag int32, value []byte) []byte {
		if len(value) == 0 {
			return nil
		}
		return cardRecord(tag, value)
	}
	pending := make(map[ddv1.Generation][]byte)
	sign := make(map[ddv1.Generation]func([]byte) []byte)
	if gen1 != nil {
		pending[ddv1.Generation_GENERATION_1] = slices.Concat(certificate(0xC10000, gen1.EquipmentCertificate), certificate(0xC10800, gen1.MSCACertificate))
		sign[ddv1.Generation_GENERATION_1] = func(value []byte) []byte { return gen1.EquipmentKey.sign(tb, value) }
	}
	if gen2 != nil {
		pending[ddv1.Generation_GENERATION_2] = slices.Concat(certificate(0xC10102, gen2.EquipmentCertificate), certificate(0xC10802, gen2.MSCACertificate), certificate(0xC10902, gen2.LinkCertificate))
		sign[ddv1.Generation_GENERATION_2] = func(value []byte) []byte { return gen2.EquipmentKey.sign(tb, value) }
	}
	var out []byte
	for _, record := range raw.GetCard().GetRecords() {
		generation, file := record.GetGeneration(), record.GetFile()
		signer, resigned := sign[generation]
		if !resigned || file == cardv1.ElementaryFileType_EF_ICC || file == cardv1.ElementaryFileType_EF_IC {
			out = append(out, cardRecord(record.GetTag(), record.GetValue())...)
			continue
		}
		out = append(out, pending[generation]...)
		delete(pending, generation)
		if record.GetContentType() == cardv1.ContentType_SIGNATURE || slices.Contains(replacedCertificates, file) {
			continue
		}
		out = append(out, cardRecord(record.GetTag(), record.GetValue())...)
		if card.IsSignedFile(file) {
			out = append(out, cardRecord(record.GetTag()|0x01, signer(record.GetValue()))...)
		}
	}
	for _, generation := range []ddv1.Generation{ddv1.Generation_GENERATION_1, ddv1.Generation_GENERATION_2} {
		out = append(out, pending[generation]...)
	}
	return out
}

// cardRecord encodes a card download TLV record: FID and appendix, a 2-byte length, the value.
func cardRecord(tag int32, value []byte) []byte {
	return slices.Concat([]byte{byte(tag >> 16), byte(tag >> 8), byte(tag)}, binary.BigEndian.AppendUint16(nil, uint16(len(value))), value)
}

package tachographtest_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/way-platform/tachograph-go"
	"github.com/way-platform/tachograph-go/internal/security"
	ddv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/dd/v1"
	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
	vuv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/vu/v1"
	"github.com/way-platform/tachograph-go/tachographtest"
)

// gen1Equipment recovers a Gen1 chain's equipment certificate under the PKI's root key.
func gen1Equipment(t *testing.T, pki *tachographtest.PKI, chain *tachographtest.Gen1Chain) *securityv1.RsaCertificate {
	t.Helper()
	root, err := security.UnmarshalRootCertificate(pki.Gen1Root.RootKey())
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	msca, err := security.UnmarshalRsaCertificate(chain.MSCACertificate)
	if err != nil {
		t.Fatalf("MSCA certificate: %v", err)
	}
	if err := security.VerifyRsaCertificateWithRoot(msca, root); err != nil {
		t.Fatalf("MSCA certificate: %v", err)
	}
	equipment, err := security.UnmarshalRsaCertificate(chain.EquipmentCertificate)
	if err != nil {
		t.Fatalf("equipment certificate: %v", err)
	}
	if err := security.VerifyRsaCertificateWithCA(equipment, msca); err != nil {
		t.Fatalf("equipment certificate: %v", err)
	}
	return equipment
}

func TestSignVehicleUnitFile(t *testing.T) {
	pki := tachographtest.NewPKI(t)
	gen1, gen2 := pki.Gen1VehicleUnit(t), pki.Gen2VehicleUnit(t)
	empty := func(recordType byte) []byte { return []byte{recordType, 0x00, 0x00, 0x00, 0x00} }
	overviewGen2 := slices.Concat(
		empty(0x04), empty(0x0F), empty(0x0A), empty(0x0B),
		[]byte{0x03, 0x00, 0x04, 0x00, 0x01, 0x6A, 0x00, 0x00, 0x00}, // current date and time
		empty(0x13), empty(0x02), empty(0x14), empty(0x10), empty(0x11), empty(0x08),
	)
	data := slices.Concat(
		[]byte{0x76, 0x01}, make([]byte, 491+1+1+128), // Gen1 overview without locks or controls
		[]byte{0x76, 0x05}, make([]byte, 116+20+1+128), // Gen1 technical data without calibrations
		[]byte{0x76, 0x00, 0x02, 0x02}, // download interface version
		[]byte{0x76, 0x31}, overviewGen2,
		[]byte{0x76, 0x35}, empty(0x19), empty(0x08),
	)
	raw, err := tachograph.Unmarshal(tachographtest.SignVehicleUnitFile(t, data, gen1, gen2))
	if err != nil {
		t.Fatalf("unmarshal the signed download: %v", err)
	}
	gen1Signer := gen1Equipment(t, pki, gen1)
	gen2Signer := gen2Certificate(t, gen2.EquipmentCertificate)
	certificates := slices.Concat(
		[]byte{0x04}, binary.BigEndian.AppendUint16(nil, uint16(len(gen2.MSCACertificate))), []byte{0x00, 0x01}, gen2.MSCACertificate,
		[]byte{0x0F}, binary.BigEndian.AppendUint16(nil, uint16(len(gen2.EquipmentCertificate))), []byte{0x00, 0x01}, gen2.EquipmentCertificate,
	)
	for _, r := range raw.GetVehicleUnit().GetRecords() {
		value := r.GetValue()
		split := len(value) - int(r.GetSignatureSize())
		body, signature := value[:split], value[split:]
		switch {
		case r.GetType() == vuv1.TransferType_DOWNLOAD_INTERFACE_VERSION:
			if !bytes.Equal(value, []byte{0x02, 0x02}) {
				t.Errorf("download interface version = % X, want it unchanged", value)
			}
		case r.GetGeneration() == ddv1.Generation_GENERATION_1:
			if r.GetType() == vuv1.TransferType_OVERVIEW_GEN1 {
				if !bytes.Equal(body[:2*194], slices.Concat(gen1.MSCACertificate, gen1.EquipmentCertificate)) {
					t.Error("the Gen1 overview does not open with the chain's certificates")
				}
				body = body[2*194:]
			}
			if err := security.VerifyRsaDataSignature(body, signature, gen1Signer); err != nil {
				t.Errorf("%v: %v", r.GetType(), err)
			}
		default:
			if r.GetType() == vuv1.TransferType_OVERVIEW_GEN2_V2 {
				if !bytes.HasPrefix(body, certificates) {
					t.Error("the Gen2 overview does not open with the chain's certificate record arrays")
				}
				body = body[len(certificates):]
			}
			if !bytes.Equal(signature[:5], []byte{0x08, 0x00, 0x40, 0x00, 0x01}) {
				t.Errorf("%v: signature record array header % X", r.GetType(), signature[:5])
			}
			if err := security.VerifyEccDataSignature(body, signature[5:], gen2Signer); err != nil {
				t.Errorf("%v: %v", r.GetType(), err)
			}
		}
	}
}

func TestSignDriverCardFile(t *testing.T) {
	pki := tachographtest.NewPKI(t)
	gen1, gen2 := pki.Gen1DriverCard(t), pki.Gen2DriverCard(t)
	gen2.LinkCertificate = pki.Gen2LinkCertificate
	record := func(fid uint16, appendix byte, value []byte) []byte {
		return slices.Concat(binary.BigEndian.AppendUint16(nil, fid), []byte{appendix}, binary.BigEndian.AppendUint16(nil, uint16(len(value))), value)
	}
	data := slices.Concat(
		record(0x0002, 0x00, make([]byte, 25)),              // EF_ICC
		record(0x0005, 0x00, make([]byte, 8)),               // EF_IC
		record(0x0501, 0x00, []byte("Gen1 application")),    // EF_Application_Identification
		record(0x0501, 0x01, make([]byte, 128)),             // its stale signature
		record(0x050E, 0x00, make([]byte, 4)),               // EF_Card_Download, unsigned
		record(0x0520, 0x02, []byte("Gen2 identification")), // EF_Identification in Tachograph_G2
	)
	raw, err := tachograph.Unmarshal(tachographtest.SignDriverCardFile(t, data, gen1, gen2))
	if err != nil {
		t.Fatalf("unmarshal the signed download: %v", err)
	}
	records := raw.GetCard().GetRecords()
	var got []string
	for _, r := range records {
		got = append(got, fmt.Sprintf("%v %v %v", r.GetFile(), r.GetGeneration(), r.GetContentType()))
	}
	want := []string{
		"EF_ICC GENERATION_1 DATA",
		"EF_IC GENERATION_1 DATA",
		"EF_CARD_CERTIFICATE GENERATION_1 DATA",
		"EF_CA_CERTIFICATE GENERATION_1 DATA",
		"EF_APPLICATION_IDENTIFICATION GENERATION_1 DATA",
		"EF_APPLICATION_IDENTIFICATION GENERATION_1 SIGNATURE",
		"EF_CARD_DOWNLOAD_DRIVER GENERATION_1 DATA",
		"EF_CARD_SIGN_CERTIFICATE GENERATION_2 DATA",
		"EF_CA_CERTIFICATE GENERATION_2 DATA",
		"EF_LINK_CERTIFICATE GENERATION_2 DATA",
		"EF_IDENTIFICATION GENERATION_2 DATA",
		"EF_IDENTIFICATION GENERATION_2 SIGNATURE",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("records (-want +got):\n%s", diff)
	}
	for i, certificate := range map[int][]byte{2: gen1.EquipmentCertificate, 3: gen1.MSCACertificate, 7: gen2.EquipmentCertificate, 8: gen2.MSCACertificate, 9: gen2.LinkCertificate} {
		if !bytes.Equal(records[i].GetValue(), certificate) {
			t.Errorf("record %d does not hold its certificate", i)
		}
	}
	if err := security.VerifyRsaDataSignature(records[4].GetValue(), records[5].GetValue(), gen1Equipment(t, pki, gen1)); err != nil {
		t.Errorf("Gen1 EF_Application_Identification: %v", err)
	}
	if err := security.VerifyEccDataSignature(records[10].GetValue(), records[11].GetValue(), gen2Certificate(t, gen2.EquipmentCertificate)); err != nil {
		t.Errorf("Gen2 EF_Identification: %v", err)
	}
}

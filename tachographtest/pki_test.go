package tachographtest_test

import (
	"bytes"
	"testing"

	"github.com/way-platform/tachograph-go/internal/security"
	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
	"github.com/way-platform/tachograph-go/tachographtest"
)

// gen2Certificate parses a Gen2 certificate.
func gen2Certificate(t *testing.T, raw []byte) *securityv1.EccCertificate {
	t.Helper()
	c, err := security.UnmarshalEccCertificate(raw)
	if err != nil {
		t.Fatalf("unmarshal Gen2 certificate: %v", err)
	}
	return c
}

func TestPKIGen2CertificatesVerifyUnderTheirIssuers(t *testing.T) {
	pki := tachographtest.NewPKI(t)
	msca521, msca521Certificate := tachographtest.NewGen2MSCA(t, pki.Gen2Root, tachographtest.P521)
	vu521 := tachographtest.Gen2Equipment(t, msca521, msca521Certificate, tachographtest.P521, tachographtest.EquipmentVehicleUnitSign)
	erca := tachographtest.Gen2CHA(tachographtest.EquipmentERCA)
	msca := tachographtest.Gen2CHA(tachographtest.EquipmentMSCA)
	tests := []struct {
		name        string
		certificate []byte
		issuer      []byte
		cha         [7]byte
	}{
		{"root", pki.Gen2RootCertificate, pki.Gen2RootCertificate, erca},
		{"next root", pki.Gen2NextRootCertificate, pki.Gen2NextRootCertificate, erca},
		{"link", pki.Gen2LinkCertificate, pki.Gen2RootCertificate, erca},
		{"MSCA", pki.Gen2MSCACertificate, pki.Gen2RootCertificate, msca},
		{"next MSCA", pki.Gen2NextMSCACertificate, pki.Gen2NextRootCertificate, msca},
		{"P-521 MSCA", msca521Certificate, pki.Gen2RootCertificate, msca},
		{"P-521 VU", vu521.EquipmentCertificate, msca521Certificate, tachographtest.Gen2CHA(tachographtest.EquipmentVehicleUnitSign)},
		{"VU", pki.Gen2VehicleUnit(t).EquipmentCertificate, pki.Gen2MSCACertificate, tachographtest.Gen2CHA(tachographtest.EquipmentVehicleUnitSign)},
		{"driver card", pki.Gen2DriverCard(t).EquipmentCertificate, pki.Gen2MSCACertificate, tachographtest.Gen2CHA(tachographtest.EquipmentDriverCardSign)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := gen2Certificate(t, tt.certificate)
			if err := security.VerifyEccCertificateWithEccRoot(c, gen2Certificate(t, tt.issuer)); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if got := c.GetCertificateHolderAuthorisation(); !bytes.Equal(got, tt.cha[:]) {
				t.Errorf("holder authorisation = %X, want %X", got, tt.cha)
			}
		})
	}
}

func TestPKIGen1CertificatesVerifyUnderTheirIssuers(t *testing.T) {
	pki := tachographtest.NewPKI(t)
	root, err := security.UnmarshalRootCertificate(pki.Gen1Root.RootKey())
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	msca, err := security.UnmarshalRsaCertificate(pki.Gen1MSCACertificate)
	if err != nil {
		t.Fatal(err)
	}
	if err := security.VerifyRsaCertificateWithRoot(msca, root); err != nil {
		t.Fatalf("MSCA certificate: %v", err)
	}
	if want := tachographtest.Gen1CHA(tachographtest.EquipmentMemberState); !bytes.Equal(msca.GetCertificateHolderAuthorisation(), want[:]) {
		t.Errorf("MSCA holder authorisation = %X, want %X", msca.GetCertificateHolderAuthorisation(), want)
	}
	tests := []struct {
		name  string
		chain *tachographtest.Gen1Chain
		cha   [7]byte
	}{
		{"VU", pki.Gen1VehicleUnit(t), tachographtest.Gen1CHA(tachographtest.EquipmentVehicleUnit)},
		{"driver card", pki.Gen1DriverCard(t), tachographtest.Gen1CHA(tachographtest.EquipmentDriverCard)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			equipment := gen1Equipment(t, pki, tt.chain)
			if got := equipment.GetCertificateHolderAuthorisation(); !bytes.Equal(got, tt.cha[:]) {
				t.Errorf("holder authorisation = %X, want %X", got, tt.cha)
			}
			if got := equipment.GetEndOfValidity().AsTime(); !got.Equal(tachographtest.EquipmentValidity.To) {
				t.Errorf("end of validity = %v, want %v", got, tachographtest.EquipmentValidity.To)
			}
		})
	}
}

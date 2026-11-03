package security

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/way-platform/tachograph-go/internal/cert/certcache"
	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
)

// gen2Root parses the embedded ERCA Gen2(1) root certificate and verifies its self-signature.
func gen2Root(t *testing.T) *securityv1.EccCertificate {
	t.Helper()
	root, err := UnmarshalEccCertificate(certcache.RootG2())
	if err != nil {
		t.Fatalf("unmarshal the ERCA Gen2 root: %v", err)
	}
	if err := VerifyEccCertificateWithCA(root, root); err != nil {
		t.Fatalf("the ERCA Gen2 root does not verify itself: %v", err)
	}
	if !root.GetSignatureValid() {
		t.Fatal("signature_valid = false after the root verified itself")
	}
	return root
}

// finlandMSCA parses a Finnish Gen2 MSCA certificate as JRC publishes it.
func finlandMSCA(t *testing.T, name string) *securityv1.EccCertificate {
	t.Helper()
	data, err := os.ReadFile("testdata/certs/g2/" + name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	cert, err := UnmarshalEccCertificate(data)
	if err != nil {
		t.Fatalf("unmarshal %s: %v", name, err)
	}
	return cert
}

func TestVerifyEccCertificateWithCA(t *testing.T) {
	root := gen2Root(t)
	if got, want := root.GetCertificateHolderReference(), "18250066869740371713"; got != want {
		t.Errorf("root CHR = %s, want %s (FD45432001FFFF01)", got, want)
	}
	tests := []struct {
		file string
		chr  string
	}{
		{"finland_msca_card42.bin", "1316820541130145537"},
		{"finland_msca_card43.bin", "1316820541146922753"},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			msca := finlandMSCA(t, tt.file)
			if err := VerifyEccCertificateWithCA(msca, root); err != nil {
				t.Fatalf("VerifyEccCertificateWithCA() = %v", err)
			}
			if !msca.GetSignatureValid() {
				t.Error("signature_valid = false after verification")
			}
			if got := msca.GetCertificateHolderReference(); got != tt.chr {
				t.Errorf("CHR = %s, want %s", got, tt.chr)
			}
		})
	}
}

func TestVerifyEccCertificateWithCA_InvalidSignature(t *testing.T) {
	root := gen2Root(t)
	msca := finlandMSCA(t, "finland_msca_card42.bin")
	r := slices.Clone(msca.GetSignature().GetR())
	r[0] ^= 0x01
	msca.GetSignature().SetR(r)
	if err := VerifyEccCertificateWithCA(msca, root); err == nil {
		t.Error("VerifyEccCertificateWithCA() accepted a corrupted signature")
	}
	if msca.GetSignatureValid() {
		t.Error("signature_valid = true after a failed verification")
	}
}

func TestVerifyEccCertificateWithCA_CARMismatch(t *testing.T) {
	card42 := finlandMSCA(t, "finland_msca_card42.bin")
	card43 := finlandMSCA(t, "finland_msca_card43.bin")
	err := VerifyEccCertificateWithCA(card42, card43)
	if err == nil || !strings.Contains(err.Error(), "does not name the issuer") {
		t.Errorf("VerifyEccCertificateWithCA() = %v, want an issuer reference error", err)
	}
}

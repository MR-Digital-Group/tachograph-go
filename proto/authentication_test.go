package proto

import (
	"testing"
	"time"

	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestAuthenticationStatusNumbers pins the wire numbers: new statuses are appended, never renumbered.
func TestAuthenticationStatusNumbers(t *testing.T) {
	for status, want := range map[securityv1.Authentication_Status]int32{
		securityv1.Authentication_VERIFIED:                        1,
		securityv1.Authentication_DATA_SIGNATURE_INVALID:          2,
		securityv1.Authentication_CERTIFICATE_VERIFICATION_FAILED: 3,
		securityv1.Authentication_UNSIGNED:                        4,
		securityv1.Authentication_SIGNATURE_MISSING:               5,
		securityv1.Authentication_CERTIFICATE_REVOKED:             6,
		securityv1.Authentication_CERTIFICATE_UNTRUSTED:           7,
		securityv1.Authentication_CERTIFICATE_MISSING:             8,
		securityv1.Authentication_CERTIFICATE_VALIDITY_UNKNOWN:    9,
	} {
		if got := int32(status.Number()); got != want {
			t.Errorf("%v = %d, want %d", status, got, want)
		}
	}
}

func TestAuthenticationCarriesTheChainAndTheSigningWindow(t *testing.T) {
	ca := &securityv1.CertificateInfo{}
	ca.SetCertificateHolderReference("1316820541130145537")
	link := &securityv1.CertificateInfo{}
	link.SetCertificateHolderReference("18250066869740371713")
	start := time.Date(2020, 7, 18, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 3, 12, 0, 0, 0, 0, time.UTC)
	auth := &securityv1.Authentication{}
	auth.SetCaCertificate(ca)
	auth.SetLinkCertificate(link)
	auth.SetDetail("no trusted root")
	auth.SetSigningWindowStart(timestamppb.New(start))
	auth.SetSigningWindowEnd(timestamppb.New(end))
	if auth.GetCaCertificate().GetCertificateHolderReference() != "1316820541130145537" ||
		auth.GetLinkCertificate().GetCertificateHolderReference() != "18250066869740371713" ||
		auth.GetDetail() != "no trusted root" ||
		!auth.GetSigningWindowStart().AsTime().Equal(start) || !auth.GetSigningWindowEnd().AsTime().Equal(end) ||
		auth.HasSignatureCreationTime() {
		t.Errorf("chain and window fields did not round-trip: %v", auth)
	}
	rsa := &securityv1.RsaCertificate{}
	rsa.SetCertificateHolderAuthorisation([]byte{0xFF, 0x54, 0x41, 0x43, 0x48, 0x4F, 0x00})
	if len(rsa.GetCertificateHolderAuthorisation()) != 7 {
		t.Error("RsaCertificate has no holder authorisation")
	}
}

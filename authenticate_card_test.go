package tachograph_test

import (
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/way-platform/tachograph-go"
	"github.com/way-platform/tachograph-go/internal/card"
	cardv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/card/v1"
	ddv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/dd/v1"
	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
	"github.com/way-platform/tachograph-go/tachographtest"
)

func isIdentification(r *cardv1.RawCardFile_Record) bool {
	return r.GetFile() == cardv1.ElementaryFileType_EF_IDENTIFICATION
}

// unsignedCardFiles are the EFs a card download leaves unsigned (Appendix 7, DDP_035): EF_ICC,
// EF_IC, EF_Card_Download and the certificate EFs. Every other EF is signed.
var unsignedCardFiles = []cardv1.ElementaryFileType{
	cardv1.ElementaryFileType_EF_ICC,
	cardv1.ElementaryFileType_EF_IC,
	cardv1.ElementaryFileType_EF_CARD_DOWNLOAD_DRIVER,
	cardv1.ElementaryFileType_EF_CARD_DOWNLOAD_WORKSHOP,
	cardv1.ElementaryFileType_EF_CARD_CERTIFICATE,
	cardv1.ElementaryFileType_EF_CA_CERTIFICATE,
	cardv1.ElementaryFileType_EF_CARD_MA_CERTIFICATE,
	cardv1.ElementaryFileType_EF_CARD_SIGN_CERTIFICATE,
	cardv1.ElementaryFileType_EF_LINK_CERTIFICATE,
}

// TestIsSignedFileFollowsDDP035 checks card.IsSignedFile, by which the library authenticates and
// tachographtest signs, against the EFs the regulation leaves unsigned.
func TestIsSignedFileFollowsDDP035(t *testing.T) {
	values := cardv1.ElementaryFileType_ELEMENTARY_FILE_UNSPECIFIED.Descriptor().Values()
	for i := range values.Len() {
		file := cardv1.ElementaryFileType(values.Get(i).Number())
		if file == cardv1.ElementaryFileType_ELEMENTARY_FILE_UNSPECIFIED {
			continue
		}
		if got, want := card.IsSignedFile(file), !slices.Contains(unsignedCardFiles, file); got != want {
			t.Errorf("IsSignedFile(%v) = %v, want %v", file, got, want)
		}
	}
}

func TestAuthenticateDriverCardDownloads(t *testing.T) {
	pki := tachographtest.NewPKI(t)
	trusted := tachographtest.Resolver(t, pki.TrustStore())
	revokedStore := pki.TrustStore()
	revokedStore.RevokedMSCACertificates = [][]byte{pki.Gen1MSCACertificate, pki.Gen2MSCACertificate}
	linkedStore := pki.TrustStore()
	linkedStore.Gen2LinkCertificates = [][]byte{pki.Gen2LinkCertificate}
	expired := time.Date(2020, 3, 1, 0, 0, 0, 0, time.UTC)
	expiresInside := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	card1, card2 := pki.Gen1DriverCard(t), pki.Gen2DriverCard(t)
	next := tachographtest.Gen2Equipment(t, pki.Gen2NextMSCA, pki.Gen2NextMSCACertificate, tachographtest.P256, tachographtest.EquipmentDriverCardSign)
	nextWithLink := *next
	nextWithLink.LinkCertificate = pki.Gen2LinkCertificate
	msca521, msca521Certificate := tachographtest.NewGen2MSCA(t, pki.Gen2Root, tachographtest.P521)

	tamper := func(t *testing.T, data []byte) []byte {
		return rewriteCard(t, data, func(records []*cardv1.RawCardFile_Record) []*cardv1.RawCardFile_Record {
			for _, r := range records {
				if isIdentification(r) && r.GetContentType() == cardv1.ContentType_DATA {
					value := slices.Clone(r.GetValue())
					value[0] ^= 0xFF
					r.SetValue(value)
				}
			}
			return records
		})
	}
	dropSignature := func(t *testing.T, data []byte) []byte {
		return rewriteCard(t, data, func(records []*cardv1.RawCardFile_Record) []*cardv1.RawCardFile_Record {
			return slices.DeleteFunc(records, func(r *cardv1.RawCardFile_Record) bool {
				return isIdentification(r) && r.GetContentType() == cardv1.ContentType_SIGNATURE
			})
		})
	}
	zeroSignature := func(t *testing.T, data []byte) []byte {
		return rewriteCard(t, data, func(records []*cardv1.RawCardFile_Record) []*cardv1.RawCardFile_Record {
			for _, r := range records {
				if isIdentification(r) && r.GetContentType() == cardv1.ContentType_SIGNATURE {
					r.SetValue(make([]byte, len(r.GetValue())))
				}
			}
			return records
		})
	}
	const (
		verified  = securityv1.Authentication_VERIFIED
		failed    = securityv1.Authentication_CERTIFICATE_VERIFICATION_FAILED
		untrusted = securityv1.Authentication_CERTIFICATE_UNTRUSTED
	)
	tests := []struct {
		name string
		// only limits the case to downloads of one generation.
		only               ddv1.Generation
		gen1               *tachographtest.Gen1Chain
		gen2               *tachographtest.Gen2Chain
		resolver           tachograph.CertificateResolver
		edit               func(*testing.T, []byte) []byte
		want               securityv1.Authentication_Status
		wantIdentification securityv1.Authentication_Status
	}{
		{name: "verified", gen1: card1, gen2: card2, want: verified},
		{name: "workshop card certificate",
			gen1: tachographtest.Gen1Equipment(t, pki.Gen1MSCA, pki.Gen1MSCACertificate, tachographtest.EquipmentWorkshopCard),
			gen2: tachographtest.Gen2Equipment(t, pki.Gen2MSCA, pki.Gen2MSCACertificate, tachographtest.P256, tachographtest.EquipmentWorkshopCardSign),
			want: verified},
		{name: "tampered identification", gen1: card1, gen2: card2, edit: tamper, want: verified,
			wantIdentification: securityv1.Authentication_DATA_SIGNATURE_INVALID},
		{name: "identification without its signature", gen1: card1, gen2: card2, edit: dropSignature, want: verified,
			wantIdentification: securityv1.Authentication_SIGNATURE_MISSING},
		{name: "identification with a zeroed signature", gen1: card1, gen2: card2, edit: zeroSignature, want: verified,
			wantIdentification: securityv1.Authentication_SIGNATURE_MISSING},
		{name: "identification with a zeroed signature, root of another PKI", gen1: card1, gen2: card2,
			resolver: tachographtest.Resolver(t, tachographtest.NewPKI(t).TrustStore()), edit: zeroSignature, want: untrusted,
			wantIdentification: securityv1.Authentication_SIGNATURE_MISSING},
		{name: "root of another PKI", gen1: card1, gen2: card2,
			resolver: tachographtest.Resolver(t, tachographtest.NewPKI(t).TrustStore()), want: untrusted},
		{name: "embedded ERCA roots only", gen1: card1, gen2: card2, resolver: tachograph.DefaultCertificateResolver(), want: untrusted},
		{name: "revoked MSCA certificate", gen1: card1, gen2: card2, resolver: tachographtest.Resolver(t, revokedStore),
			want: securityv1.Authentication_CERTIFICATE_REVOKED},
		{name: "CAR naming another authority",
			gen1: pki.Gen1DriverCard(t, func(c *tachographtest.Gen1Certificate) { c.CAR = pki.Gen1Root.ID }),
			gen2: pki.Gen2DriverCard(t, func(c *tachographtest.Gen2Certificate) { c.CAR = pki.Gen2NextMSCA.CHR }),
			want: failed},
		{name: "inner CAR other than CAR'", only: ddv1.Generation_GENERATION_1,
			gen1: pki.Gen1DriverCard(t, func(c *tachographtest.Gen1Certificate) { c.CAR, c.TrailingCAR = pki.Gen1Root.ID, pki.Gen1MSCA.ID }),
			want: failed},
		{name: "vehicle unit certificate",
			gen1: pki.Gen1DriverCard(t, func(c *tachographtest.Gen1Certificate) {
				c.CHA = tachographtest.Gen1CHA(tachographtest.EquipmentVehicleUnit)
			}),
			gen2: pki.Gen2DriverCard(t, func(c *tachographtest.Gen2Certificate) {
				c.CHA = tachographtest.Gen2CHA(tachographtest.EquipmentVehicleUnitSign)
			}),
			want: failed},
		{name: "mutual authentication certificate", only: ddv1.Generation_GENERATION_2,
			gen2: pki.Gen2DriverCard(t, func(c *tachographtest.Gen2Certificate) {
				c.CHA = tachographtest.Gen2CHA(tachographtest.EquipmentDriverCard)
			}),
			want: failed},
		{name: "equipment certificate expiring inside the signing window",
			gen1: pki.Gen1DriverCard(t, func(c *tachographtest.Gen1Certificate) { c.EndOfValidity = expiresInside }),
			gen2: pki.Gen2DriverCard(t, func(c *tachographtest.Gen2Certificate) { c.ExpirationDate = expiresInside }),
			want: securityv1.Authentication_CERTIFICATE_VALIDITY_UNKNOWN},
		{name: "tampered identification, equipment certificate expiring inside the signing window",
			gen1: pki.Gen1DriverCard(t, func(c *tachographtest.Gen1Certificate) { c.EndOfValidity = expiresInside }),
			gen2: pki.Gen2DriverCard(t, func(c *tachographtest.Gen2Certificate) { c.ExpirationDate = expiresInside }),
			edit: tamper, want: securityv1.Authentication_CERTIFICATE_VALIDITY_UNKNOWN,
			wantIdentification: securityv1.Authentication_DATA_SIGNATURE_INVALID},
		{name: "equipment certificate expired before the signing window",
			gen1: pki.Gen1DriverCard(t, func(c *tachographtest.Gen1Certificate) { c.EndOfValidity = expired }),
			gen2: pki.Gen2DriverCard(t, func(c *tachographtest.Gen2Certificate) { c.ExpirationDate = expired }),
			want: failed},
		{name: "no certificate files",
			gen1: &tachographtest.Gen1Chain{EquipmentKey: card1.EquipmentKey},
			gen2: &tachographtest.Gen2Chain{EquipmentKey: card2.EquipmentKey},
			want: securityv1.Authentication_CERTIFICATE_MISSING},
		{name: "link certificate in EF_Link_Certificate", only: ddv1.Generation_GENERATION_2, gen2: &nextWithLink, want: verified},
		{name: "link certificate in the trust store", only: ddv1.Generation_GENERATION_2, gen2: next,
			resolver: tachographtest.Resolver(t, linkedStore), want: verified},
		{name: "link certificate unknown", only: ddv1.Generation_GENERATION_2, gen2: next, want: untrusted},
		{name: "P-521", only: ddv1.Generation_GENERATION_2,
			gen2: tachographtest.Gen2Equipment(t, msca521, msca521Certificate, tachographtest.P521, tachographtest.EquipmentDriverCardSign),
			want: verified},
	}
	for _, kind := range cardKinds {
		for _, tt := range tests {
			if tt.only != ddv1.Generation_GENERATION_UNSPECIFIED && tt.only != kind.generation {
				continue
			}
			t.Run(kind.name+"/"+tt.name, func(t *testing.T) {
				gen1, gen2 := tt.gen1, tt.gen2
				if kind.generation == ddv1.Generation_GENERATION_1 {
					gen2 = nil
				} else {
					gen1 = nil
				}
				data := tachographtest.SignDriverCardFile(t, kind.body(t), gen1, gen2)
				if tt.edit != nil {
					data = tt.edit(t, data)
				}
				resolver := tt.resolver
				if resolver == nil {
					resolver = trusted
				}
				var got, want []string
				for _, r := range authenticate(t, data, resolver, receivedAt).GetCard().GetRecords() {
					auth := r.GetAuthentication()
					status := tt.want
					switch {
					case slices.Contains(unsignedCardFiles, r.GetFile()):
						status = securityv1.Authentication_UNSIGNED
					case isIdentification(r) && tt.wantIdentification != securityv1.Authentication_STATUS_UNSPECIFIED:
						status = tt.wantIdentification
					}
					label := r.GetFile().String() + " " + r.GetContentType().String() + " "
					got = append(got, label+auth.GetStatus().String())
					want = append(want, label+status.String())
					if auth.GetStatus() != verified && auth.GetDetail() == "" {
						t.Errorf("%s: %v without a detail", label, auth.GetStatus())
					}
					if auth.GetStatus() == verified && (auth.HasSignatureCreationTime() ||
						!auth.GetSigningWindowStart().AsTime().Equal(kind.newest) || !auth.GetSigningWindowEnd().AsTime().Equal(receivedAt)) {
						t.Errorf("%s: signed at %v in the window %v to %v, want no signing time and the window %v to %v", label,
							auth.GetSignatureCreationTime(), auth.GetSigningWindowStart(), auth.GetSigningWindowEnd(), kind.newest, receivedAt)
					}
				}
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("statuses (-want +got):\n%s", diff)
				}
			})
		}
	}
}

func TestAuthenticateDriverCardWithBothDFs(t *testing.T) {
	pki := tachographtest.NewPKI(t)
	body := cardFixture(t, "004-anonymized", ddv1.Generation_GENERATION_UNSPECIFIED)
	data := tachographtest.SignDriverCardFile(t, body, pki.Gen1DriverCard(t), pki.Gen2DriverCard(t))
	for _, r := range authenticate(t, data, tachographtest.Resolver(t, pki.TrustStore()), receivedAt).GetCard().GetRecords() {
		want := securityv1.Authentication_VERIFIED
		if slices.Contains(unsignedCardFiles, r.GetFile()) {
			want = securityv1.Authentication_UNSIGNED
		}
		if got := r.GetAuthentication().GetStatus(); got != want {
			t.Errorf("%v %v %v: %v (%s), want %v", r.GetFile(), r.GetGeneration(), r.GetContentType(), got, r.GetAuthentication().GetDetail(), want)
		}
	}
}

// TestAuthenticateDriverCardWithoutTimestamps signs card downloads without their activity and
// event data: a Gen2 window then starts at the signing certificate's effective date, a Gen1 window
// has no start, and a certificate expiring before the receipt can't be placed.
func TestAuthenticateDriverCardWithoutTimestamps(t *testing.T) {
	pki := tachographtest.NewPKI(t)
	resolver := tachographtest.Resolver(t, pki.TrustStore())
	expiresInside := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		kind      cardKind
		gen1      *tachographtest.Gen1Chain
		gen2      *tachographtest.Gen2Chain
		want      securityv1.Authentication_Status
		wantStart time.Time
	}{
		{"Gen1", cardKinds[0], pki.Gen1DriverCard(t), nil, securityv1.Authentication_VERIFIED, time.Time{}},
		{"Gen1 certificate ending before the receipt", cardKinds[0],
			pki.Gen1DriverCard(t, func(c *tachographtest.Gen1Certificate) { c.EndOfValidity = expiresInside }), nil,
			securityv1.Authentication_CERTIFICATE_VALIDITY_UNKNOWN, time.Time{}},
		{"Gen2", cardKinds[1], nil, pki.Gen2DriverCard(t), securityv1.Authentication_VERIFIED, tachographtest.EquipmentValidity.From},
		{"Gen2 certificate expiring before the receipt", cardKinds[1], nil,
			pki.Gen2DriverCard(t, func(c *tachographtest.Gen2Certificate) { c.ExpirationDate = expiresInside }),
			securityv1.Authentication_CERTIFICATE_VALIDITY_UNKNOWN, tachographtest.EquipmentValidity.From},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := rewriteCard(t, tt.kind.body(t), func(records []*cardv1.RawCardFile_Record) []*cardv1.RawCardFile_Record {
				return slices.DeleteFunc(records, func(r *cardv1.RawCardFile_Record) bool {
					return r.GetFile() == cardv1.ElementaryFileType_EF_DRIVER_ACTIVITY_DATA || r.GetFile() == cardv1.ElementaryFileType_EF_EVENTS_DATA
				})
			})
			data := tachographtest.SignDriverCardFile(t, body, tt.gen1, tt.gen2)
			for _, r := range authenticate(t, data, resolver, receivedAt).GetCard().GetRecords() {
				if slices.Contains(unsignedCardFiles, r.GetFile()) {
					continue
				}
				auth := r.GetAuthentication()
				if auth.GetStatus() != tt.want {
					t.Errorf("%v: %v (%s), want %v", r.GetFile(), auth.GetStatus(), auth.GetDetail(), tt.want)
				}
				start, end := auth.GetSigningWindowStart(), auth.GetSigningWindowEnd()
				if auth.HasSigningWindowStart() != !tt.wantStart.IsZero() || (auth.HasSigningWindowStart() && !start.AsTime().Equal(tt.wantStart)) ||
					!end.AsTime().Equal(receivedAt) || auth.HasSignatureCreationTime() {
					t.Errorf("%v: window %v to %v, signed at %v; want %v to %v and no signing time", r.GetFile(),
						start, end, auth.GetSignatureCreationTime(), tt.wantStart, receivedAt)
				}
			}
		})
	}
}

// TestAuthenticateDriverCardReceivedAtItsNewestRecord receives each card download at its newest
// record's time: the window has no width, yet it stays a window and never becomes a signing time.
func TestAuthenticateDriverCardReceivedAtItsNewestRecord(t *testing.T) {
	pki := tachographtest.NewPKI(t)
	resolver := tachographtest.Resolver(t, pki.TrustStore())
	for _, kind := range cardKinds {
		t.Run(kind.name, func(t *testing.T) {
			gen1, gen2 := pki.Gen1DriverCard(t), pki.Gen2DriverCard(t)
			if kind.generation == ddv1.Generation_GENERATION_1 {
				gen2 = nil
			} else {
				gen1 = nil
			}
			data := tachographtest.SignDriverCardFile(t, kind.body(t), gen1, gen2)
			for _, r := range authenticate(t, data, resolver, kind.newest).GetCard().GetRecords() {
				if slices.Contains(unsignedCardFiles, r.GetFile()) {
					continue
				}
				auth := r.GetAuthentication()
				start, end := auth.GetSigningWindowStart(), auth.GetSigningWindowEnd()
				if auth.GetStatus() != securityv1.Authentication_VERIFIED || auth.HasSignatureCreationTime() ||
					!auth.HasSigningWindowStart() || !start.AsTime().Equal(kind.newest) || !end.AsTime().Equal(kind.newest) {
					t.Errorf("%v: %v (%s), window %v to %v, signed at %v; want VERIFIED, the window %v to %v and no signing time",
						r.GetFile(), auth.GetStatus(), auth.GetDetail(), start, end, auth.GetSignatureCreationTime(), kind.newest, kind.newest)
				}
			}
		})
	}
}

// TestAuthenticateDriverCardReceivedBeforeItsNewestRecord receives each card download a day before
// its newest record, as a card whose clock runs ahead could have it: that record can't start the
// signing window, which starts as if the card held no timestamps.
func TestAuthenticateDriverCardReceivedBeforeItsNewestRecord(t *testing.T) {
	pki := tachographtest.NewPKI(t)
	resolver := tachographtest.Resolver(t, pki.TrustStore())
	for _, kind := range cardKinds {
		t.Run(kind.name, func(t *testing.T) {
			gen1, gen2 := pki.Gen1DriverCard(t), pki.Gen2DriverCard(t)
			wantStart := tachographtest.EquipmentValidity.From
			if kind.generation == ddv1.Generation_GENERATION_1 {
				gen2, wantStart = nil, time.Time{}
			} else {
				gen1 = nil
			}
			at := kind.newest.Add(-24 * time.Hour)
			data := tachographtest.SignDriverCardFile(t, kind.body(t), gen1, gen2)
			for _, r := range authenticate(t, data, resolver, at).GetCard().GetRecords() {
				if slices.Contains(unsignedCardFiles, r.GetFile()) {
					continue
				}
				auth := r.GetAuthentication()
				start, end := auth.GetSigningWindowStart(), auth.GetSigningWindowEnd()
				if auth.GetStatus() != securityv1.Authentication_VERIFIED || auth.HasSigningWindowStart() != !wantStart.IsZero() ||
					(auth.HasSigningWindowStart() && !start.AsTime().Equal(wantStart)) || !end.AsTime().Equal(at) {
					t.Errorf("%v: %v (%s), window %v to %v; want VERIFIED and the window %v to %v",
						r.GetFile(), auth.GetStatus(), auth.GetDetail(), start, end, wantStart, at)
				}
			}
		})
	}
}

package tachograph_test

import (
	"encoding/binary"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/way-platform/tachograph-go"
	ddv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/dd/v1"
	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
	vuv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/vu/v1"
	"github.com/way-platform/tachograph-go/tachographtest"
)

func isTechnicalData(r *vuv1.RawVehicleUnitFile_Record) bool {
	return slices.Contains([]vuv1.TransferType{
		vuv1.TransferType_TECHNICAL_DATA_GEN1, vuv1.TransferType_TECHNICAL_DATA_GEN2_V1, vuv1.TransferType_TECHNICAL_DATA_GEN2_V2,
	}, r.GetType())
}

func isOverview(r *vuv1.RawVehicleUnitFile_Record) bool {
	return slices.Contains([]vuv1.TransferType{
		vuv1.TransferType_OVERVIEW_GEN1, vuv1.TransferType_OVERVIEW_GEN2_V1, vuv1.TransferType_OVERVIEW_GEN2_V2,
	}, r.GetType())
}

func TestAuthenticateVehicleUnitDownloads(t *testing.T) {
	pki := tachographtest.NewPKI(t)
	trusted := tachographtest.Resolver(t, pki.TrustStore())
	revokedStore := pki.TrustStore()
	revokedStore.RevokedMSCACertificates = [][]byte{pki.Gen1MSCACertificate, pki.Gen2MSCACertificate}
	linkedStore := pki.TrustStore()
	linkedStore.Gen2LinkCertificates = [][]byte{pki.Gen2LinkCertificate}
	expired := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	vu1, vu2 := pki.Gen1VehicleUnit(t), pki.Gen2VehicleUnit(t)
	next := tachographtest.Gen2Equipment(t, pki.Gen2NextMSCA, pki.Gen2NextMSCACertificate, tachographtest.P256, tachographtest.EquipmentVehicleUnitSign)
	msca521, msca521Certificate := tachographtest.NewGen2MSCA(t, pki.Gen2Root, tachographtest.P521)

	tamper := func(t *testing.T, data []byte) []byte {
		return rewriteVU(t, data, func(r *vuv1.RawVehicleUnitFile_Record) []byte {
			value := slices.Clone(r.GetValue())
			if isTechnicalData(r) {
				value[10] ^= 0xFF
			}
			return value
		})
	}
	dropSignature := func(of func(*vuv1.RawVehicleUnitFile_Record) bool) func(*testing.T, []byte) []byte {
		return func(t *testing.T, data []byte) []byte {
			return rewriteVU(t, data, func(r *vuv1.RawVehicleUnitFile_Record) []byte {
				value := r.GetValue()
				if !of(r) {
					return value
				}
				body := value[:len(value)-int(r.GetSignatureSize())]
				if r.GetGeneration() == ddv1.Generation_GENERATION_1 {
					return slices.Concat(body, make([]byte, 128))
				}
				return slices.Concat(body, []byte{0x08, 0x00, 0x00, 0x00, 0x00})
			})
		}
	}
	// zeroSignature zeroes a transfer's signature: Gen1's 128 bytes, Gen2's record behind its array header.
	zeroSignature := func(of func(*vuv1.RawVehicleUnitFile_Record) bool) func(*testing.T, []byte) []byte {
		return func(t *testing.T, data []byte) []byte {
			return rewriteVU(t, data, func(r *vuv1.RawVehicleUnitFile_Record) []byte {
				value := slices.Clone(r.GetValue())
				if of(r) {
					signature := value[len(value)-int(r.GetSignatureSize()):]
					if r.GetGeneration() == ddv1.Generation_GENERATION_2 {
						signature = signature[5:]
					}
					clear(signature)
				}
				return value
			})
		}
	}
	// retypeOverviewSignature gives a Gen2 overview's SignatureRecordArray record type 0x07.
	retypeOverviewSignature := func(t *testing.T, data []byte) []byte {
		return rewriteVU(t, data, func(r *vuv1.RawVehicleUnitFile_Record) []byte {
			value := slices.Clone(r.GetValue())
			if isOverview(r) {
				value[len(value)-int(r.GetSignatureSize())] = 0x07
			}
			return value
		})
	}
	// redate rewrites the overview's current date and time after it was signed.
	redate := func(at time.Time) func(*testing.T, []byte) []byte {
		return func(t *testing.T, data []byte) []byte {
			return rewriteVU(t, data, func(r *vuv1.RawVehicleUnitFile_Record) []byte {
				value := slices.Clone(r.GetValue())
				switch r.GetType() {
				case vuv1.TransferType_OVERVIEW_GEN1:
					binary.BigEndian.PutUint32(value[2*194+17+15:], uint32(at.Unix()))
				case vuv1.TransferType_OVERVIEW_GEN2_V1, vuv1.TransferType_OVERVIEW_GEN2_V2:
					// Certificates, VIN and registration arrays precede the current date and time's.
					offset := 0
					for range 4 {
						offset += 5 + int(binary.BigEndian.Uint16(value[offset+1:]))*int(binary.BigEndian.Uint16(value[offset+3:]))
					}
					binary.BigEndian.PutUint32(value[offset+5:], uint32(at.Unix()))
				}
				return value
			})
		}
	}
	dropOverview := func(t *testing.T, data []byte) []byte {
		return rewriteVU(t, data, func(r *vuv1.RawVehicleUnitFile_Record) []byte {
			switch r.GetType() {
			case vuv1.TransferType_OVERVIEW_GEN1, vuv1.TransferType_OVERVIEW_GEN2_V1, vuv1.TransferType_OVERVIEW_GEN2_V2:
				return nil
			}
			return r.GetValue()
		})
	}
	const (
		verified  = securityv1.Authentication_VERIFIED
		failed    = securityv1.Authentication_CERTIFICATE_VERIFICATION_FAILED
		untrusted = securityv1.Authentication_CERTIFICATE_UNTRUSTED
		missing   = securityv1.Authentication_CERTIFICATE_MISSING
		unknown   = securityv1.Authentication_CERTIFICATE_VALIDITY_UNKNOWN
		invalid   = securityv1.Authentication_DATA_SIGNATURE_INVALID
	)
	tests := []struct {
		name string
		// only limits the case to downloads of one generation.
		only              ddv1.Generation
		gen1              *tachographtest.Gen1Chain
		gen2              *tachographtest.Gen2Chain
		resolver          tachograph.CertificateResolver
		receivedAt        func(signedAt time.Time) time.Time
		edit              func(*testing.T, []byte) []byte
		want              securityv1.Authentication_Status
		wantOverview      securityv1.Authentication_Status
		wantTechnicalData securityv1.Authentication_Status
	}{
		{name: "verified", gen1: vu1, gen2: vu2, want: verified},
		{name: "tampered technical data", gen1: vu1, gen2: vu2, edit: tamper, want: verified,
			wantTechnicalData: invalid},
		{name: "technical data without its signature", gen1: vu1, gen2: vu2, edit: dropSignature(isTechnicalData), want: verified,
			wantTechnicalData: securityv1.Authentication_SIGNATURE_MISSING},
		{name: "technical data with a zeroed signature", gen1: vu1, gen2: vu2, edit: zeroSignature(isTechnicalData), want: verified,
			wantTechnicalData: securityv1.Authentication_SIGNATURE_MISSING},
		{name: "technical data with a zeroed signature, root of another PKI", gen1: vu1, gen2: vu2,
			resolver: tachographtest.Resolver(t, tachographtest.NewPKI(t).TrustStore()), edit: zeroSignature(isTechnicalData), want: untrusted,
			wantTechnicalData: securityv1.Authentication_SIGNATURE_MISSING},
		{name: "overview without its signature", gen1: vu1, gen2: vu2, edit: dropSignature(isOverview), want: unknown,
			wantOverview: securityv1.Authentication_SIGNATURE_MISSING},
		{name: "overview redated into an expired certificate's validity",
			gen1: pki.Gen1VehicleUnit(t, func(c *tachographtest.Gen1Certificate) { c.EndOfValidity = expired }),
			gen2: pki.Gen2VehicleUnit(t, func(c *tachographtest.Gen2Certificate) { c.ExpirationDate = expired }),
			edit: redate(time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC)), want: unknown, wantOverview: invalid},
		{name: "overview redated into an expired certificate's validity, tampered technical data",
			gen1: pki.Gen1VehicleUnit(t, func(c *tachographtest.Gen1Certificate) { c.EndOfValidity = expired }),
			gen2: pki.Gen2VehicleUnit(t, func(c *tachographtest.Gen2Certificate) { c.ExpirationDate = expired }),
			edit: func(t *testing.T, data []byte) []byte {
				return tamper(t, redate(time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC))(t, data))
			},
			want: unknown, wantOverview: invalid, wantTechnicalData: invalid},
		{name: "overview redated past the certificate's expiry and the receipt", gen1: vu1, gen2: vu2,
			edit: redate(time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)), want: unknown, wantOverview: invalid},
		{name: "root of another PKI", gen1: vu1, gen2: vu2,
			resolver: tachographtest.Resolver(t, tachographtest.NewPKI(t).TrustStore()), want: untrusted},
		{name: "embedded ERCA roots only", gen1: vu1, gen2: vu2, resolver: tachograph.DefaultCertificateResolver(), want: untrusted},
		{name: "revoked MSCA certificate", gen1: vu1, gen2: vu2, resolver: tachographtest.Resolver(t, revokedStore),
			want: securityv1.Authentication_CERTIFICATE_REVOKED},
		{name: "CAR naming another authority",
			gen1: pki.Gen1VehicleUnit(t, func(c *tachographtest.Gen1Certificate) { c.CAR = pki.Gen1Root.ID }),
			gen2: pki.Gen2VehicleUnit(t, func(c *tachographtest.Gen2Certificate) { c.CAR = pki.Gen2NextMSCA.CHR }),
			want: failed},
		{name: "inner CAR other than CAR'", only: ddv1.Generation_GENERATION_1,
			gen1: pki.Gen1VehicleUnit(t, func(c *tachographtest.Gen1Certificate) { c.CAR, c.TrailingCAR = pki.Gen1Root.ID, pki.Gen1MSCA.ID }),
			want: failed},
		{name: "driver card certificate",
			gen1: pki.Gen1VehicleUnit(t, func(c *tachographtest.Gen1Certificate) {
				c.CHA = tachographtest.Gen1CHA(tachographtest.EquipmentDriverCard)
			}),
			gen2: pki.Gen2VehicleUnit(t, func(c *tachographtest.Gen2Certificate) {
				c.CHA = tachographtest.Gen2CHA(tachographtest.EquipmentDriverCardSign)
			}),
			want: failed},
		{name: "mutual authentication certificate", only: ddv1.Generation_GENERATION_2,
			gen2: pki.Gen2VehicleUnit(t, func(c *tachographtest.Gen2Certificate) {
				c.CHA = tachographtest.Gen2CHA(tachographtest.EquipmentVehicleUnit)
			}),
			want: failed},
		{name: "equipment certificate expired before the signing time",
			gen1: pki.Gen1VehicleUnit(t, func(c *tachographtest.Gen1Certificate) { c.EndOfValidity = expired }),
			gen2: pki.Gen2VehicleUnit(t, func(c *tachographtest.Gen2Certificate) { c.ExpirationDate = expired }),
			want: failed},
		{name: "overview without certificates",
			gen1: &tachographtest.Gen1Chain{EquipmentKey: vu1.EquipmentKey},
			gen2: &tachographtest.Gen2Chain{EquipmentKey: vu2.EquipmentKey},
			want: missing},
		{name: "download without an overview", gen1: vu1, gen2: vu2, edit: dropOverview, want: missing},
		{name: "signed a day after receipt", gen1: vu1, gen2: vu2,
			receivedAt: func(signedAt time.Time) time.Time { return signedAt.Add(-24 * time.Hour) }, want: verified},
		{name: "signed more than a day after receipt", gen1: vu1, gen2: vu2,
			receivedAt: func(signedAt time.Time) time.Time { return signedAt.Add(-24*time.Hour - time.Second) }, want: failed},
		{name: "equipment certificate expiring between the signing time and the receipt",
			gen1: pki.Gen1VehicleUnit(t, func(c *tachographtest.Gen1Certificate) {
				c.EndOfValidity = time.Date(2025, 9, 13, 0, 0, 0, 0, time.UTC)
			}),
			gen2: pki.Gen2VehicleUnit(t, func(c *tachographtest.Gen2Certificate) {
				c.ExpirationDate = time.Date(2026, 3, 11, 23, 0, 0, 0, time.UTC)
			}),
			want: verified},
		{name: "overview signature record of another type", only: ddv1.Generation_GENERATION_2, gen2: vu2, edit: retypeOverviewSignature,
			want: unknown, wantOverview: invalid},
		{name: "root reached through a link certificate", only: ddv1.Generation_GENERATION_2, gen2: next,
			resolver: tachographtest.Resolver(t, linkedStore), want: verified},
		{name: "link certificate unknown", only: ddv1.Generation_GENERATION_2, gen2: next, want: untrusted},
		{name: "P-521", only: ddv1.Generation_GENERATION_2,
			gen2: tachographtest.Gen2Equipment(t, msca521, msca521Certificate, tachographtest.P521, tachographtest.EquipmentVehicleUnitSign),
			want: verified},
	}
	for _, kind := range vuKinds {
		for _, tt := range tests {
			if tt.only != ddv1.Generation_GENERATION_UNSPECIFIED && tt.only != kind.generation {
				continue
			}
			t.Run(kind.name+"/"+tt.name, func(t *testing.T) {
				data := tachographtest.SignVehicleUnitFile(t, kind.body(t), tt.gen1, tt.gen2)
				if tt.edit != nil {
					data = tt.edit(t, data)
				}
				resolver, at := tt.resolver, receivedAt
				if resolver == nil {
					resolver = trusted
				}
				if tt.receivedAt != nil {
					at = tt.receivedAt(kind.signedAt)
				}
				var got, want []string
				for _, r := range authenticate(t, data, resolver, at).GetVehicleUnit().GetRecords() {
					auth := r.GetAuthentication()
					status := tt.want
					switch {
					case r.GetType() == vuv1.TransferType_DOWNLOAD_INTERFACE_VERSION, r.GetType() == vuv1.TransferType_CARD_DOWNLOAD:
						status = securityv1.Authentication_UNSIGNED
					case isOverview(r) && tt.wantOverview != securityv1.Authentication_STATUS_UNSPECIFIED:
						status = tt.wantOverview
					case isTechnicalData(r) && tt.wantTechnicalData != securityv1.Authentication_STATUS_UNSPECIFIED:
						status = tt.wantTechnicalData
					}
					got = append(got, r.GetType().String()+" "+auth.GetStatus().String())
					want = append(want, r.GetType().String()+" "+status.String())
					if auth.GetStatus() != verified && auth.GetDetail() == "" {
						t.Errorf("%v: %v without a detail", r.GetType(), auth.GetStatus())
					}
					if auth.GetStatus() == unknown && (!strings.Contains(auth.GetDetail(), "overview") || auth.HasSignatureCreationTime()) {
						t.Errorf("%v: %v (%s) signed at %v; want the overview named as the reason and no signing time",
							r.GetType(), auth.GetStatus(), auth.GetDetail(), auth.GetSignatureCreationTime())
					}
				}
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("statuses (-want +got):\n%s", diff)
				}
			})
		}
	}
}

// TestAuthenticateVehicleUnitRejectsBytesAfterTheSignatureArray covers a RawFile built by hand whose signature size claims more than its SignatureRecordArray, which Unmarshal never produces.
func TestAuthenticateVehicleUnitRejectsBytesAfterTheSignatureArray(t *testing.T) {
	pki := tachographtest.NewPKI(t)
	for _, kind := range vuKinds {
		if kind.generation != ddv1.Generation_GENERATION_2 {
			continue
		}
		t.Run(kind.name, func(t *testing.T) {
			raw, err := tachograph.Unmarshal(tachographtest.SignVehicleUnitFile(t, kind.body(t), nil, pki.Gen2VehicleUnit(t)))
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			for _, r := range raw.GetVehicleUnit().GetRecords() {
				if isTechnicalData(r) {
					r.SetValue(append(slices.Clone(r.GetValue()), 0))
					r.SetSignatureSize(r.GetSignatureSize() + 1)
				}
			}
			authenticated, err := tachograph.AuthenticateOptions{
				CertificateResolver: tachographtest.Resolver(t, pki.TrustStore()), ReceivedAt: receivedAt,
			}.Authenticate(t.Context(), raw)
			if err != nil {
				t.Fatalf("authenticate: %v", err)
			}
			for _, r := range authenticated.GetVehicleUnit().GetRecords() {
				if got := r.GetAuthentication().GetStatus(); isTechnicalData(r) && got != securityv1.Authentication_DATA_SIGNATURE_INVALID {
					t.Errorf("%v: %v, want DATA_SIGNATURE_INVALID for a byte after its SignatureRecordArray", r.GetType(), got)
				}
			}
		})
	}
}

func TestAuthenticateVehicleUnitReportsTheChain(t *testing.T) {
	pki := tachographtest.NewPKI(t)
	linked := pki.TrustStore()
	linked.Gen2LinkCertificates = [][]byte{pki.Gen2LinkCertificate}
	msca521, msca521Certificate := tachographtest.NewGen2MSCA(t, pki.Gen2Root, tachographtest.P521)
	vu1, vu2 := pki.Gen1VehicleUnit(t), pki.Gen2VehicleUnit(t)
	next := tachographtest.Gen2Equipment(t, pki.Gen2NextMSCA, pki.Gen2NextMSCACertificate, tachographtest.P256, tachographtest.EquipmentVehicleUnitSign)
	vu521 := tachographtest.Gen2Equipment(t, msca521, msca521Certificate, tachographtest.P521, tachographtest.EquipmentVehicleUnitSign)
	var none time.Time
	root, msca, equipment := tachographtest.RootValidity, tachographtest.MSCAValidity, tachographtest.EquipmentValidity
	info := func(chr, car [8]byte, from, to time.Time) *securityv1.CertificateInfo {
		i := &securityv1.CertificateInfo{}
		i.SetCertificateHolderReference(decimal(chr))
		i.SetCertificationAuthorityReference(decimal(car))
		if !from.IsZero() {
			i.SetValidFrom(timestamppb.New(from))
		}
		if !to.IsZero() {
			i.SetValidTo(timestamppb.New(to))
		}
		return i
	}
	verified := func(algorithm securityv1.SignatureAlgorithm, signedAt time.Time, rootInfo, link, ca, signer *securityv1.CertificateInfo) *securityv1.Authentication {
		a := &securityv1.Authentication{}
		a.SetStatus(securityv1.Authentication_VERIFIED)
		a.SetSignatureAlgorithm(algorithm)
		a.SetSignatureCreationTime(timestamppb.New(signedAt))
		a.SetRootCertificate(rootInfo)
		if link != nil {
			a.SetLinkCertificate(link)
		}
		a.SetCaCertificate(ca)
		a.SetSignerCertificate(signer)
		return a
	}
	gen1Kind, gen2Kind := vuKinds[0], vuKinds[2]
	gen2Root := info(pki.Gen2Root.CHR, pki.Gen2Root.CHR, root.From, root.To)
	tests := []struct {
		name  string
		kind  vuKind
		gen1  *tachographtest.Gen1Chain
		gen2  *tachographtest.Gen2Chain
		store tachograph.TrustStore
		want  *securityv1.Authentication
	}{
		{"Gen1", gen1Kind, vu1, nil, pki.TrustStore(), verified(securityv1.SignatureAlgorithm_SHA1_WITH_RSA_ENCRYPTION, gen1Kind.signedAt,
			info(pki.Gen1Root.ID, pki.Gen1Root.ID, none, none), nil,
			info(pki.Gen1MSCA.ID, pki.Gen1Root.ID, none, msca.To),
			info(vu1.EquipmentKey.ID, pki.Gen1MSCA.ID, none, equipment.To))},
		{"Gen2", gen2Kind, nil, vu2, pki.TrustStore(), verified(securityv1.SignatureAlgorithm_ECDSA_WITH_SHA256, gen2Kind.signedAt,
			gen2Root, nil,
			info(pki.Gen2MSCA.CHR, pki.Gen2Root.CHR, msca.From, msca.To),
			info(vu2.EquipmentKey.CHR, pki.Gen2MSCA.CHR, equipment.From, equipment.To))},
		{"Gen2 through a link certificate", gen2Kind, nil, next, linked, verified(securityv1.SignatureAlgorithm_ECDSA_WITH_SHA256, gen2Kind.signedAt,
			gen2Root, info(pki.Gen2NextRoot.CHR, pki.Gen2Root.CHR, root.From, root.To),
			info(pki.Gen2NextMSCA.CHR, pki.Gen2NextRoot.CHR, msca.From, msca.To),
			info(next.EquipmentKey.CHR, pki.Gen2NextMSCA.CHR, equipment.From, equipment.To))},
		{"Gen2 on P-521", gen2Kind, nil, vu521, pki.TrustStore(), verified(securityv1.SignatureAlgorithm_ECDSA_WITH_SHA512, gen2Kind.signedAt,
			gen2Root, nil,
			info(msca521.CHR, pki.Gen2Root.CHR, msca.From, msca.To),
			info(vu521.EquipmentKey.CHR, msca521.CHR, equipment.From, equipment.To))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tachographtest.SignVehicleUnitFile(t, tt.kind.body(t), tt.gen1, tt.gen2)
			for _, r := range authenticate(t, data, tachographtest.Resolver(t, tt.store), receivedAt).GetVehicleUnit().GetRecords() {
				if r.GetType() == vuv1.TransferType_DOWNLOAD_INTERFACE_VERSION || r.GetType() == vuv1.TransferType_CARD_DOWNLOAD {
					continue
				}
				if diff := cmp.Diff(tt.want, r.GetAuthentication(), protocmp.Transform()); diff != "" {
					t.Errorf("%v authentication (-want +got):\n%s", r.GetType(), diff)
				}
			}
		})
	}
}

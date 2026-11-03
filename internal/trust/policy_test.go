package trust_test

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/way-platform/tachograph-go/internal/trust"
	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
	"github.com/way-platform/tachograph-go/tachographtest"
)

const (
	verified  = securityv1.Authentication_VERIFIED
	failed    = securityv1.Authentication_CERTIFICATE_VERIFICATION_FAILED
	untrusted = securityv1.Authentication_CERTIFICATE_UNTRUSTED
	missing   = securityv1.Authentication_CERTIFICATE_MISSING
	revoked   = securityv1.Authentication_CERTIFICATE_REVOKED
	unknown   = securityv1.Authentication_CERTIFICATE_VALIDITY_UNKNOWN
)

func date(year int, month time.Month, day int) time.Time {
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

// signedAt is a VU overview's signing time. cardWindow runs from a card's newest signed record to
// the receipt; noTimestamps is the window of a card holding none.
var (
	receipt      = date(2026, 3, 12)
	signedAt     = trust.At(date(2026, 3, 11))
	cardWindow   = trust.Window{From: date(2020, 7, 18), To: receipt}
	noTimestamps = trust.Window{To: receipt}
)

func decimal(reference [8]byte) string {
	return strconv.FormatUint(binary.BigEndian.Uint64(reference[:]), 10)
}

func newStore(t *testing.T, pki *tachographtest.PKI, links ...[]byte) *trust.Store {
	t.Helper()
	store, err := trust.NewStore([][]byte{pki.Gen1Root.RootKey()}, [][]byte{pki.Gen2RootCertificate}, links, nil)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

// distrusting answers every root lookup with the store's key or certificate, but reports it untrusted.
type distrusting struct{ *trust.Store }

func (d distrusting) Gen1RootKey(keyID string) (*securityv1.RootCertificate, bool) {
	key, _ := d.Store.Gen1RootKey(keyID)
	return key, false
}

func (d distrusting) Gen2RootCertificate(chr string) (*securityv1.EccCertificate, bool) {
	root, _ := d.Store.Gen2RootCertificate(chr)
	return root, false
}

func TestVerifyChainsTrustNoRootTheResolverReportsUntrusted(t *testing.T) {
	pki := tachographtest.NewPKI(t)
	resolver := distrusting{newStore(t, pki, pki.Gen2LinkCertificate)}
	vu1 := pki.Gen1VehicleUnit(t)
	if auth, signer := trust.VerifyGen1Chain(resolver, vu1.MSCACertificate, vu1.EquipmentCertificate, trust.VehicleUnit, signedAt); auth.GetStatus() != untrusted || signer != nil {
		t.Errorf("Gen1: %v (%s), signer returned %v; want %v and none", auth.GetStatus(), auth.GetDetail(), signer != nil, untrusted)
	}
	for name, chain := range map[string]*tachographtest.Gen2Chain{
		"Gen2 under the root":             pki.Gen2VehicleUnit(t),
		"Gen2 through a link certificate": tachographtest.Gen2Equipment(t, pki.Gen2NextMSCA, pki.Gen2NextMSCACertificate, tachographtest.P256, tachographtest.EquipmentVehicleUnitSign),
	} {
		if auth, signer := trust.VerifyGen2Chain(resolver, chain.MSCACertificate, chain.EquipmentCertificate, nil, trust.VehicleUnit, signedAt); auth.GetStatus() != untrusted || signer != nil {
			t.Errorf("%s: %v (%s), signer returned %v; want %v and none", name, auth.GetStatus(), auth.GetDetail(), signer != nil, untrusted)
		}
	}
}

func TestVerifyGen2ChainFollowsLinkCertificates(t *testing.T) {
	pki := tachographtest.NewPKI(t)
	next := tachographtest.Gen2Equipment(t, pki.Gen2NextMSCA, pki.Gen2NextMSCACertificate, tachographtest.P256, tachographtest.EquipmentVehicleUnitSign)
	forged := tachographtest.Gen2Certificate{
		CAR: pki.Gen2Root.CHR, CHA: tachographtest.Gen2CHA(tachographtest.EquipmentERCA),
		EffectiveDate: tachographtest.RootValidity.From, ExpirationDate: tachographtest.RootValidity.To, Holder: pki.Gen2NextRoot,
	}.Sign(t, pki.Gen2NextRoot)
	early := tachographtest.Gen2Certificate{
		CAR: pki.Gen2Root.CHR, CHA: tachographtest.Gen2CHA(tachographtest.EquipmentERCA),
		EffectiveDate: date(2005, 1, 1), ExpirationDate: tachographtest.RootValidity.To, Holder: pki.Gen2NextRoot,
	}.Sign(t, pki.Gen2Root)
	// An MSCA certificate the file carries as a link would certify an MSCA of its own.
	subMSCA, subMSCACertificate := tachographtest.NewGen2MSCA(t, pki.Gen2MSCA, tachographtest.P256)
	underMSCA := tachographtest.Gen2Equipment(t, subMSCA, subMSCACertificate, tachographtest.P256, tachographtest.EquipmentVehicleUnitSign)
	tests := []struct {
		name      string
		store     *trust.Store
		chain     *tachographtest.Gen2Chain
		fileLinks [][]byte
		want      securityv1.Authentication_Status
	}{
		{"link certificate in the trust store", newStore(t, pki, pki.Gen2LinkCertificate), next, nil, verified},
		{"link certificate in the file", newStore(t, pki), next, [][]byte{pki.Gen2LinkCertificate}, verified},
		{"no link certificate", newStore(t, pki), next, nil, untrusted},
		{"link certificate not signed by the previous root", newStore(t, pki), next, [][]byte{forged}, failed},
		{"link certificate effective before the previous root", newStore(t, pki), next, [][]byte{early}, failed},
		{"MSCA certificate as a link certificate", newStore(t, pki), underMSCA, [][]byte{pki.Gen2MSCACertificate}, failed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, signer := trust.VerifyGen2Chain(tt.store, tt.chain.MSCACertificate, tt.chain.EquipmentCertificate, tt.fileLinks, trust.VehicleUnit, signedAt)
			if got := auth.GetStatus(); got != tt.want {
				t.Fatalf("status = %v (%s), want %v", got, auth.GetDetail(), tt.want)
			}
			if (signer != nil) != (tt.want == verified) {
				t.Errorf("signer returned = %v, want %v", signer != nil, tt.want == verified)
			}
			if tt.want != verified {
				return
			}
			if got, want := auth.GetLinkCertificate().GetCertificateHolderReference(), decimal(pki.Gen2NextRoot.CHR); got != want {
				t.Errorf("link CHR = %s, want %s", got, want)
			}
			if got, want := auth.GetRootCertificate().GetCertificateHolderReference(), decimal(pki.Gen2Root.CHR); got != want {
				t.Errorf("root CHR = %s, want %s", got, want)
			}
		})
	}
}

func TestVerifyGen2ChainChecksEachCertificateWhenItWasUsed(t *testing.T) {
	pki := tachographtest.NewPKI(t)
	store := newStore(t, pki)
	early := tachographtest.Gen2Certificate{
		CAR: pki.Gen2Root.CHR, CHA: tachographtest.Gen2CHA(tachographtest.EquipmentMSCA),
		EffectiveDate: date(2005, 1, 1), ExpirationDate: date(2045, 1, 1), Holder: pki.Gen2MSCA,
	}.Sign(t, pki.Gen2Root)
	ercaRole := tachographtest.Gen2Certificate{
		CAR: pki.Gen2Root.CHR, CHA: tachographtest.Gen2CHA(tachographtest.EquipmentERCA),
		EffectiveDate: tachographtest.MSCAValidity.From, ExpirationDate: tachographtest.MSCAValidity.To, Holder: pki.Gen2MSCA,
	}.Sign(t, pki.Gen2Root)
	expires := func(day time.Time) func(*tachographtest.Gen2Certificate) {
		return func(c *tachographtest.Gen2Certificate) { c.ExpirationDate = day }
	}
	tests := []struct {
		name   string
		msca   []byte
		edit   func(*tachographtest.Gen2Certificate)
		window trust.Window
		want   securityv1.Authentication_Status
	}{
		{"verified at the signing time", pki.Gen2MSCACertificate, nil, signedAt, verified},
		{"MSCA certificate effective before the root", early, nil, signedAt, failed},
		{"MSCA certificate without the MSCA role", ercaRole, nil, signedAt, failed},
		{"equipment certificate effective after the MSCA certificate expired", pki.Gen2MSCACertificate,
			func(c *tachographtest.Gen2Certificate) {
				c.EffectiveDate, c.ExpirationDate = date(2046, 1, 1), date(2050, 1, 1)
			}, trust.At(date(2047, 1, 1)), failed},
		{"equipment certificate expired before the signing time", pki.Gen2MSCACertificate, expires(date(2024, 1, 1)), signedAt, failed},
		{"equipment certificate not yet effective at the signing time", pki.Gen2MSCACertificate,
			func(c *tachographtest.Gen2Certificate) { c.EffectiveDate = date(2027, 1, 1) }, signedAt, failed},
		{"card certificate expiring after the receipt", pki.Gen2MSCACertificate, nil, cardWindow, verified},
		{"card certificate expiring inside the window", pki.Gen2MSCACertificate, expires(date(2021, 1, 1)), cardWindow, unknown},
		{"card certificate expired before the newest record", pki.Gen2MSCACertificate, expires(date(2020, 1, 1)), cardWindow, failed},
		{"card certificate effective after the receipt", pki.Gen2MSCACertificate,
			func(c *tachographtest.Gen2Certificate) { c.EffectiveDate = date(2027, 1, 1) }, cardWindow, failed},
		{"card without timestamps, certificate expiring after the receipt", pki.Gen2MSCACertificate, nil, noTimestamps, verified},
		{"card without timestamps, certificate expiring before the receipt", pki.Gen2MSCACertificate, expires(date(2021, 1, 1)), noTimestamps, unknown},
		{"nothing dates the signature", pki.Gen2MSCACertificate, nil, trust.Window{}, unknown},
		{"VU signing certificate on a card", pki.Gen2MSCACertificate,
			func(c *tachographtest.Gen2Certificate) {
				c.CHA = tachographtest.Gen2CHA(tachographtest.EquipmentVehicleUnitSign)
			}, signedAt, failed},
		{"card mutual authentication certificate", pki.Gen2MSCACertificate,
			func(c *tachographtest.Gen2Certificate) {
				c.CHA = tachographtest.Gen2CHA(tachographtest.EquipmentDriverCard)
			}, signedAt, failed},
		{"workshop card signing certificate", pki.Gen2MSCACertificate,
			func(c *tachographtest.Gen2Certificate) {
				c.CHA = tachographtest.Gen2CHA(tachographtest.EquipmentWorkshopCardSign)
			}, signedAt, verified},
		{"workshop card mutual authentication certificate", pki.Gen2MSCACertificate,
			func(c *tachographtest.Gen2Certificate) {
				c.CHA = tachographtest.Gen2CHA(tachographtest.EquipmentWorkshopCard)
			}, signedAt, failed},
		{"card signing type behind the Gen1 application ID", pki.Gen2MSCACertificate,
			func(c *tachographtest.Gen2Certificate) {
				c.CHA = tachographtest.Gen1CHA(tachographtest.EquipmentDriverCardSign)
			}, signedAt, failed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var edits []func(*tachographtest.Gen2Certificate)
			if tt.edit != nil {
				edits = append(edits, tt.edit)
			}
			chain := tachographtest.Gen2Equipment(t, pki.Gen2MSCA, tt.msca, tachographtest.P256, tachographtest.EquipmentDriverCardSign, edits...)
			auth, signer := trust.VerifyGen2Chain(store, chain.MSCACertificate, chain.EquipmentCertificate, nil, trust.Card, tt.window)
			if got := auth.GetStatus(); got != tt.want {
				t.Fatalf("status = %v (%s), want %v", got, auth.GetDetail(), tt.want)
			}
			if want := tt.want == verified || tt.want == unknown; (signer != nil) != want {
				t.Errorf("signer returned = %v, want %v", signer != nil, want)
			}
		})
	}
	if auth, _ := trust.VerifyGen2Chain(store, nil, nil, nil, trust.VehicleUnit, signedAt); auth.GetStatus() != missing {
		t.Errorf("no certificates: %v, want %v", auth.GetStatus(), missing)
	}
}

func TestVerifyGen2ChainReportsTheSigningTimeOrWindow(t *testing.T) {
	pki := tachographtest.NewPKI(t)
	store := newStore(t, pki)
	card := pki.Gen2DriverCard(t)
	tests := []struct {
		name       string
		window     trust.Window
		wantSigned time.Time
		wantStart  time.Time
		wantEnd    time.Time
	}{
		{"VU signing time", signedAt, signedAt.From, time.Time{}, time.Time{}},
		{"card window", cardWindow, time.Time{}, cardWindow.From, receipt},
		{"card without timestamps starts at the certificate's effective date", noTimestamps, time.Time{}, tachographtest.EquipmentValidity.From, receipt},
		{"card whose newest record predates the certificate starts at its effective date",
			trust.Window{From: date(2018, 6, 1), To: receipt}, time.Time{}, tachographtest.EquipmentValidity.From, receipt},
		{"card whose newest record is the receipt time is still a window", trust.Window{From: receipt, To: receipt}, time.Time{}, receipt, receipt},
		{"nothing dates the signature", trust.Window{}, time.Time{}, time.Time{}, time.Time{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, _ := trust.VerifyGen2Chain(store, card.MSCACertificate, card.EquipmentCertificate, nil, trust.Card, tt.window)
			want := verified
			if tt.window.To.IsZero() {
				want = unknown
			}
			if auth.GetStatus() != want {
				t.Fatalf("status = %v (%s), want %v", auth.GetStatus(), auth.GetDetail(), want)
			}
			for name, got := range map[string]struct {
				set  bool
				at   time.Time
				want time.Time
			}{
				"signature_creation_time": {auth.HasSignatureCreationTime(), auth.GetSignatureCreationTime().AsTime(), tt.wantSigned},
				"signing_window_start":    {auth.HasSigningWindowStart(), auth.GetSigningWindowStart().AsTime(), tt.wantStart},
				"signing_window_end":      {auth.HasSigningWindowEnd(), auth.GetSigningWindowEnd().AsTime(), tt.wantEnd},
			} {
				if got.set != !got.want.IsZero() || (got.set && !got.at.Equal(got.want)) {
					t.Errorf("%s = %v (set %v), want %v", name, got.at, got.set, got.want)
				}
			}
		})
	}
}

func TestVerifyGen1ChainChecksRolesAndEndOfValidity(t *testing.T) {
	pki := tachographtest.NewPKI(t)
	store := newStore(t, pki)
	vuMSCA := tachographtest.Gen1Certificate{
		CAR: pki.Gen1Root.ID, CHA: tachographtest.Gen1CHA(tachographtest.EquipmentVehicleUnit),
		EndOfValidity: tachographtest.MSCAValidity.To, Holder: pki.Gen1MSCA,
	}.Sign(t, pki.Gen1Root)
	gen1Window := trust.Window{From: date(2020, 7, 7), To: receipt}
	ends := func(day time.Time) func(*tachographtest.Gen1Certificate) {
		return func(c *tachographtest.Gen1Certificate) { c.EndOfValidity = day }
	}
	tests := []struct {
		name   string
		msca   []byte
		edit   func(*tachographtest.Gen1Certificate)
		window trust.Window
		want   securityv1.Authentication_Status
	}{
		{"verified", pki.Gen1MSCACertificate, nil, signedAt, verified},
		{"no end of validity", pki.Gen1MSCACertificate, ends(time.Time{}), signedAt, verified},
		{"ended before the signing time", pki.Gen1MSCACertificate, ends(date(2024, 1, 1)), signedAt, failed},
		{"end of validity 00000000, 1970-01-01", pki.Gen1MSCACertificate, ends(time.Unix(0, 0)), signedAt, failed},
		{"card certificate ending after the receipt", pki.Gen1MSCACertificate, nil, gen1Window, verified},
		{"card certificate ending inside the window", pki.Gen1MSCACertificate, ends(date(2021, 1, 1)), gen1Window, unknown},
		{"card certificate ended before the newest record", pki.Gen1MSCACertificate, ends(date(2020, 1, 1)), gen1Window, failed},
		{"card without timestamps, certificate ending after the receipt", pki.Gen1MSCACertificate, nil, noTimestamps, verified},
		{"card without timestamps, certificate ending before the receipt", pki.Gen1MSCACertificate, ends(date(2020, 1, 1)), noTimestamps, unknown},
		{"nothing dates the signature", pki.Gen1MSCACertificate, nil, trust.Window{}, unknown},
		{"no end of validity, nothing dates the signature", pki.Gen1MSCACertificate, ends(time.Time{}), trust.Window{}, verified},
		{"MSCA certificate without the Member State role", vuMSCA, nil, signedAt, failed},
		{"workshop card certificate", pki.Gen1MSCACertificate,
			func(c *tachographtest.Gen1Certificate) {
				c.CHA = tachographtest.Gen1CHA(tachographtest.EquipmentWorkshopCard)
			}, signedAt, verified},
		{"VU certificate on a card", pki.Gen1MSCACertificate,
			func(c *tachographtest.Gen1Certificate) {
				c.CHA = tachographtest.Gen1CHA(tachographtest.EquipmentVehicleUnit)
			}, signedAt, failed},
		{"card type behind the Gen2 application ID", pki.Gen1MSCACertificate,
			func(c *tachographtest.Gen1Certificate) {
				c.CHA = tachographtest.Gen2CHA(tachographtest.EquipmentDriverCard)
			}, signedAt, failed},
		{"CAR inside other than CAR'", pki.Gen1MSCACertificate,
			func(c *tachographtest.Gen1Certificate) { c.CAR, c.TrailingCAR = pki.Gen1Root.ID, pki.Gen1MSCA.ID }, signedAt, failed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var edits []func(*tachographtest.Gen1Certificate)
			if tt.edit != nil {
				edits = append(edits, tt.edit)
			}
			chain := tachographtest.Gen1Equipment(t, pki.Gen1MSCA, tt.msca, tachographtest.EquipmentDriverCard, edits...)
			auth, signer := trust.VerifyGen1Chain(store, chain.MSCACertificate, chain.EquipmentCertificate, trust.Card, tt.window)
			if got := auth.GetStatus(); got != tt.want {
				t.Fatalf("status = %v (%s), want %v", got, auth.GetDetail(), tt.want)
			}
			if want := tt.want == verified || tt.want == unknown; (signer != nil) != want {
				t.Errorf("signer returned = %v, want %v", signer != nil, want)
			}
		})
	}
	if auth, _ := trust.VerifyGen1Chain(store, make([]byte, 194), make([]byte, 194), trust.Card, signedAt); auth.GetStatus() != missing {
		t.Errorf("zeroed certificates: %v, want %v", auth.GetStatus(), missing)
	}
}

// TestVerifyChainsRevokeTheMSCACertificatesCHR revokes by the CHR the verified certificate
// carries, so re-encodings that still verify stay revoked: a byte appended after the DER
// certificate, and the ECDSA signature's S replaced by N - S under the issuer's curve.
func TestVerifyChainsRevokeTheMSCACertificatesCHR(t *testing.T) {
	pki := tachographtest.NewPKI(t)
	vu1, vu2 := pki.Gen1VehicleUnit(t), pki.Gen2VehicleUnit(t)
	original := pki.Gen2MSCACertificate
	n := pki.Gen2Root.PrivateKey.Curve.Params().N // the root signed the MSCA certificate
	s := new(big.Int).SetBytes(original[len(original)-32:])
	reencodings := map[string][]byte{
		"original":          original,
		"one byte appended": slices.Concat(original, []byte{0x00}),
		"S replaced by N-S": slices.Concat(original[:len(original)-32], new(big.Int).Sub(n, s).FillBytes(make([]byte, 32))),
	}
	trusted := newStore(t, pki)
	revokedStore, err := trust.NewStore([][]byte{pki.Gen1Root.RootKey()}, [][]byte{pki.Gen2RootCertificate}, nil,
		[][]byte{pki.Gen1MSCACertificate, pki.Gen2MSCACertificate})
	if err != nil {
		t.Fatal(err)
	}
	for name, msca := range reencodings {
		if name != "original" && sha256.Sum256(msca) == sha256.Sum256(original) {
			t.Fatalf("%s: same SHA-256 as the original", name)
		}
		if auth, _ := trust.VerifyGen2Chain(trusted, msca, vu2.EquipmentCertificate, nil, trust.VehicleUnit, signedAt); auth.GetStatus() != verified {
			t.Errorf("%s: %v (%s) with nothing revoked, want %v", name, auth.GetStatus(), auth.GetDetail(), verified)
		}
		if auth, signer := trust.VerifyGen2Chain(revokedStore, msca, vu2.EquipmentCertificate, nil, trust.VehicleUnit, signedAt); auth.GetStatus() != revoked || signer != nil {
			t.Errorf("%s: %v (%s), want %v", name, auth.GetStatus(), auth.GetDetail(), revoked)
		}
	}
	if auth, signer := trust.VerifyGen1Chain(revokedStore, vu1.MSCACertificate, vu1.EquipmentCertificate, trust.VehicleUnit, signedAt); auth.GetStatus() != revoked || signer != nil {
		t.Errorf("Gen1: %v (%s), want %v", auth.GetStatus(), auth.GetDetail(), revoked)
	}
}
